//! Views over masked columns.
//!
//! A view whose definition reads masked columns (SQL or proxy) is inlined:
//! `FROM v` becomes `FROM (<definition>) AS v(columns)`, and the definition is
//! then masked like any subquery. Postgres expands views the same way, so this
//! doesn't change plans. Views that would change meaning if inlined (`security_barrier`,
//! `security_invoker`, materialized views, views with their own masked columns,
//! or all views with `inline_views = false`) are queried like tables instead;
//! their columns are masked by lineage (see `Assignments`).
//!
//! The definition of a table-like view runs on real values, whatever the
//! user's masks: it's analyzed with every masked column carrying its value,
//! like a proxy-masked one, and nothing rewritten. Its columns are masked,
//! but nothing else is: if it would move values anywhere else, e.g. to
//! `pg_notify()`, or can't be analyzed, the view can't be read. A function
//! that can't be analyzed is the exception: it can be called there, but not
//! with values of masked columns.
use pg_raw_parse::{Node, make::Unique, nodes};

use super::{BodyInfo, Masker, Verdict, find_cte, ident, names};
use crate::catalog::{Relation, RelationKind};

impl<'c, 'mem> Masker<'c, 'mem> {
    /// What reading a view means for this user. Tables are `Safe`, and so
    /// are table-like views their definition allows: their masked columns
    /// are handled like any table's.
    pub(super) fn view_verdict(&mut self, relation: &Relation) -> Verdict {
        if !matches!(
            relation.kind,
            RelationKind::View | RelationKind::MaterializedView
        ) || self.view_allowlisted(relation)
        {
            return Verdict::Safe;
        }
        let table_like = self
            .ctx
            .assignments
            .is_table_like(&relation.schema, &relation.name);
        // A materialized view holds a copy: its definition only runs on
        // REFRESH.
        if table_like && relation.kind == RelationKind::MaterializedView {
            return Verdict::Safe;
        }

        let info = if table_like && !self.real_values {
            self.real_values_masker().view_info(relation, true)
        } else {
            self.view_info(relation, table_like)
        };
        self.touched |= info.touched;
        // Inlined or not, the definition runs on real values: a view calling
        // a function that writes, or computing on values of masked columns
        // that aren't rewritten, may quote them in messages.
        self.state.writes |= info.redacts;
        info.verdict
    }

    /// A view's definition, analyzed for this user. Memoized.
    fn view_info(&mut self, relation: &Relation, table_like: bool) -> BodyInfo {
        let key = (relation.schema.clone(), relation.name.clone());
        if let Some(info) = self.memo.borrow().views.get(&key).cloned() {
            return info;
        }

        let label = relation.qualified_name();
        let active = format!("view {label}");
        let info = match relation.definition.as_deref() {
            None => BodyInfo::blocked(format!(
                "view {label} has no definition in the catalog, so it can't be checked for masked columns"
            )),
            Some(_) if self.memo.borrow().active.contains(&active) => {
                BodyInfo::blocked(format!("view {label} is recursive"))
            }
            Some(definition) => {
                self.memo.borrow_mut().active.push(active);
                // Definitions are schema-qualified, so no search_path is needed.
                let mut info = self.analyze_body(definition, vec![], |_| Ok(()));
                self.memo.borrow_mut().active.pop();
                info.verdict = match info.verdict {
                    Verdict::Blocked(reason) if table_like => Verdict::Blocked(format!(
                        "view {label} is queried like a table, so its definition runs on real values: {reason}"
                    )),
                    Verdict::Blocked(reason) => Verdict::Blocked(format!("view {label}: {reason}")),
                    // Inlined, so what its columns carry is known.
                    Verdict::Safe if info.reads_proxies && !table_like => Verdict::Inline,
                    verdict => verdict,
                };
                info
            }
        };

        self.memo.borrow_mut().views.insert(key, info.clone());
        info
    }

    fn view_allowlisted(&self, relation: &Relation) -> bool {
        let qualified = relation.qualified_name();
        self.ctx
            .policies
            .config
            .general
            .view_allowlist
            .iter()
            .any(|v| *v == qualified || *v == relation.name)
    }

    /// `FROM v` for a view over masked columns: `(<definition>) AS v(columns)`.
    pub(super) fn inline_view(
        &mut self,
        range_var: &nodes::RangeVar,
    ) -> Option<Unique<'mem, Node<'mem>>> {
        // After a change of name resolution, `add_range_var` blocks it.
        if !self.from || self.path_changed {
            return None;
        }
        let name = range_var.relname()?;
        let schema = range_var.schemaname();
        if schema.is_none() && find_cte(&self.frames, name).is_some() {
            return None;
        }
        let relation = self.resolve_relation(schema, name)?;
        if relation.kind != RelationKind::View || self.view_verdict(relation) != Verdict::Inline {
            return None;
        }

        let definition = relation.definition.as_deref()?.trim().trim_end_matches(';');
        let alias = range_var.alias();
        let refname = alias.and_then(|a| a.aliasname()).unwrap_or(name);
        let aliases = alias.map(|a| names(a.colnames())).unwrap_or_default();
        let columns: Vec<String> = relation
            .columns
            .iter()
            .enumerate()
            .map(|(i, column)| ident(aliases.get(i).unwrap_or(&column.name)))
            .collect();
        let sql = format!(
            "SELECT * FROM ({definition}) AS {}({})",
            ident(refname),
            columns.join(", ")
        );

        let inlined = self.parse_from_item(&sql);
        if inlined.is_none() {
            self.block(format!(
                "failed to inline view {}",
                relation.qualified_name()
            ));
        }
        inlined
    }

    /// The first FROM item of a query, copied into this statement's memory.
    pub(super) fn parse_from_item(&self, sql: &str) -> Option<Unique<'mem, Node<'mem>>> {
        let parsed = self.mem.parse(sql).ok()?;
        let stmt = parsed.as_ref().iter().next()?;
        let Node::SelectStmt(select) = stmt.stmt() else {
            return None;
        };
        let item = select.from_clause().iter().next()?;
        Some(self.mem.make_unique(item))
    }

    /// Masked users can't write through views that read masked columns.
    pub(super) fn check_view_write(&mut self, range_var: &nodes::RangeVar) {
        let Some(name) = range_var.relname() else {
            return;
        };
        let Some(relation) = self.resolve_relation(range_var.schemaname(), name) else {
            return;
        };
        if !matches!(
            relation.kind,
            RelationKind::View | RelationKind::MaterializedView
        ) {
            return;
        }
        let masked = if self
            .ctx
            .assignments
            .is_table_like(&relation.schema, &relation.name)
        {
            self.is_masked_relation(relation)
        } else {
            self.view_verdict(relation) == Verdict::Inline
        };
        if masked {
            self.block(format!(
                "view {} reads masked columns, so masked users can't write through it",
                relation.qualified_name()
            ));
        }
    }
}
