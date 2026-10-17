//! Views over masked columns.
//!
//! A view whose definition reads masked columns (SQL or proxy) is inlined:
//! `FROM v` becomes `FROM (<definition>) AS v(columns)`, and the definition is
//! then masked like any subquery. Postgres expands views the same way, so this
//! doesn't change plans. Views that would change meaning if inlined (`security_barrier`,
//! `security_invoker`, materialized views, views with their own masked columns,
//! or all views with `inline_views = false`) are queried like tables instead;
//! their columns are masked by lineage (see `Assignments`).
use pg_raw_parse::{Node, make::Unique, nodes};

use super::{BodyInfo, Masker, Verdict, find_cte, ident, names};
use crate::catalog::{Relation, RelationKind};

impl<'c, 'mem> Masker<'c, 'mem> {
    /// What reading a view means for this user. Tables and table-like views are `Safe`:
    /// their masked columns are handled like any table's.
    pub(super) fn view_verdict(&mut self, relation: &Relation) -> Verdict {
        if !matches!(
            relation.kind,
            RelationKind::View | RelationKind::MaterializedView
        ) || self.view_allowlisted(relation)
            || self
                .ctx
                .assignments
                .is_table_like(&relation.schema, &relation.name)
        {
            return Verdict::Safe;
        }

        let key = (relation.schema.clone(), relation.name.clone());
        if let Some(info) = self.memo.borrow().views.get(&key).cloned() {
            self.touched |= info.touched;
            return info.verdict;
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
                    Verdict::Blocked(reason) => Verdict::Blocked(format!("view {label}: {reason}")),
                    // Inlined, so what its columns carry is known.
                    Verdict::Safe if info.reads_proxies => Verdict::Inline,
                    verdict => verdict,
                };
                info
            }
        };

        self.memo.borrow_mut().views.insert(key, info.clone());
        self.touched |= info.touched;
        info.verdict
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
