//! Statement-level rules: DDL, shadowing, maintenance, COPY and EXECUTE.
use pg_raw_parse::{Node, nodes, transform};

use super::{Masker, RESOLUTION_CHANGED, ident, names, range_vars, rules};
use crate::analyzer::taint::Outputs;
use crate::config::OnUnresolved;

/// Why EXECUTE of a statement prepared elsewhere is blocked.
const EXECUTE_UNKNOWN: &str = "EXECUTE of a statement prepared outside this query can't be checked for masked users; send the PREPARE in the same query";

impl<'c, 'mem> Masker<'c, 'mem> {
    /// TRUNCATE, VACUUM, ANALYZE and LOCK of relations with proxy-masked
    /// columns run their triggers and index expressions on real values.
    pub(super) fn check_maintenance(&mut self, node: Node<'_>) {
        let range_vars: Vec<&nodes::RangeVar> = match node {
            Node::TruncateStmt(truncate) => range_vars(truncate.relations()),
            Node::LockStmt(lock) => range_vars(lock.relations()),
            Node::VacuumStmt(vacuum) => {
                let relations: Vec<_> = vacuum
                    .rels()
                    .iter()
                    .filter_map(|relation| relation.relation())
                    .collect();
                // Without a list, every table: those with proxy masks too.
                if relations.is_empty() && self.ctx.profile.proxies {
                    self.state.writes_proxies = true;
                }
                relations
            }
            _ => return,
        };
        for range_var in range_vars {
            if self.resolves_to_proxy_relation(range_var) {
                self.state.touches_proxies = true;
                self.state.writes_proxies = true;
            }
        }
    }

    /// Does a relation name resolve to a relation with proxy-masked columns?
    pub(super) fn resolves_to_proxy_relation(&self, range_var: &nodes::RangeVar) -> bool {
        range_var.relname().is_some_and(|name| {
            self.ctx
                .catalog
                .resolve(range_var.schemaname(), name, &self.ctx.search_path)
                .is_some_and(|relation| self.has_proxy_masks(relation))
        })
    }

    /// DDL masked users may run can't touch relations with masked columns:
    /// expressions in ALTER TABLE or CREATE INDEX can leak values through errors,
    /// renames would unmask them, and attaching or inheriting would expose their
    /// rows through another table.
    pub(super) fn check_ddl(&mut self, node: Node<'_>) {
        if !matches!(
            node,
            Node::AlterTableStmt(_) | Node::IndexStmt(_) | Node::RenameStmt(_)
        ) {
            return;
        }

        // The target relation, and relations attached or inherited by ALTER TABLE.
        // (Postgres' expression walker doesn't handle DDL, so this reads the
        // statements directly.)
        let mut range_vars: Vec<&nodes::RangeVar> = vec![];
        match node {
            Node::AlterTableStmt(alter) => {
                range_vars.extend(alter.relation());
                for cmd in alter.cmds().iter() {
                    if let Node::AlterTableCmd(cmd) = cmd {
                        match cmd.def() {
                            Node::PartitionCmd(partition) => range_vars.extend(partition.name()),
                            Node::RangeVar(parent) => range_vars.push(parent),
                            _ => (),
                        }
                    }
                }
            }
            Node::IndexStmt(index) => range_vars.extend(index.relation()),
            Node::RenameStmt(rename) => range_vars.extend(rename.relation()),
            _ => (),
        }
        let relations: Vec<_> = range_vars
            .into_iter()
            .filter_map(|range_var| {
                range_var
                    .relname()
                    .map(|name| (range_var.schemaname().map(str::to_owned), name.to_owned()))
            })
            .collect();

        // Renames of schemas and other objects without a relation could move
        // masked tables out from under the configuration.
        if relations.is_empty() {
            self.block("this statement is not allowed for masked users");
            return;
        }
        if self.path_changed {
            self.block(RESOLUTION_CHANGED);
            return;
        }

        for (schema, name) in relations {
            if let Some(relation) =
                self.ctx
                    .catalog
                    .resolve(schema.as_deref(), &name, &self.ctx.search_path)
                && self.is_masked_relation(relation)
            {
                self.block(format!(
                    "masked users can't alter {}.{}, which has masked columns",
                    relation.schema, relation.name
                ));
                return;
            }
        }
    }

    /// Masked users can't create tables that shadow masked relations.
    pub(super) fn check_shadowing(&mut self, node: Node<'_>) {
        let node = match node {
            Node::ExplainStmt(explain) => explain.query(),
            node => node,
        };
        let created = match node {
            Node::CreateStmt(create) => create.relation().and_then(|r| r.relname()),
            Node::CreateTableAsStmt(ctas) => ctas
                .into()
                .and_then(|into| into.rel())
                .and_then(|r| r.relname()),
            Node::SelectStmt(select) => rules::into_clause(select)
                .and_then(|into| into.rel())
                .and_then(|r| r.relname()),
            _ => None,
        };
        if created.is_some() && self.path_changed {
            self.block(RESOLUTION_CHANGED);
            return;
        }
        if let Some(name) = created
            && self
                .ctx
                .assignments
                .relation_names()
                .any(|masked| masked == name)
        {
            self.block(format!(
                "creating \"{name}\" would shadow a relation with masked columns"
            ));
        }
    }

    /// SQL EXECUTE: only of statements prepared earlier in this query.
    pub(super) fn execute_stmt(&mut self, node: nodes::ExecuteStmtMut<'mem, '_>) {
        // Postgres analyzes a prepared statement again when search_path changes.
        if self.path_changed {
            self.block(RESOLUTION_CHANGED);
            return;
        }
        // Only statements prepared earlier in this query were checked, and
        // PgDog attaches no masks to the rows of the others.
        if !self.ctx.profile.exempt && !node.name().is_some_and(|name| self.prepared.contains(name))
        {
            self.block(EXECUTE_UNKNOWN);
            return;
        }
        self.state.runs_earlier = true;
        // The statement was analyzed with clean parameters. EXPLAIN EXECUTE
        // evaluates them too, and plans the statement with their values.
        let executing = std::mem::replace(&mut self.executing, true);
        let params = self.scoped(|masker| transform::transform_execute_stmt(node, masker));
        self.sink(params, "EXECUTE");
        self.executing = executing;
        self.outputs = Some(Outputs::default());
    }

    /// COPY: `COPY t TO` reads the table's columns as a query would.
    pub(super) fn copy_stmt(&mut self, mut node: nodes::CopyStmtMut<'mem, '_>) {
        if node.is_from {
            // Triggers and constraints of the table see real values.
            if node
                .relation()
                .is_some_and(|range_var| self.resolves_to_proxy_relation(range_var))
            {
                self.state.touches_proxies = true;
                self.state.writes_proxies = true;
            }
            return;
        }
        if node.is_program || node.filename().is_some() {
            self.block("COPY to a file or program is not allowed for masked users");
            return;
        }

        if let Some(range_var) = node.relation()
            && let Some(name) = range_var.relname()
        {
            if self.path_changed {
                self.block(RESOLUTION_CHANGED);
                return;
            }
            let schema = range_var.schemaname();
            let Some(relation) = self
                .ctx
                .catalog
                .resolve(schema, name, &self.ctx.search_path)
            else {
                if self.ctx.policies.config.general.on_unresolved == OnUnresolved::Block {
                    self.block(format!(
                        "relation \"{name}\" is not in the catalog, so its columns can't be checked"
                    ));
                }
                return;
            };
            if !self.is_masked_relation(relation) {
                return;
            }
            if self.has_proxy_masks(relation) {
                self.state.touches_proxies = true;
            }

            // COPY t TO ... => COPY (SELECT <columns> FROM t) TO ..., which is then masked.
            let attlist = names(node.attlist());
            let columns = if attlist.is_empty() {
                relation
                    .columns
                    .iter()
                    .map(|c| ident(&c.name))
                    .collect::<Vec<_>>()
            } else {
                attlist.iter().map(|c| ident(c)).collect()
            };
            let sql = format!(
                "COPY (SELECT {} FROM {}.{}) TO STDOUT",
                columns.join(", "),
                ident(&relation.schema),
                ident(&relation.name)
            );
            let parsed = match self.mem.parse(&sql) {
                Ok(parsed) => parsed,
                Err(err) => {
                    self.block(format!("failed to rewrite COPY: {err}"));
                    return;
                }
            };
            let Some(Node::CopyStmt(copy)) = parsed.as_ref().iter().next().map(|stmt| stmt.stmt())
            else {
                return;
            };
            let mut copy = self.mem.make_unique(copy);
            if !node.options().is_empty() {
                copy.as_mut()
                    .set_options(self.mem.make_unique(node.options()));
            }
            self.outputs = None;
            transform::transform_node(copy.as_mut().query_mut(), self);
            self.sink_outputs("COPY");
            node.replace(copy);
            self.changed = true;
            return;
        }

        self.outputs = None;
        transform::transform_node(node.query_mut(), self);
        self.sink_outputs("COPY");
    }
}
