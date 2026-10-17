//! Statement-level rules: DDL, shadowing, maintenance, COPY and EXECUTE.
use pg_raw_parse::{
    Node, nodes,
    raw::{AlterTableType, DropBehavior, ObjectType},
    transform,
};

use super::{Masker, RESOLUTION_CHANGED, ident, names, range_vars, rules};
use crate::analyzer::taint::Outputs;
use crate::config::OnUnresolved;

/// Why DDL that changes which relation or column a name means is blocked.
const STALE_CATALOG: &str = "names would resolve differently in Postgres than in the plugin's catalog until PgDog reloads it";

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
    /// and attaching or inheriting would expose their rows through another
    /// table. Nor can it change which relation or column a name means: the
    /// catalog the plugin resolves names with is only reloaded after the
    /// statement, and not before the transaction ends. A column reference
    /// that no longer resolves in an inner query level resolves in an outer
    /// one, where it may read masked values.
    pub(super) fn check_ddl(&mut self, node: Node<'_>) {
        let range_vars: Vec<&nodes::RangeVar> = match node {
            Node::RenameStmt(_) => {
                self.block(format!(
                    "masked users can't rename relations, columns or schemas: {STALE_CATALOG}"
                ));
                return;
            }
            Node::DropStmt(drop) => {
                self.check_drop(drop);
                return;
            }
            // The target relation, and relations attached or inherited by ALTER TABLE.
            // (Postgres' expression walker doesn't handle DDL, so this reads the
            // statements directly.)
            Node::AlterTableStmt(alter) => {
                let mut range_vars: Vec<_> = alter.relation().into_iter().collect();
                for cmd in alter.cmds().iter() {
                    let Node::AlterTableCmd(cmd) = cmd else {
                        continue;
                    };
                    if cmd.subtype == AlterTableType::AT_DropColumn {
                        self.block(format!("masked users can't drop columns: {STALE_CATALOG}"));
                        return;
                    }
                    match cmd.def() {
                        Node::PartitionCmd(partition) => range_vars.extend(partition.name()),
                        Node::RangeVar(parent) => range_vars.push(parent),
                        _ => (),
                    }
                }
                range_vars
            }
            Node::IndexStmt(index) => index.relation().into_iter().collect(),
            _ => return,
        };
        if self.path_changed {
            self.block(RESOLUTION_CHANGED);
            return;
        }

        for range_var in range_vars {
            if let Some(name) = range_var.relname()
                && let Some(relation) =
                    self.ctx
                        .catalog
                        .resolve(range_var.schemaname(), name, &self.ctx.search_path)
                && self.is_masked_relation(relation)
            {
                self.block(format!(
                    "masked users can't alter {}, which has masked columns",
                    relation.qualified_name()
                ));
                return;
            }
        }
    }

    /// DROP can't change which relation a name means: dropping a relation
    /// whose name others share, or dropping with CASCADE, which can drop
    /// columns and relations that depend on the object.
    fn check_drop(&mut self, drop: &nodes::DropStmt) {
        if drop.behavior == DropBehavior::DROP_CASCADE {
            self.block(format!(
                "masked users can't DROP ... CASCADE, which can drop columns and relations: {STALE_CATALOG}"
            ));
            return;
        }
        match drop.remove_type {
            ObjectType::OBJECT_EXTENSION => {
                self.block(format!(
                    "masked users can't drop extensions, whose relations go with them: {STALE_CATALOG}"
                ));
                return;
            }
            ObjectType::OBJECT_TABLE
            | ObjectType::OBJECT_VIEW
            | ObjectType::OBJECT_MATVIEW
            | ObjectType::OBJECT_FOREIGN_TABLE
            | ObjectType::OBJECT_SEQUENCE => (),
            _ => return,
        }
        for object in drop.objects().iter() {
            let Node::NodeList(names) = object else {
                continue;
            };
            if let Some(name) = names.iter().next_back().and_then(|name| name.as_str())
                && self.ctx.catalog.relations_named(name).len() > 1
            {
                self.block(format!(
                    "masked users can't drop \"{name}\", whose name other relations share: {STALE_CATALOG}"
                ));
                return;
            }
        }
    }

    /// Relations masked users create can't be temporary, nor take the name
    /// of a relation in the catalog. Postgres resolves names to temporary
    /// relations first, and the plugin can't see them; a relation in an
    /// earlier schema of the search_path hides one of the same name until
    /// PgDog reloads its catalog. Either way, a column reference that would
    /// resolve to the hidden relation resolves in an outer query level
    /// instead, where it may read masked values.
    pub(super) fn check_created(&mut self, node: Node<'_>) {
        let node = match node {
            Node::ExplainStmt(explain) => explain.query(),
            node => node,
        };
        let created = match node {
            Node::CreateStmt(create) => create.relation(),
            Node::CreateTableAsStmt(ctas) => ctas.into().and_then(|into| into.rel()),
            Node::SelectStmt(select) => rules::into_clause(select).and_then(|into| into.rel()),
            Node::CreateSeqStmt(seq) => seq.sequence(),
            _ => None,
        };
        let Some(range_var) = created else {
            return;
        };
        if self.path_changed {
            self.block(RESOLUTION_CHANGED);
            return;
        }
        if rules::temporary(range_var) {
            self.block(
                "masked users can't create temporary relations: names resolve to them first, and the plugin can't see them",
            );
            return;
        }
        let Some(name) = range_var.relname() else {
            return;
        };
        let shadowed = self.ctx.catalog.relations_named(name).first();
        if shadowed.is_some()
            || self
                .ctx
                .assignments
                .relation_names()
                .any(|masked| masked == name)
        {
            let what = shadowed.map_or("a relation with masked columns".to_owned(), |relation| {
                relation.qualified_name()
            });
            self.block(format!(
                "creating \"{name}\" would shadow {what}: {STALE_CATALOG}; choose another name"
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
