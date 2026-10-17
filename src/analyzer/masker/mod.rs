//! Rewrites a statement so every reference to a masked column reads the mask instead.
mod functions;
mod views;

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::rc::Rc;

use pg_raw_parse::{
    Node, NodeMut,
    make::{MemoryToken, Unique},
    nodes,
    raw::{A_Expr_Kind, SetOperation},
    transform::{self, Assignable, Transform},
};

use super::Context;
use super::rules;
use super::scope::{Cte, Frame, Item, ItemKind, find_cte, find_item, resolve_column};
use crate::catalog::Relation;
use crate::config::OnUnresolved;
use crate::mask::{Mask, SearchOp, VALUE, castable};
use functions::CallUse;

/// Quote an identifier.
pub(super) fn ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Mask to apply to one column reference.
struct MaskTarget<'c> {
    /// Index of the policy in the config.
    policy: usize,
    template: &'c str,
    raw_search: &'c HashSet<SearchOp>,
    cast: &'c str,
    qualifier: String,
    arguments: &'c [String],
    label: String,
    /// Index of the proxy mask, if the policy has one for this user.
    proxy: Option<usize>,
    /// Type OID of the column; 0 if unknown.
    type_oid: u32,
}

/// Functions that only normalize a value, allowed around a column in raw searches.
const NORMALIZERS: &[&str] = &["lower", "upper", "btrim", "ltrim", "rtrim"];

/// Views and functions nested deeper than this are blocked.
const MAX_DEPTH: usize = 16;

/// Transform a clause stored in a field of a known type, whose root can't be
/// replaced in place: a call or operator at the root that must be inlined is
/// set through the field's setter instead.
macro_rules! clause {
    ($masker:expr, $node:expr, $get:ident, $get_mut:ident, $set:ident) => {{
        // The root isn't visited by `transform_node`, only its children.
        $masker.guard_bare($node.$get());
        match $masker.root_replacement($node.$get()) {
            Some(mut replacement) => {
                $masker.mask_replacement(&mut replacement);
                $node.$set(replacement);
            }
            None => transform::transform_node($node.$get_mut(), $masker),
        }
    }};
}

/// What a view or function does for this user.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// Reads no masked columns; use it as is.
    Safe,
    /// Reads masked columns; inline its definition with masks applied.
    Inline,
    Blocked(String),
}

/// Verdicts shared by the masker of a statement and the maskers it starts for
/// view and function bodies.
#[derive(Debug, Default)]
struct Memo {
    /// Verdict and whether it reads relations with masked columns.
    views: HashMap<(String, String), (Verdict, bool)>,
    functions: HashMap<i64, (Verdict, bool)>,
    /// Views and functions being analyzed, to stop recursion.
    active: Vec<String>,
}

pub(super) struct Masker<'c, 'mem> {
    mem: MemoryToken<'mem>,
    ctx: &'c Context<'c>,
    frames: Vec<Frame<'c>>,
    /// Inside a WHERE or JOIN condition, where raw searches are possible.
    predicate: bool,
    /// Column references used in an allowed raw search shape.
    raw_refs: HashSet<usize>,
    /// Function calls already checked, e.g. in a FROM list.
    checked_calls: HashSet<usize>,
    /// Inside a FROM list, where views can be inlined.
    from: bool,
    /// Nesting of view and function bodies.
    depth: usize,
    memo: Rc<RefCell<Memo>>,
    pub(super) blocked: Option<String>,
    pub(super) changed: bool,
    pub(super) masked: BTreeSet<String>,
    pub(super) raw: BTreeSet<String>,
    /// Reads or writes a relation with masked columns.
    pub(super) touched: bool,
    /// The next SELECT is the statement's top level, whose plain output
    /// columns can be masked by proxy masks.
    proxies_allowed: bool,
    /// Column references left raw for a proxy mask.
    proxy_refs: HashSet<usize>,
    /// Output columns masked by proxy masks.
    pub(super) proxies: Vec<super::ProxyColumn>,
}

fn names(list: &pg_raw_parse::list::NodeList) -> Vec<String> {
    list.iter()
        .filter_map(|node| node.as_str().map(str::to_owned))
        .collect()
}

/// Column reference fields, and whether it ends with `*`.
fn fields(column: &nodes::ColumnRef) -> (Vec<&str>, bool) {
    let mut star = false;
    let mut fields = vec![];
    for field in column.fields().iter() {
        match field {
            Node::A_Star(_) => star = true,
            node => fields.extend(node.as_str()),
        }
    }
    (fields, star)
}

fn address(column: &nodes::ColumnRef) -> usize {
    std::ptr::from_ref(column) as usize
}

fn call_address(call: &nodes::FuncCall) -> usize {
    std::ptr::from_ref(call) as usize
}

/// Output column name Postgres gives an expression, if it's a (cast) column reference.
fn column_ref_name(node: Node<'_>) -> Option<String> {
    match node {
        Node::ColumnRef(column) => {
            let (fields, star) = fields(column);
            if star {
                None
            } else {
                fields.last().map(|f| (*f).to_owned())
            }
        }
        Node::TypeCast(cast) => column_ref_name(cast.arg()),
        _ => None,
    }
}

/// Output column names of a subquery, if they can be determined without expanding `*`.
fn output_names(node: Node<'_>) -> Option<Vec<String>> {
    let Node::SelectStmt(select) = node else {
        return None;
    };
    if select.op != SetOperation::SETOP_NONE {
        return select
            .larg()
            .and_then(|larg| output_names(Node::SelectStmt(larg)));
    }
    if !select.values_lists().is_empty() {
        return None;
    }
    select
        .target_list()
        .iter()
        .map(|target| match target.name() {
            Some(name) => Some(name.to_owned()),
            None => match target.val() {
                Node::ColumnRef(column) if fields(column).1 => None,
                val => Some(figure_name(val)),
            },
        })
        .collect()
}

/// Approximation of Postgres' FigureColname, good enough for name lookups.
fn figure_name(node: Node<'_>) -> String {
    match node {
        Node::ColumnRef(_) | Node::TypeCast(_) => {
            column_ref_name(node).unwrap_or_else(|| "?column?".into())
        }
        Node::FuncCall(call) => call
            .funcname()
            .iter()
            .next_back()
            .and_then(|n| n.as_str())
            .unwrap_or("?column?")
            .to_owned(),
        Node::CaseExpr(_) => "case".into(),
        Node::CoalesceExpr(_) => "coalesce".into(),
        _ => "?column?".into(),
    }
}

impl<'c, 'mem> Masker<'c, 'mem> {
    pub(super) fn new(mem: MemoryToken<'mem>, ctx: &'c Context<'c>) -> Self {
        Self {
            mem,
            ctx,
            frames: vec![],
            predicate: false,
            raw_refs: HashSet::new(),
            checked_calls: HashSet::new(),
            from: false,
            depth: 0,
            memo: Rc::default(),
            blocked: None,
            changed: false,
            masked: BTreeSet::new(),
            raw: BTreeSet::new(),
            touched: false,
            proxies_allowed: false,
            proxy_refs: HashSet::new(),
            proxies: vec![],
        }
    }

    /// A masker for the body of a view or function, sharing this one's verdicts.
    fn nested<'n>(&self, ctx: &'n Context<'n>) -> Masker<'n, 'mem> {
        let mut nested = Masker::new(self.mem, ctx);
        nested.depth = self.depth + 1;
        nested.memo = self.memo.clone();
        nested
    }

    /// Analyze the statements of a view or function body for this user.
    /// Returns the verdict and whether the body reads relations with masked columns.
    fn analyze_body(
        &self,
        body: &str,
        search_path: Vec<String>,
        inlinable: impl FnOnce(&nodes::RawStmt) -> Result<(), String>,
    ) -> (Verdict, bool) {
        if self.depth >= MAX_DEPTH {
            return (
                Verdict::Blocked("views or functions are nested too deeply".into()),
                false,
            );
        }
        let mut stmts = match self.mem.parse(body) {
            Ok(stmts) => stmts,
            Err(err) => return (Verdict::Blocked(format!("failed to parse: {err}")), false),
        };
        let ctx = Context {
            catalog: self.ctx.catalog,
            assignments: self.ctx.assignments,
            policies: self.ctx.policies,
            profile: self.ctx.profile,
            search_path,
        };
        let mut nested = self.nested(&ctx);
        let shape = match stmts.as_ref().iter().collect::<Vec<_>>().as_slice() {
            [stmt] => inlinable(stmt),
            _ => Err("it has more than one statement".into()),
        };
        for stmt in stmts.as_mut() {
            nested.statement(stmt);
        }

        let verdict = match nested.blocked {
            Some(reason) => Verdict::Blocked(reason),
            None if !nested.changed => Verdict::Safe,
            None => match shape {
                Ok(()) => Verdict::Inline,
                Err(why) => {
                    Verdict::Blocked(format!("reads masked columns and can't be inlined: {why}"))
                }
            },
        };
        (verdict, nested.touched)
    }

    fn block(&mut self, reason: impl Into<String>) {
        self.blocked.get_or_insert_with(|| reason.into());
    }

    /// Mask a top-level statement.
    pub(super) fn statement(&mut self, stmt: nodes::RawStmtMut<'mem, '_>) {
        let node = stmt.stmt();
        if let Err(reason) = rules::check_statement(node) {
            self.block(reason);
            return;
        }
        self.check_shadowing(node);
        self.check_ddl(node);
        transform::transform_raw_stmt(stmt, self);
    }

    /// DDL masked users may run can't touch relations with masked columns:
    /// expressions in ALTER TABLE or CREATE INDEX can leak values through errors,
    /// renames would unmask them, and attaching or inheriting would expose their
    /// rows through another table.
    fn check_ddl(&mut self, node: Node<'_>) {
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
    fn check_shadowing(&mut self, node: Node<'_>) {
        let created = match node {
            Node::CreateStmt(create) => create.relation().and_then(|r| r.relname()),
            Node::CreateTableAsStmt(ctas) => ctas
                .into()
                .and_then(|into| into.rel())
                .and_then(|r| r.relname()),
            Node::SelectStmt(select) => select
                .into_clause()
                .and_then(|into| into.rel())
                .and_then(|r| r.relname()),
            _ => None,
        };
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

    /// The mask for a relation column, if it's masked for this user.
    fn mask_target(
        &self,
        relation: &'c Relation,
        column: &str,
        refname: &str,
    ) -> Option<MaskTarget<'c>> {
        let ctx: &'c Context<'c> = self.ctx;
        let assignment = ctx
            .assignments
            .column(&relation.schema, &relation.name, column)?;
        let Mask::Masked {
            template,
            raw_search,
            proxy,
        } = &ctx.profile.masks[assignment.policy]
        else {
            return None;
        };
        let policy = &ctx.policies.policies[assignment.policy].policy;
        let catalog_column = relation.column(column);
        let data_type = catalog_column
            .map(|c| c.data_type.as_str())
            .filter(|t| castable(t))
            .unwrap_or(&policy.data_type);

        Some(MaskTarget {
            policy: assignment.policy,
            template,
            raw_search,
            cast: data_type,
            qualifier: refname.to_owned(),
            arguments: &assignment.arguments,
            label: format!("{}.{}.{}", relation.schema, relation.name, column),
            proxy: *proxy,
            type_oid: catalog_column.map(|c| c.type_oid).unwrap_or(0),
        })
    }

    fn is_masked_relation(&self, relation: &Relation) -> bool {
        self.ctx
            .assignments
            .relation_policies(&relation.schema, &relation.name)
            .any(|policy| self.ctx.profile.masks[policy].is_masked())
    }

    /// The mask for a column reference, if it points to a masked column.
    fn column_target(&self, fields: &[&str]) -> Option<MaskTarget<'c>> {
        let resolved = resolve_column(&self.frames, fields)?;
        self.mask_target(resolved.relation, resolved.column, resolved.refname)
    }

    /// Parse a SQL expression into this statement's memory.
    fn parse_expr(&mut self, expr: &str) -> Option<Unique<'mem, Node<'mem>>> {
        let parsed = match self.mem.parse(&format!("SELECT {expr}")) {
            Ok(parsed) => parsed,
            Err(err) => {
                self.block(format!("failed to build mask expression: {err}"));
                return None;
            }
        };
        let stmt = parsed.as_ref().iter().next()?;
        let Node::SelectStmt(select) = stmt.stmt() else {
            return None;
        };
        let target = select.target_list().iter().next()?;
        Some(self.mem.make_unique(target.val()))
    }

    /// Build the masked expression replacing `original`.
    fn masked_expr(
        &mut self,
        original: &nodes::ColumnRef,
        target: &MaskTarget<'c>,
    ) -> Option<Unique<'mem, Node<'mem>>> {
        let template = match self
            .ctx
            .policies
            .template(&format!("({})::{}", target.template, target.cast))
        {
            Ok(template) => template,
            Err(err) => {
                self.block(format!("failed to build mask expression: {err}"));
                return None;
            }
        };
        let val = template.iter().next().and_then(|stmt| match stmt.stmt() {
            Node::SelectStmt(select) => select.target_list().iter().next().map(|t| t.val()),
            _ => None,
        })?;
        let mut expr = self.mem.make_unique(val);
        let mem = self.mem;
        let policy_arguments: &[String] =
            &self.ctx.policies.policies[target.policy].policy.arguments;

        transform::transform(&mut expr, |node| {
            let replacement = match &*node {
                NodeMut::ColumnRef(column) => {
                    let (names, _) = fields(column);
                    match names.as_slice() {
                        [name] if *name == VALUE => Some(mem.make_unique(original).uncast()),
                        [name] => policy_arguments
                            .iter()
                            .position(|arg| arg == name)
                            .and_then(|i| target.arguments.get(i))
                            .map(|column| {
                                let mut fields = vec![];
                                if !target.qualifier.is_empty() {
                                    fields.push(mem.make_string(Some(&target.qualifier)).uncast());
                                }
                                fields.push(mem.make_string(Some(column)).uncast());
                                mem.make_column_ref(mem.make_list(&fields)).uncast()
                            }),
                        _ => None,
                    }
                }
                _ => None,
            };
            match replacement {
                Some(replacement) => {
                    node.replace(replacement);
                    None
                }
                None => Some(node),
            }
        });

        Some(expr)
    }

    /// Masked columns used directly as a clause, e.g. `WHERE flag`, can't be
    /// replaced in place. Columns computed from masked columns can't be
    /// masked at all.
    fn guard_bare(&mut self, node: Node<'_>) {
        if let Node::ColumnRef(column) = node {
            let (names, star) = fields(column);
            if star {
                return;
            }
            if let Some(target) = self.column_target(&names) {
                self.block(format!(
                    "masked column {} can't be used directly as a condition",
                    target.label
                ));
            } else {
                self.guard_derived(&names);
            }
        }
    }

    /// Block a column computed from columns masked for this user, e.g. a
    /// column of a materialized view. Returns whether it blocked.
    fn guard_derived(&mut self, names: &[&str]) -> bool {
        if let Some(resolved) = resolve_column(&self.frames, names)
            && let Some(policies) = self.ctx.assignments.derived(
                &resolved.relation.schema,
                &resolved.relation.name,
                resolved.column,
            )
            && policies
                .iter()
                .any(|policy| self.ctx.profile.masks[*policy].is_masked())
        {
            self.block(format!(
                "column {}.{} is computed from masked columns and can't be masked; assign it a policy",
                resolved.relation.qualified_name(),
                resolved.column
            ));
            return true;
        }
        false
    }

    /// Record raw-search references in a comparison.
    fn mark_raw(&mut self, op: Option<SearchOp>, sides: &[(Node<'_>, Node<'_>)]) {
        let Some(op) = op else {
            return;
        };
        for (column_side, other_side) in sides {
            let Some(column) = raw_column(*column_side) else {
                continue;
            };
            if !operand_ok(*other_side) {
                continue;
            }
            let (names, star) = fields(column);
            if star {
                continue;
            }
            if let Some(target) = self.column_target(&names)
                && target.raw_search.contains(&op)
            {
                self.raw_refs.insert(address(column));
            }
        }
    }

    /// Record a raw-search reference with no other operand, e.g. `IS NULL`.
    fn mark_raw_column(&mut self, op: SearchOp, node: Node<'_>) {
        if let Some(column) = raw_column(node) {
            let (names, star) = fields(column);
            if !star
                && let Some(target) = self.column_target(&names)
                && target.raw_search.contains(&op)
            {
                self.raw_refs.insert(address(column));
            }
        }
    }

    fn mark_raw_a_expr(&mut self, expr: &nodes::A_Expr) {
        let op = search_op(expr);
        let (l, r) = (expr.lexpr(), expr.rexpr());
        self.mark_raw(op, &[(l, r), (r, l)]);
    }

    /// A FROM item naming a relation.
    fn add_range_var(&mut self, range_var: &nodes::RangeVar) {
        let Some(name) = range_var.relname() else {
            return;
        };
        let schema = range_var.schemaname();
        let alias = range_var.alias();
        let refname = alias.and_then(|a| a.aliasname()).unwrap_or(name).to_owned();
        let aliases = alias.map(|a| names(a.colnames())).unwrap_or_default();

        let item = if let Some(cte) = schema
            .is_none()
            .then(|| find_cte(&self.frames, name))
            .flatten()
        {
            let columns = if aliases.is_empty() {
                cte.columns.clone()
            } else {
                Some(aliases)
            };
            Item {
                refname,
                kind: ItemKind::Derived(columns),
            }
        } else if let Some(relation) = self
            .ctx
            .catalog
            .resolve(schema, name, &self.ctx.search_path)
        {
            match self.view_verdict(relation) {
                Verdict::Safe => (),
                // Views are inlined in FROM lists; anywhere else they can't be.
                Verdict::Inline => self.block(format!(
                    "view {} reads masked columns and can only be read in a FROM list",
                    relation.qualified_name()
                )),
                Verdict::Blocked(reason) => self.block(reason),
            }
            if self.is_masked_relation(relation) {
                self.touched = true;
            }
            Item::relation(refname, relation, &aliases)
        } else if let Some(result) = rules::check_catalog_relation(schema, name) {
            if let Err(reason) = result {
                self.block(reason);
            }
            Item {
                refname,
                kind: ItemKind::Derived(None),
            }
        } else {
            if self.ctx.policies.config.general.on_unresolved == OnUnresolved::Block {
                self.block(format!(
                    "relation \"{name}\" is not in the catalog, so its columns can't be checked"
                ));
            }
            Item {
                refname,
                kind: ItemKind::Derived(None),
            }
        };

        if let Some(frame) = self.frames.last_mut() {
            frame.items.push(item);
        }
    }

    /// `qualifier.column`, or `qualifier.*`, as a target list entry.
    fn star_target(
        &self,
        qualifier: &str,
        column: Option<&str>,
    ) -> Unique<'mem, &'mem nodes::ResTarget> {
        let mem = self.mem;
        let last = match column {
            Some(column) => mem.make_string(Some(column)).uncast(),
            None => mem.make_node::<nodes::A_Star>().uncast(),
        };
        let fields = [mem.make_string(Some(qualifier)).uncast(), last];
        let column = mem.make_column_ref(mem.make_list(&fields));
        mem.make_res_target(None, mem.empty(), column.uncast())
    }

    /// An item's columns, replacing `*` for it.
    fn expand_item(
        &mut self,
        item_index: usize,
    ) -> Option<Vec<Unique<'mem, &'mem nodes::ResTarget>>> {
        let frame = self.frames.last()?;
        let item = &frame.items[item_index];
        let masked = self.item_is_masked(item);
        match &item.kind {
            ItemKind::Relation { names, .. } if masked => Some(
                names
                    .iter()
                    .map(|name| self.star_target(&item.refname, Some(name)))
                    .collect(),
            ),
            _ if !item.refname.is_empty() => Some(vec![self.star_target(&item.refname, None)]),
            _ => {
                self.block("can't expand * over a subquery without an alias");
                None
            }
        }
    }

    fn item_is_masked(&self, item: &Item<'_>) -> bool {
        matches!(&item.kind, ItemKind::Relation { relation, .. } if self.is_masked_relation(relation))
    }

    /// Target list with `*` and `alias.*` replaced by explicit columns, if they
    /// cover masked columns.
    fn expand_stars(
        &mut self,
        targets: &[&nodes::ResTarget],
    ) -> Option<Vec<Unique<'mem, &'mem nodes::ResTarget>>> {
        let frame = self.frames.last()?;
        let masked: Vec<bool> = frame
            .items
            .iter()
            .map(|item| self.item_is_masked(item))
            .collect();
        let refnames: Vec<String> = frame
            .items
            .iter()
            .map(|item| item.refname.clone())
            .collect();
        let merging = frame.merging_join;

        let mut plans: Vec<Option<Vec<Unique<'mem, &'mem nodes::ResTarget>>>> = vec![];
        let mut needed = false;

        for target in targets {
            let plan = match target.val() {
                Node::ColumnRef(column) => match fields(column) {
                    (names, true) if names.is_empty() => {
                        if masked.iter().any(|m| *m) {
                            if merging {
                                self.block("can't expand * across a JOIN with USING or NATURAL over masked columns; list the columns");
                                return None;
                            }
                            let parts: Option<Vec<_>> =
                                (0..masked.len()).map(|i| self.expand_item(i)).collect();
                            parts.map(|p| p.into_iter().flatten().collect())
                        } else {
                            None
                        }
                    }
                    (names, true) => {
                        let qualifier = names.last().copied().unwrap_or("");
                        match refnames.iter().position(|r| r == qualifier) {
                            Some(i) if masked[i] => self.expand_item(i),
                            _ => None,
                        }
                    }
                    _ => None,
                },
                _ => None,
            };
            needed |= plan.is_some();
            plans.push(plan);
        }

        if !needed {
            return None;
        }

        let mut expanded: Vec<Unique<'mem, &'mem nodes::ResTarget>> = vec![];
        for (target, plan) in targets.iter().zip(plans) {
            match plan {
                None => expanded.push(self.mem.make_unique(*target)),
                Some(columns) => expanded.extend(columns),
            }
        }

        self.changed = true;
        Some(expanded)
    }

    /// Expand `*` in RETURNING, then mask it.
    fn returning(&mut self, returning: Option<nodes::ReturningClauseMut<'mem, '_>>) {
        if let Some(mut returning) = returning {
            let targets: Vec<_> = returning
                .exprs()
                .iter()
                .filter_map(|node| match node {
                    Node::ResTarget(target) => Some(target),
                    _ => None,
                })
                .collect();
            if let Some(exprs) = self.expand_stars(&targets) {
                let exprs: Vec<_> = exprs.into_iter().map(|e| e.uncast()).collect();
                returning.set_exprs(self.mem.make_list(&exprs));
            }
            self.transform_returning_clause(returning);
        }
    }

    /// Whole-row reference to a masked relation: `t`, `t.*` in an expression.
    fn whole_row(&mut self, refname: &str) -> Option<Unique<'mem, Node<'mem>>> {
        let item = find_item(&self.frames, refname)?;
        let ItemKind::Relation { relation, names } = &item.kind else {
            return None;
        };
        if !self.is_masked_relation(relation) {
            return None;
        }
        let qualifier = ident(&item.refname);
        let columns = names
            .iter()
            .map(|name| format!("{qualifier}.{}", ident(name)))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "ROW({columns})::{}.{}",
            ident(&relation.schema),
            ident(&relation.name)
        );
        let mut expr = self.parse_expr(&sql)?;
        // Mask the columns inside the row.
        self.transform_node(Assignable::new(&mut expr));
        Some(expr)
    }

    fn column_ref(&mut self, column: &nodes::ColumnRef) -> Option<Unique<'mem, Node<'mem>>> {
        let (names, star) = fields(column);

        if star {
            return match names.as_slice() {
                [.., qualifier] => self.whole_row(qualifier),
                [] => None,
            };
        }

        if self.guard_derived(&names) {
            return None;
        }

        if let Some(target) = self.column_target(&names) {
            if self.proxy_refs.contains(&address(column)) {
                // Masked in the results by the proxy mask.
                self.masked.insert(target.label);
                return None;
            }
            if self.raw_refs.contains(&address(column)) {
                self.raw.insert(target.label);
                return None;
            }
            let expr = self.masked_expr(column, &target)?;
            self.masked.insert(target.label);
            return Some(expr);
        }

        // `SELECT t FROM t` is a whole-row reference if no column is named `t`.
        if let [name] = names.as_slice()
            && resolve_column(&self.frames, &names).is_none()
        {
            return self.whole_row(name);
        }

        None
    }

    fn with_frame(&mut self, f: impl FnOnce(&mut Self)) {
        self.frames.push(Frame::default());
        let predicate = std::mem::replace(&mut self.predicate, false);
        let from = std::mem::replace(&mut self.from, false);
        f(self);
        self.predicate = predicate;
        self.from = from;
        self.frames.pop();
    }

    /// Transform a FROM list, where views are inlined.
    fn transform_from_list<'mutref>(
        &mut self,
        list: pg_raw_parse::list_mut::NodeListMut<'mem, 'mutref, pg_raw_parse::list::NodeList>,
    ) {
        let from = std::mem::replace(&mut self.from, true);
        self.transform_list(list);
        self.from = from;
    }

    fn with_predicate(&mut self, predicate: bool, f: impl FnOnce(&mut Self)) {
        let saved = std::mem::replace(&mut self.predicate, predicate);
        f(self);
        self.predicate = saved;
    }

    /// A call or operator that must be inlined, at the root of a clause.
    fn root_replacement(&mut self, node: Node<'_>) -> Option<Unique<'mem, Node<'mem>>> {
        let use_ = match node {
            Node::FuncCall(call) => self.call(call),
            Node::A_Expr(expr) => self.operator(expr),
            _ => return None,
        };
        match use_ {
            CallUse::Inline(inlined) => Some(inlined),
            CallUse::Allow | CallUse::Block => None,
        }
    }

    /// Mask an inlined view or function before it replaces the original node.
    fn mask_replacement(&mut self, replacement: &mut Unique<'mem, Node<'mem>>) {
        if self.depth > MAX_DEPTH * 4 {
            self.block("views or functions are nested too deeply");
            return;
        }
        self.depth += 1;
        self.transform_node(Assignable::new(replacement));
        self.depth -= 1;
        self.changed = true;
        self.touched = true;
    }

    /// Add a DML target relation to the current frame.
    /// Allow proxy masks on the next SELECT, the statement's top level.
    pub(super) fn allow_proxies(&mut self) {
        self.proxies_allowed = true;
    }

    /// Leave plain output columns of the top-level SELECT whose policy has a
    /// proxy mask unmasked in the statement, for the plugin to mask in the
    /// results. Other references to the same columns still get the fallback.
    fn route_proxies(&mut self, select: &nodes::SelectStmt) {
        // Raw values would be written, deduplicated, grouped or aggregated.
        if select.into_clause().is_some()
            || !select.distinct_clause().is_empty()
            || !select.group_clause().is_empty()
            || !matches!(select.having_clause(), Node::None)
        {
            return;
        }

        for (position, target) in select.target_list().iter().enumerate() {
            let Node::ColumnRef(column) = target.val() else {
                continue;
            };
            let (names, star) = fields(column);
            // Positions after a star depend on what it expands to.
            if star {
                return;
            }
            let Some(mask) = self.column_target(&names) else {
                continue;
            };
            let (Some(proxy), type_oid @ 1..) = (mask.proxy, mask.type_oid) else {
                continue;
            };
            let output = target
                .name()
                .or_else(|| names.last().copied())
                .unwrap_or_default();
            // ORDER BY the output column would sort by raw values.
            if select
                .sort_clause()
                .iter()
                .any(|sort| refers_to_output(sort.node(), position, output))
            {
                continue;
            }
            let Ok(column_index) = u16::try_from(position) else {
                return;
            };
            self.proxy_refs.insert(address(column));
            self.proxies.push(super::ProxyColumn {
                column: column_index,
                proxy,
                type_oid,
            });
        }
    }

    fn add_target(&mut self, relation: Option<&nodes::RangeVar>) {
        if let Some(range_var) = relation {
            self.check_view_write(range_var);
            self.add_range_var(range_var);
        }
    }
}

/// The column in a raw-search comparison side, possibly wrapped in a normalizer.
/// Does an `ORDER BY` item refer to the output column at `position` named `name`,
/// by ordinal or by name?
fn refers_to_output(node: Node<'_>, position: usize, name: &str) -> bool {
    match node {
        Node::A_Const(constant) => matches!(
            constant.val(),
            Some(pg_raw_parse::ConstValue::Integer(ordinal)) if ordinal as usize == position + 1
        ),
        Node::ColumnRef(column) => matches!(fields(column).0.as_slice(), [field] if *field == name),
        _ => false,
    }
}

fn raw_column(node: Node<'_>) -> Option<&nodes::ColumnRef> {
    match node {
        Node::ColumnRef(column) => Some(column),
        Node::FuncCall(call) if is_normalizer(call) => {
            let mut args = call.args().iter();
            match (args.next(), args.next()) {
                (Some(arg), None) => raw_column(arg),
                _ => None,
            }
        }
        _ => None,
    }
}

fn is_normalizer(call: &nodes::FuncCall) -> bool {
    let names: Vec<_> = call.funcname().iter().filter_map(|n| n.as_str()).collect();
    matches!(names.as_slice(), [name] | ["pg_catalog", name] if NORMALIZERS.contains(name))
}

/// Values a masked column may be compared with in a raw search.
fn operand_ok(node: Node<'_>) -> bool {
    match node {
        Node::ParamRef(_) | Node::A_Const(_) | Node::ColumnRef(_) => true,
        Node::TypeCast(cast) => operand_ok(cast.arg()),
        Node::FuncCall(call) if is_normalizer(call) => call.args().iter().all(operand_ok),
        Node::NodeList(list) => list.iter().all(operand_ok),
        Node::A_ArrayExpr(array) => array.elements().iter().all(operand_ok),
        _ => false,
    }
}

fn search_op(expr: &nodes::A_Expr) -> Option<SearchOp> {
    let op = expr
        .name()
        .iter()
        .next_back()
        .and_then(|n| n.as_str())
        .unwrap_or("");
    match expr.kind {
        A_Expr_Kind::AEXPR_OP => match op {
            "=" | "<>" | "!=" => Some(SearchOp::Equality),
            "<" | ">" | "<=" | ">=" => Some(SearchOp::Range),
            "~~" | "!~~" | "~~*" | "!~~*" => Some(SearchOp::Like),
            _ => None,
        },
        A_Expr_Kind::AEXPR_OP_ANY | A_Expr_Kind::AEXPR_OP_ALL if matches!(op, "=" | "<>") => {
            Some(SearchOp::Any)
        }
        A_Expr_Kind::AEXPR_DISTINCT | A_Expr_Kind::AEXPR_NOT_DISTINCT => Some(SearchOp::Distinct),
        A_Expr_Kind::AEXPR_IN => Some(SearchOp::In),
        A_Expr_Kind::AEXPR_LIKE | A_Expr_Kind::AEXPR_ILIKE => Some(SearchOp::Like),
        A_Expr_Kind::AEXPR_BETWEEN
        | A_Expr_Kind::AEXPR_NOT_BETWEEN
        | A_Expr_Kind::AEXPR_BETWEEN_SYM
        | A_Expr_Kind::AEXPR_NOT_BETWEEN_SYM => Some(SearchOp::Range),
        _ => None,
    }
}

fn cte_info(cte: &nodes::CommonTableExpr) -> Cte {
    let aliases = names(cte.aliascolnames());
    Cte {
        name: cte.ctename().unwrap_or("").to_owned(),
        columns: if aliases.is_empty() {
            output_names(cte.ctequery())
        } else {
            Some(aliases)
        },
    }
}

/// What to do with a generic node, decided while it's borrowed.
enum Action<'mem> {
    Recurse,
    Done,
    ColumnRef,
    /// Replace the node with this one, then mask it.
    Replace(Unique<'mem, Node<'mem>>),
    Subselect {
        refname: String,
        columns: Option<Vec<String>>,
    },
    Function {
        refname: String,
        columns: Option<Vec<String>>,
    },
    Join {
        merging: bool,
        aliased: bool,
    },
}

impl<'c, 'mem> Transform<'mem> for Masker<'c, 'mem> {
    fn transform_node<'mutref>(&mut self, node: Assignable<'mem, 'mutref>) {
        let action = match &*node {
            NodeMut::ColumnRef(_) => Action::ColumnRef,
            NodeMut::RangeVar(range_var) => match self.inline_view(range_var) {
                Some(inlined) => Action::Replace(inlined),
                None => {
                    self.add_range_var(range_var);
                    Action::Done
                }
            },
            NodeMut::FuncCall(call) => match self.call(call) {
                CallUse::Allow => Action::Recurse,
                CallUse::Inline(inlined) => Action::Replace(inlined),
                CallUse::Block => Action::Done,
            },
            NodeMut::A_Expr(expr) => match self.operator(expr) {
                CallUse::Allow => Action::Recurse,
                CallUse::Inline(inlined) => Action::Replace(inlined),
                CallUse::Block => Action::Done,
            },
            NodeMut::RangeSubselect(subselect) => {
                let alias = subselect.alias();
                let aliases = alias.map(|a| names(a.colnames())).unwrap_or_default();
                Action::Subselect {
                    refname: alias.and_then(|a| a.aliasname()).unwrap_or("").to_owned(),
                    columns: if aliases.is_empty() {
                        output_names(subselect.subquery())
                    } else {
                        Some(aliases)
                    },
                }
            }
            NodeMut::RangeFunction(function) if let Some(use_) = self.range_function(function) => {
                match use_ {
                    CallUse::Inline(inlined) => Action::Replace(inlined),
                    CallUse::Allow | CallUse::Block => Action::Done,
                }
            }
            NodeMut::RangeFunction(function) => {
                let alias = function.alias();
                let aliases = alias.map(|a| names(a.colnames())).unwrap_or_default();
                let function_name = function
                    .functions()
                    .iter()
                    .next()
                    .and_then(|pair| pair.as_node_list().and_then(|l| l.iter().next()))
                    .and_then(|call| match call {
                        Node::FuncCall(call) => {
                            call.funcname().iter().next_back().and_then(|n| n.as_str())
                        }
                        _ => None,
                    })
                    .unwrap_or("");
                Action::Function {
                    refname: alias
                        .and_then(|a| a.aliasname())
                        .unwrap_or(function_name)
                        .to_owned(),
                    columns: (!aliases.is_empty()).then_some(aliases),
                }
            }
            NodeMut::JoinExpr(join) => Action::Join {
                merging: join.is_natural || !join.using_clause().is_empty(),
                aliased: join.alias().is_some() || join.join_using_alias().is_some(),
            },
            _ => Action::Recurse,
        };

        match action {
            Action::Done => (),
            Action::Recurse => transform::transform_node(node.into_inner(), self),
            Action::Replace(mut replacement) => {
                self.mask_replacement(&mut replacement);
                node.replace(replacement);
            }
            Action::ColumnRef => {
                let replacement = match &*node {
                    NodeMut::ColumnRef(column) => self.column_ref(column),
                    _ => None,
                };
                if let Some(replacement) = replacement {
                    node.replace(replacement);
                    self.changed = true;
                }
            }
            Action::Subselect { refname, columns } | Action::Function { refname, columns } => {
                transform::transform_node(node.into_inner(), self);
                if let Some(frame) = self.frames.last_mut() {
                    frame.items.push(Item {
                        refname,
                        kind: ItemKind::Derived(columns),
                    });
                }
            }
            Action::Join { merging, aliased } => {
                let before = self.frames.last().map(|f| f.items.len()).unwrap_or(0);
                self.with_predicate(true, |masker| {
                    transform::transform_node(node.into_inner(), masker);
                });
                if let Some(frame) = self.frames.last_mut() {
                    frame.merging_join |= merging;
                }
                if aliased
                    && let Some(frame) = self.frames.last()
                    && frame.items[before.min(frame.items.len())..]
                        .iter()
                        .any(|item| self.item_is_masked(item))
                {
                    self.block("aliased joins over masked columns are not supported");
                }
            }
        }
    }

    // Expressions are checked in their typed hooks, which run for top-level
    // expressions (e.g. a whole WHERE clause) as well as nested ones.
    fn transform_a_expr<'mutref>(&mut self, node: nodes::A_ExprMut<'mem, 'mutref>) {
        if self.predicate {
            self.mark_raw_a_expr(&node);
        }
        transform::transform_a_expr(node, self);
    }

    fn transform_null_test<'mutref>(&mut self, node: nodes::NullTestMut<'mem, 'mutref>) {
        if self.predicate {
            self.mark_raw_column(SearchOp::IsNull, node.arg());
        }
        transform::transform_null_test(node, self);
    }

    fn transform_func_call<'mutref>(&mut self, node: nodes::FuncCallMut<'mem, 'mutref>) {
        // Calls in generic positions were checked by `transform_node`.
        if !self.checked_calls.contains(&call_address(&node)) {
            self.check_call(&node);
        }
        transform::transform_func_call(node, self);
    }

    fn transform_with_clause<'mutref>(&mut self, node: nodes::WithClauseMut<'mem, 'mutref>) {
        let recursive = node.recursive;
        // A recursive CTE can refer to itself, and to CTEs after it.
        if recursive {
            for cte in node.ctes().iter() {
                let cte = cte_info(cte);
                if let Some(frame) = self.frames.last_mut() {
                    frame.ctes.push(cte);
                }
            }
        }
        transform::transform_with_clause(node, self);
    }

    fn transform_common_table_expr<'mutref>(
        &mut self,
        node: nodes::CommonTableExprMut<'mem, 'mutref>,
    ) {
        let cte = cte_info(&node);
        transform::transform_common_table_expr(node, self);
        if let Some(frame) = self.frames.last_mut()
            && !frame.ctes.iter().any(|c| c.name == cte.name)
        {
            frame.ctes.push(cte);
        }
    }

    fn transform_res_target<'mutref>(&mut self, mut node: nodes::ResTargetMut<'mem, 'mutref>) {
        // Pin the output name of column references, which masking would change.
        // This is the name Postgres would give them anyway.
        // Function calls can be inlined, which would change their output name too.
        if node.name().is_none()
            && let Some(name) = column_ref_name(node.val())
                .filter(|name| !super::shape::is_placeholder(name))
                .or_else(|| match node.val() {
                    Node::FuncCall(_) => Some(figure_name(node.val())),
                    Node::A_Expr(expr) if self.is_user_operator(expr) => Some("?column?".into()),
                    _ => None,
                })
        {
            node.set_name(Some(self.mem.copy_string(&name)));
        }
        transform::transform_res_target(node, self);
    }

    fn transform_select_stmt<'mutref>(&mut self, mut node: nodes::SelectStmtMut<'mem, 'mutref>) {
        let top = std::mem::take(&mut self.proxies_allowed);
        self.with_frame(|masker| {
            if let Some(with) = node.with_clause_mut() {
                masker.transform_with_clause(with);
            }

            if node.op != SetOperation::SETOP_NONE {
                if let Some(larg) = node.larg_mut() {
                    masker.transform_select_stmt(larg);
                }
                if let Some(rarg) = node.rarg_mut() {
                    masker.transform_select_stmt(rarg);
                }
                // ORDER BY / LIMIT of a set operation refer to its (masked) output.
                masker.transform_sort_by_list(node.sort_clause_mut());
                clause!(
                    masker,
                    node,
                    limit_offset,
                    limit_offset_mut,
                    set_limit_offset
                );
                clause!(masker, node, limit_count, limit_count_mut, set_limit_count);
                return;
            }

            masker.transform_list(node.values_lists_mut());
            masker.transform_from_list(node.from_clause_mut());
            let targets: Vec<_> = node.target_list().iter().collect();
            if let Some(targets) = masker.expand_stars(&targets) {
                node.set_target_list(masker.mem.make_list(&targets));
            }
            if top {
                masker.route_proxies(&node);
            }
            masker.transform_res_target_list(node.target_list_mut());
            masker.transform_list(node.distinct_clause_mut());

            masker.with_predicate(true, |masker| {
                clause!(
                    masker,
                    node,
                    where_clause,
                    where_clause_mut,
                    set_where_clause
                );
            });

            masker.transform_list(node.group_clause_mut());
            clause!(
                masker,
                node,
                having_clause,
                having_clause_mut,
                set_having_clause
            );
            masker.transform_list(node.window_clause_mut());
            masker.transform_sort_by_list(node.sort_clause_mut());
            clause!(
                masker,
                node,
                limit_offset,
                limit_offset_mut,
                set_limit_offset
            );
            clause!(masker, node, limit_count, limit_count_mut, set_limit_count);
        });
    }

    fn transform_insert_stmt<'mutref>(&mut self, mut node: nodes::InsertStmtMut<'mem, 'mutref>) {
        self.with_frame(|masker| {
            if let Some(with) = node.with_clause_mut() {
                masker.transform_with_clause(with);
            }
            // The source query doesn't see the target table.
            transform::transform_node(node.select_stmt_mut(), masker);

            masker.add_target(node.relation());
            if let Some(on_conflict) = node.on_conflict_clause_mut() {
                // The proposed row; it's the client's own input, so it's not masked.
                if let Some(frame) = masker.frames.last_mut() {
                    frame.items.push(Item {
                        refname: "excluded".into(),
                        kind: ItemKind::Derived(None),
                    });
                }
                masker.transform_on_conflict_clause(on_conflict);
                if let Some(frame) = masker.frames.last_mut() {
                    frame.items.pop();
                }
            }
            masker.returning(node.returning_clause_mut());
        });
    }

    fn transform_update_stmt<'mutref>(&mut self, mut node: nodes::UpdateStmtMut<'mem, 'mutref>) {
        self.with_frame(|masker| {
            if let Some(with) = node.with_clause_mut() {
                masker.transform_with_clause(with);
            }
            masker.add_target(node.relation());
            masker.transform_from_list(node.from_clause_mut());
            masker.transform_res_target_list(node.target_list_mut());
            masker.with_predicate(true, |masker| {
                clause!(
                    masker,
                    node,
                    where_clause,
                    where_clause_mut,
                    set_where_clause
                );
            });
            masker.returning(node.returning_clause_mut());
        });
    }

    fn transform_delete_stmt<'mutref>(&mut self, mut node: nodes::DeleteStmtMut<'mem, 'mutref>) {
        self.with_frame(|masker| {
            if let Some(with) = node.with_clause_mut() {
                masker.transform_with_clause(with);
            }
            masker.add_target(node.relation());
            masker.transform_from_list(node.using_clause_mut());
            masker.with_predicate(true, |masker| {
                clause!(
                    masker,
                    node,
                    where_clause,
                    where_clause_mut,
                    set_where_clause
                );
            });
            masker.returning(node.returning_clause_mut());
        });
    }

    fn transform_copy_stmt<'mutref>(&mut self, mut node: nodes::CopyStmtMut<'mem, 'mutref>) {
        if node.is_from {
            return;
        }
        if node.is_program || node.filename().is_some() {
            self.block("COPY to a file or program is not allowed for masked users");
            return;
        }

        if let Some(range_var) = node.relation()
            && let Some(name) = range_var.relname()
        {
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
            transform::transform_node(copy.as_mut().query_mut(), self);
            node.replace(copy);
            self.changed = true;
            return;
        }

        transform::transform_node(node.query_mut(), self);
    }
}
