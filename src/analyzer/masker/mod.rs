//! Rewrites a statement so every reference to a SQL-masked column reads the
//! mask instead, and tracks what values carry from proxy-masked columns,
//! which are masked in the results (see `results`).
mod columns;
mod functions;
mod results;
mod stars;
mod views;

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::rc::Rc;

use pg_raw_parse::{
    Node, NodeMut,
    make::{MemoryToken, Unique},
    nodes,
    raw::{JsonTableColumnType, ObjectType, ReturningOptionKind, SetOperation, SubLinkType},
    transform::{self, Assignable, Transform},
};

use super::Context;
use super::rules;
use super::scope::{Cte, Frame, Item, ItemKind, derived_outputs, find_cte, unknown_columns};
use super::shape::is_placeholder;
use super::taint::{Lookup, OutputColumn, Outputs, Taint};
use crate::config::OnUnresolved;
use crate::mask::SearchOp;
use functions::{CallCheck, CallUse, ParamMode};
use results::{OutputRef, StatementState};

/// Why statements after one that may change name resolution are blocked.
const RESOLUTION_CHANGED: &str = "statements after one that may change name resolution (search_path, role or DDL) can't be checked in the same query; send them separately";

/// Why EXECUTE of a statement prepared elsewhere is blocked.
const EXECUTE_UNKNOWN: &str = "EXECUTE of a statement prepared outside this query can't be checked for masked users; send the PREPARE in the same query";

/// Quote an identifier.
pub(super) fn ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Mask to apply to one column reference.
struct MaskTarget<'c> {
    /// Index of the policy in the config.
    policy: usize,
    qualifier: String,
    label: String,
    kind: TargetKind<'c>,
}

/// How a masked column is masked for this user.
enum TargetKind<'c> {
    /// Rewritten in the statement.
    Sql {
        template: &'c str,
        raw_search: &'c HashSet<SearchOp>,
        cast: &'c str,
        arguments: &'c [String],
    },
    /// Masked in the results by `Policies::proxies[proxy]`; references are
    /// never rewritten.
    Proxy {
        proxy: usize,
        /// Type OID of the column; 0 if unknown.
        type_oid: u32,
    },
}

impl MaskTarget<'_> {
    /// The value a reference reads, if the column is proxy-masked.
    fn proxy(&self) -> Option<Taint> {
        match self.kind {
            TargetKind::Proxy { proxy, type_oid } => Some(Taint::Proxy { proxy, type_oid }),
            TargetKind::Sql { .. } => None,
        }
    }
}

/// How a table-like view's column computed from masked columns is masked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DerivedPolicy {
    /// Not computed from columns masked for this user.
    None,
    /// Computed from a SQL-masked column: it can't be masked.
    Sql,
    /// Computed only from proxy-masked columns: NULL in results.
    Proxy,
}

/// How `*` covers one FROM item.
#[derive(Clone)]
enum Expansion {
    /// A relation with masked columns: its columns, by name.
    Columns { refname: String, names: Vec<String> },
    /// Anything else: `refname.*`.
    Star(String),
}

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

/// Transform a generic child of a node of a known type the way
/// `transform_node` would, replacing it through the field's setter.
macro_rules! child {
    ($masker:expr, $node:expr, $get_mut:ident, $set:ident) => {{
        let action = $masker.action(&$node.$get_mut());
        match $masker.replacement(action, &$node.$get_mut()) {
            Ok(Some(replacement)) => $node.$set(replacement),
            Ok(None) => (),
            Err(keep) => $masker.descend(keep, $node.$get_mut()),
        }
    }};
}

/// What a view or function does for this user.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// Reads no SQL-masked columns; use it as is.
    Safe,
    /// Reads masked columns; inline its definition with masks applied.
    Inline,
    Blocked(String),
}

/// What a view or function body does for this user.
#[derive(Debug, Clone)]
struct BodyInfo {
    verdict: Verdict,
    /// Reads relations with masked columns.
    touched: bool,
    /// Reads proxy-masked columns.
    reads_proxies: bool,
    /// Calls an IMMUTABLE function that reads proxy-masked columns, which
    /// the planner may run in advance.
    folds_proxies: bool,
}

impl BodyInfo {
    fn blocked(reason: impl Into<String>) -> Self {
        Self {
            verdict: Verdict::Blocked(reason.into()),
            touched: false,
            reads_proxies: false,
            folds_proxies: false,
        }
    }
}

/// Verdicts shared by the masker of a statement and the maskers it starts for
/// view and function bodies.
#[derive(Debug, Default)]
struct Memo {
    views: HashMap<(String, String), BodyInfo>,
    functions: HashMap<i64, BodyInfo>,
    /// Whether a parameter of a SQL function can reach a sink in its body.
    param_sinks: HashMap<i64, bool>,
    /// Views and functions being analyzed, to stop recursion.
    active: Vec<String>,
    /// Bodies parsed to find where their parameters go.
    #[cfg(test)]
    param_parses: usize,
}

pub(super) struct Masker<'c, 'mem> {
    mem: MemoryToken<'mem>,
    ctx: &'c Context<'c>,
    frames: Vec<Frame<'c>>,
    /// Inside a WHERE or JOIN condition, where raw searches are possible.
    predicate: bool,
    /// Column references used in an allowed raw search shape.
    raw_refs: HashSet<usize>,
    /// Function calls and user operators already checked, e.g. in a FROM
    /// list, by address, and what's left to check once their arguments are
    /// transformed.
    checked_calls: HashMap<usize, CallCheck<'c>>,
    /// Inside a FROM list, where views can be inlined.
    from: bool,
    /// Nesting of view and function bodies.
    depth: usize,
    memo: Rc<RefCell<Memo>>,
    pub(super) blocked: Option<String>,
    pub(super) changed: bool,
    /// SQL masks changed what the statement computes, not only its text.
    masked_sql: bool,
    pub(super) masked: BTreeSet<String>,
    pub(super) raw: BTreeSet<String>,
    /// Reads or writes a relation with masked columns.
    pub(super) touched: bool,
    /// Taint of the expression being transformed: the join of its inputs.
    taint: Taint,
    /// Column references that are whole output columns.
    passthrough: HashSet<usize>,
    /// ORDER BY, DISTINCT ON and GROUP BY names of output columns.
    output_refs: HashMap<usize, OutputRef>,
    /// Outputs of the query level that finished last; its caller takes them.
    outputs: Option<Outputs>,
    /// What the statement being analyzed does with proxy-masked columns.
    state: StatementState,
    /// Result masks and redaction of the statements analyzed so far.
    pub(super) results: super::Results,
    /// Some statement, or a body it uses, reads proxy-masked columns.
    pub(super) reads_proxies: bool,
    /// Some statement calls an IMMUTABLE function that reads proxy-masked
    /// columns, directly or through other functions.
    folds_proxies: bool,
    /// The statement runs: false inside a plain EXPLAIN, where only sinks
    /// reached while planning apply.
    executing: bool,
    /// Inside an EXPLAIN, whose plan shows values the planner computes.
    explaining: bool,
    /// Analyzing a SQL function's body with parameters carrying values of
    /// proxy-masked columns, to find where they can go.
    params: Option<ParamMode>,
    /// Transforming a WINDOW clause, whose definitions are recorded by name.
    in_window_clause: bool,
    /// Transforming a set operation's ORDER BY, which sees only its outputs.
    setop_sort: bool,
    /// Transforming the SET list of UPDATE or ON CONFLICT DO UPDATE.
    writing: Option<&'static str>,
    /// Non-Clean taints from sources so far, to tell whether a recursive CTE
    /// read any.
    sources: u64,
    /// CTEs being analyzed, innermost last.
    ctes: Vec<String>,
    /// Names SQL-PREPAREd by earlier statements of this query.
    prepared: HashSet<String>,
    /// An earlier statement of this query may change name resolution.
    path_changed: bool,
    /// The query is the one `set_config` call PgDog tracks.
    tracked_set_config: bool,
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

fn expr_address(expr: &nodes::A_Expr) -> usize {
    std::ptr::from_ref(expr) as usize
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

/// Approximation of Postgres' FigureColname, good enough for pinning names.
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
            checked_calls: HashMap::new(),
            from: false,
            depth: 0,
            memo: Rc::default(),
            blocked: None,
            changed: false,
            masked_sql: false,
            masked: BTreeSet::new(),
            raw: BTreeSet::new(),
            touched: false,
            taint: Taint::Clean,
            passthrough: HashSet::new(),
            output_refs: HashMap::new(),
            outputs: None,
            state: StatementState::default(),
            results: super::Results::default(),
            reads_proxies: false,
            folds_proxies: false,
            executing: true,
            explaining: false,
            params: None,
            in_window_clause: false,
            setop_sort: false,
            writing: None,
            sources: 0,
            ctes: vec![],
            prepared: HashSet::new(),
            path_changed: false,
            tracked_set_config: false,
        }
    }

    /// The query is the one `SELECT set_config(...)` PgDog tracks: it may
    /// change `search_path`.
    pub(super) fn track_set_config(&mut self) {
        self.tracked_set_config = true;
    }

    /// A masker for the body of a view or function, sharing this one's
    /// verdicts. Verdicts are memoized whatever context first asked for them,
    /// so it starts from a clean state.
    fn nested<'n>(&self, ctx: &'n Context<'n>) -> Masker<'n, 'mem> {
        let mut nested = Masker::new(self.mem, ctx);
        nested.depth = self.depth + 1;
        nested.memo = self.memo.clone();
        nested
    }

    /// The context of a view or function body.
    fn body_context(&self, search_path: Vec<String>) -> Context<'c> {
        Context {
            catalog: self.ctx.catalog,
            assignments: self.ctx.assignments,
            policies: self.ctx.policies,
            profile: self.ctx.profile,
            search_path,
        }
    }

    /// Analyze the statements of a body, each on its own: deferred sinks
    /// apply inside bodies too.
    fn body_statements<'r>(
        &mut self,
        stmts: impl IntoIterator<Item = nodes::RawStmtMut<'mem, 'r>>,
    ) {
        for (i, stmt) in stmts.into_iter().enumerate() {
            self.statement(stmt);
            self.finish_statement(i, false);
        }
    }

    /// Analyze the statements of a view or function body for this user.
    fn analyze_body(
        &self,
        body: &str,
        search_path: Vec<String>,
        inlinable: impl FnOnce(&nodes::RawStmt) -> Result<(), String>,
    ) -> BodyInfo {
        if self.depth >= MAX_DEPTH {
            return BodyInfo::blocked("views or functions are nested too deeply");
        }
        let mut stmts = match self.mem.parse(body) {
            Ok(stmts) => stmts,
            Err(err) => return BodyInfo::blocked(format!("failed to parse: {err}")),
        };
        let ctx = self.body_context(search_path);
        let mut nested = self.nested(&ctx);
        let shape = match stmts.as_ref().iter().collect::<Vec<_>>().as_slice() {
            [stmt] => inlinable(stmt),
            _ => Err("it has more than one statement".into()),
        };
        nested.body_statements(stmts.as_mut());

        // Only SQL masks make a body unsafe as is: star expansions are
        // plan-equivalent, and proxy-masked columns are never rewritten.
        let verdict = match nested.blocked {
            // The change would outlive the call, without PgDog seeing it.
            _ if nested.path_changed => Verdict::Blocked(
                "it changes name resolution (search_path, role or DDL) beyond the call".into(),
            ),
            Some(reason) => Verdict::Blocked(reason),
            None if !nested.masked_sql => Verdict::Safe,
            None => match shape {
                Ok(()) => Verdict::Inline,
                Err(why) => {
                    Verdict::Blocked(format!("reads masked columns and can't be inlined: {why}"))
                }
            },
        };
        BodyInfo {
            verdict,
            touched: nested.touched,
            reads_proxies: nested.reads_proxies,
            folds_proxies: nested.folds_proxies,
        }
    }

    /// Could a function's parameters reach a sink in its body? The body is
    /// analyzed with parameters carrying values of proxy-masked columns.
    /// Anything that can't be analyzed counts as a sink.
    fn body_param_sinks(&self, body: &str, search_path: Vec<String>, params: ParamMode) -> bool {
        if self.depth >= MAX_DEPTH {
            return true;
        }
        let Ok(mut stmts) = self.mem.parse(body) else {
            return true;
        };
        #[cfg(test)]
        {
            self.memo.borrow_mut().param_parses += 1;
        }
        let ctx = self.body_context(search_path);
        let mut nested = self.nested(&ctx);
        nested.params = Some(params);
        nested.body_statements(stmts.as_mut());
        nested.blocked.is_some() || nested.params.is_some_and(|params| params.sinks)
    }

    /// How many function bodies were parsed to find where their parameters
    /// go.
    #[cfg(test)]
    pub(super) fn param_parses(&self) -> usize {
        self.memo.borrow().param_parses
    }

    fn block(&mut self, reason: impl Into<String>) {
        self.blocked.get_or_insert_with(|| reason.into());
    }

    /// Mask a top-level statement. `finish_statement` ends it.
    pub(super) fn statement(&mut self, stmt: nodes::RawStmtMut<'mem, '_>) {
        let node = stmt.stmt();
        // A plain EXPLAIN of SELECT INTO creates no table.
        let query = match node {
            Node::ExplainStmt(explain) if rules::explain_executes(explain) => explain.query(),
            Node::ExplainStmt(_) => Node::None,
            node => node,
        };
        self.state = StatementState {
            // `set_config('role', ...)` calls also set it, in `call_target`.
            changes_resolution: rules::changes_resolution(node),
            stores_expressions: rules::stores_expressions(node),
            returns_rows: super::returns_rows(node),
            select_into: matches!(query, Node::SelectStmt(select) if rules::into_clause(select).is_some()),
            ..StatementState::default()
        };
        self.outputs = None;
        self.passthrough.clear();
        self.output_refs.clear();
        if let Err(reason) = rules::check_statement(node) {
            self.block(reason);
            return;
        }
        self.check_shadowing(node);
        self.check_ddl(node);
        self.check_maintenance(node);
        transform::transform_raw_stmt(stmt, self);
    }

    /// TRUNCATE, VACUUM, ANALYZE and LOCK of relations with proxy-masked
    /// columns run their triggers and index expressions on real values.
    fn check_maintenance(&mut self, node: Node<'_>) {
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
    fn resolves_to_proxy_relation(&self, range_var: &nodes::RangeVar) -> bool {
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
    fn check_shadowing(&mut self, node: Node<'_>) {
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
            let mut item = Item::derived(refname, cte.outputs.clone().renamed(&aliases));
            item.pending = cte.pending.then(|| cte.name.clone());
            item
        } else if self.path_changed {
            self.block(RESOLUTION_CHANGED);
            Item::derived(refname, unknown_columns())
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
            if self.has_proxy_masks(relation) {
                self.state.touches_proxies = true;
            }
            // Aliases map to columns by position, which a stale catalog can
            // get wrong; names can't be.
            if !aliases.is_empty()
                && let Some(first) = self.first_masked_column(relation)
                && aliases.len() > first
            {
                self.block(format!(
                    "the column aliases of {refname} cover masked column {}.{}; alias columns in the select list instead",
                    relation.qualified_name(),
                    relation.columns[first].name
                ));
            }
            Item::relation(refname, relation, &aliases)
        } else if let Some(result) = rules::check_catalog_relation(schema, name) {
            if let Err(reason) = result {
                self.block(reason);
            }
            Item::derived(refname, unknown_columns())
        } else {
            if self.ctx.policies.config.general.on_unresolved == OnUnresolved::Block {
                self.block(format!(
                    "relation \"{name}\" is not in the catalog, so its columns can't be checked"
                ));
            }
            // Nothing is known about its columns.
            Item::derived(refname, Outputs::unknown())
        };

        if let Some(frame) = self.frames.last_mut() {
            frame.items.push(item);
        }
    }

    /// Expand `*` in RETURNING, then mask it and set its outputs. `target` is
    /// the DML target's item in the current frame.
    fn returning(
        &mut self,
        returning: Option<nodes::ReturningClauseMut<'mem, '_>>,
        target: Option<usize>,
    ) {
        let Some(mut returning) = returning else {
            self.outputs = Some(Outputs::default());
            return;
        };

        // PG18: `old` and `new` (or their aliases) are the target row before
        // and after the change, for qualified names only.
        let target = target.and_then(|i| Some(self.frames.last()?.items.get(i)?.kind.clone()));
        let items = self.frames.last().map_or(0, |frame| frame.items.len());
        if let Some(kind) = target
            && let Some(frame) = self.frames.last_mut()
        {
            let (mut old, mut new) = ("old", "new");
            for option in returning.options().iter() {
                match (option.option, option.value()) {
                    (ReturningOptionKind::RETURNING_OPTION_OLD, Some(alias)) => old = alias,
                    (ReturningOptionKind::RETURNING_OPTION_NEW, Some(alias)) => new = alias,
                    _ => (),
                }
            }
            for refname in [old, new] {
                frame.items.push(Item {
                    refname: refname.to_owned(),
                    kind: kind.clone(),
                    qualified_only: true,
                    pending: None,
                    function: false,
                });
            }
        }

        let targets = res_targets(returning.exprs());
        if let Some(exprs) = self.expand_stars(&targets) {
            let exprs: Vec<_> = exprs.into_iter().map(|e| e.uncast()).collect();
            returning.set_exprs(self.mem.make_list(&exprs));
        }
        let top = self.result_level();
        let slots = self.output_slots(
            returning
                .exprs_mut()
                .into_iter()
                .filter_map(|node| match node {
                    NodeMut::ResTarget(target) => Some(target),
                    _ => None,
                }),
            top,
        );
        let (outputs, expand) = self.level_outputs(&slots, top);
        if expand && let Some(exprs) = self.expand_slots(&res_targets(returning.exprs()), &slots) {
            let exprs: Vec<_> = exprs.into_iter().map(|e| e.uncast()).collect();
            returning.set_exprs(self.mem.make_list(&exprs));
        }
        self.outputs = Some(outputs);

        if let Some(frame) = self.frames.last_mut() {
            frame.items.truncate(items);
        }
    }

    /// Transform a query level. Its references never join the enclosing
    /// expression's taint: what it passes on is in its outputs.
    fn with_frame(&mut self, f: impl FnOnce(&mut Self)) {
        self.frames.push(Frame::default());
        let predicate = std::mem::replace(&mut self.predicate, false);
        let from = std::mem::replace(&mut self.from, false);
        let taint = std::mem::take(&mut self.taint);
        let in_window_clause = std::mem::replace(&mut self.in_window_clause, false);
        let setop_sort = std::mem::replace(&mut self.setop_sort, false);
        let writing = self.writing.take();
        f(self);
        self.predicate = predicate;
        self.from = from;
        self.taint = taint;
        self.in_window_clause = in_window_clause;
        self.setop_sort = setop_sort;
        self.writing = writing;
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

    /// Add a DML target relation to the current frame. Returns its item's
    /// position.
    fn add_target(&mut self, relation: Option<&nodes::RangeVar>) -> Option<usize> {
        let range_var = relation?;
        self.check_view_write(range_var);
        let position = self.frames.last()?.items.len();
        self.add_range_var(range_var);
        let item = self.frames.last()?.items.get(position)?;
        if let ItemKind::Relation { relation, .. } = item.kind
            && self.has_proxy_masks(relation)
        {
            self.state.writes_proxies = true;
        }
        Some(position)
    }

    /// Transform the FROM list of UPDATE or DELETE, which can't see the
    /// target, not even from LATERAL items.
    fn transform_dml_from_list<'mutref>(
        &mut self,
        list: pg_raw_parse::list_mut::NodeListMut<'mem, 'mutref, pg_raw_parse::list::NodeList>,
        target: Option<usize>,
    ) {
        let start = target.map_or(0, |target| target + 1);
        let saved = self
            .frames
            .last_mut()
            .map(|frame| frame.visible.replace(start..usize::MAX));
        self.transform_from_list(list);
        if let (Some(frame), Some(saved)) = (self.frames.last_mut(), saved) {
            frame.visible = saved;
        }
    }

    /// The output name `transform_res_target` pins on a target without one.
    fn pinned_name(&self, val: Node<'_>) -> Option<String> {
        column_ref_name(val)
            .filter(|name| !is_placeholder(name))
            .or_else(|| match val {
                Node::FuncCall(_) => Some(figure_name(val)),
                Node::A_Expr(expr) if self.is_user_operator(expr) => Some("?column?".into()),
                _ => None,
            })
    }

    /// What the merged columns of a USING or NATURAL join over `items` of
    /// this level carry.
    fn merged_taint(
        &self,
        items: std::ops::Range<usize>,
        using: &[String],
        natural: bool,
    ) -> Taint {
        let Some(items) = self.frames.last().and_then(|frame| frame.items.get(items)) else {
            return Taint::Clean;
        };
        let mut taint = Taint::Clean;
        for item in items {
            let column = |name: &str| match &item.kind {
                ItemKind::Relation { .. } => item
                    .relation_column(name)
                    .and_then(|(relation, column)| self.mask_target(relation, column, ""))
                    .and_then(|target| target.proxy())
                    .unwrap_or_default(),
                ItemKind::Derived(outputs) => match outputs.lookup(name) {
                    Lookup::Certain(taint) | Lookup::Possible(taint) => taint,
                    Lookup::Absent => Taint::Clean,
                },
            };
            if natural {
                // Every column with a matching name: any of them.
                taint = taint.join(match &item.kind {
                    ItemKind::Relation { relation, .. } if self.has_proxy_masks(relation) => {
                        Taint::Computed
                    }
                    ItemKind::Relation { .. } => Taint::Clean,
                    ItemKind::Derived(outputs) => outputs.bound().computed(),
                });
            }
            for name in using {
                taint = taint.join(column(name));
            }
        }
        taint
    }

    /// Push an item for a table function (XMLTABLE, JSON_TABLE) whose columns
    /// are defined in the call: names, and whether they're FOR ORDINALITY.
    /// Every other column is computed from the arguments.
    fn add_table_function(
        &mut self,
        refname: String,
        columns: Option<Vec<(String, bool)>>,
        aliases: &[String],
        args: Taint,
    ) {
        let taint = args.computed();
        let outputs = match columns {
            Some(columns) => Outputs {
                columns: columns
                    .into_iter()
                    .map(|(name, ordinality)| OutputColumn {
                        name: Some(name),
                        taint: if ordinality { Taint::Clean } else { taint },
                    })
                    .collect(),
                rest: None,
            },
            None => Outputs {
                columns: vec![],
                rest: Some(taint),
            },
        };
        if let Some(frame) = self.frames.last_mut() {
            frame
                .items
                .push(Item::derived(refname, outputs.renamed(aliases)));
        }
    }

    /// What to do with a generic node, decided while it's borrowed.
    fn action(&mut self, node: &NodeMut<'mem, '_>) -> Action<'mem> {
        match node {
            NodeMut::ColumnRef(_) => Action::ColumnRef,
            NodeMut::RangeVar(range_var) => match self.inline_view(range_var) {
                Some(inlined) => Action::Replace(inlined),
                None => {
                    self.add_range_var(range_var);
                    Action::Keep(Keep::Done)
                }
            },
            NodeMut::FuncCall(call) => match self.call(call) {
                CallUse::Allow => Action::Keep(Keep::Recurse),
                CallUse::Inline(inlined) => Action::Replace(inlined),
                CallUse::Block => Action::Keep(Keep::Done),
            },
            NodeMut::A_Expr(expr) => match self.operator(expr) {
                CallUse::Allow => Action::Keep(Keep::Recurse),
                CallUse::Inline(inlined) => Action::Replace(inlined),
                CallUse::Block => Action::Keep(Keep::Done),
            },
            NodeMut::RangeSubselect(subselect) => {
                let alias = subselect.alias();
                Action::Keep(Keep::Subselect {
                    refname: alias.and_then(|a| a.aliasname()).unwrap_or("").to_owned(),
                    aliases: alias.map(|a| names(a.colnames())).unwrap_or_default(),
                    lateral: subselect.lateral,
                })
            }
            NodeMut::RangeFunction(function) if let Some(use_) = self.range_function(function) => {
                match use_ {
                    CallUse::Inline(inlined) => Action::Replace(inlined),
                    CallUse::Allow | CallUse::Block => Action::Keep(Keep::Done),
                }
            }
            NodeMut::RangeFunction(function) => {
                let alias = function.alias();
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
                let refname = alias
                    .and_then(|a| a.aliasname())
                    .unwrap_or(function_name)
                    .to_owned();
                Action::Keep(Keep::Function {
                    names: self.range_function_names(function, &refname),
                    refname,
                })
            }
            _ => Action::Keep(Keep::Recurse),
        }
    }

    /// The node replacing a generic node, if it must be replaced, or what to
    /// do with it otherwise.
    fn replacement(
        &mut self,
        action: Action<'mem>,
        node: &NodeMut<'mem, '_>,
    ) -> Result<Option<Unique<'mem, Node<'mem>>>, Keep> {
        match action {
            Action::Replace(mut replacement) => {
                self.mask_replacement(&mut replacement);
                Ok(Some(replacement))
            }
            Action::ColumnRef => {
                let replacement = match node {
                    NodeMut::ColumnRef(column) => self.column_ref(column),
                    _ => None,
                };
                if replacement.is_some() {
                    self.changed = true;
                }
                Ok(replacement)
            }
            Action::Keep(keep) => Err(keep),
        }
    }

    /// Transform a generic node that stays in place.
    fn descend(&mut self, keep: Keep, node: NodeMut<'mem, '_>) {
        match keep {
            Keep::Done => (),
            Keep::Recurse => transform::transform_node(node, self),
            Keep::Subselect {
                refname,
                aliases,
                lateral,
            } => {
                // A non-LATERAL subquery doesn't see the other items of this level.
                let saved = self
                    .frames
                    .last_mut()
                    .map(|frame| std::mem::replace(&mut frame.lateral_only, !lateral));
                self.outputs = None;
                transform::transform_node(node, self);
                let outputs = self
                    .outputs
                    .take()
                    .unwrap_or_else(Outputs::unknown)
                    .renamed(&aliases);
                if let Some(frame) = self.frames.last_mut() {
                    frame.lateral_only = saved.unwrap_or_default();
                    frame.items.push(Item::derived(refname, outputs));
                }
            }
            Keep::Function { refname, names } => {
                // Every column is computed from the arguments, and from the
                // body of a function that reads proxy-masked columns.
                let taint = self
                    .scoped(|masker| transform::transform_node(node, masker))
                    .computed();
                let mut item = Item::derived(
                    refname,
                    Outputs {
                        columns: names
                            .into_iter()
                            .map(|name| OutputColumn {
                                name: Some(name),
                                taint,
                            })
                            .collect(),
                        rest: Some(taint),
                    },
                );
                item.function = true;
                if let Some(frame) = self.frames.last_mut() {
                    frame.items.push(item);
                }
            }
        }
    }
}

/// The relations of a list of relation names.
fn range_vars(list: &pg_raw_parse::list::NodeList) -> Vec<&nodes::RangeVar> {
    list.iter()
        .filter_map(|node| match node {
            Node::RangeVar(range_var) => Some(range_var),
            _ => None,
        })
        .collect()
}

/// The targets of a RETURNING list.
fn res_targets(list: &pg_raw_parse::list::NodeList) -> Vec<&nodes::ResTarget> {
    list.iter()
        .filter_map(|node| match node {
            Node::ResTarget(target) => Some(target),
            _ => None,
        })
        .collect()
}

/// Add the columns a JSON_TABLE column defines, NESTED ones flattened, and
/// whether they're FOR ORDINALITY. Sets `names` to `None` if a column can't be
/// read.
fn json_table_columns(column: &nodes::JsonTableColumn, names: &mut Option<Vec<(String, bool)>>) {
    if column.coltype == JsonTableColumnType::JTC_NESTED {
        for nested in column.columns().iter() {
            match nested {
                Node::JsonTableColumn(nested) => json_table_columns(nested, names),
                _ => *names = None,
            }
        }
        return;
    }
    let ordinality = column.coltype == JsonTableColumnType::JTC_FOR_ORDINALITY;
    match (column.name(), names.as_mut()) {
        (Some(name), Some(names)) => names.push((name.to_owned(), ordinality)),
        (None, _) => *names = None,
        (Some(_), None) => (),
    }
}

/// A recursive CTE before it's analyzed: it can refer to itself, and to CTEs
/// after it. Nothing is known about what its columns carry yet.
fn pending_cte(cte: &nodes::CommonTableExpr) -> Cte {
    let outputs = derived_outputs(cte.ctequery()).renamed(&names(cte.aliascolnames()));
    Cte {
        name: cte.ctename().unwrap_or("").to_owned(),
        outputs: Outputs {
            columns: outputs
                .columns
                .into_iter()
                .map(|column| OutputColumn {
                    name: column.name,
                    taint: Taint::Unknown,
                })
                .collect(),
            rest: outputs.rest.map(|_| Taint::Unknown),
        },
        pending: true,
    }
}

/// Columns a CTE's SEARCH and CYCLE clauses add, after its own. They hold the
/// listed columns' values.
fn search_cycle_columns(cte: &nodes::CommonTableExpr) -> Vec<(String, Vec<String>)> {
    let mut columns = vec![];
    if let Some(search) = cte.search_clause() {
        let listed = names(search.search_col_list());
        columns.push((search.search_seq_column().unwrap_or("").to_owned(), listed));
    }
    if let Some(cycle) = cte.cycle_clause() {
        let listed = names(cycle.cycle_col_list());
        for column in [cycle.cycle_mark_column(), cycle.cycle_path_column()] {
            columns.push((column.unwrap_or("").to_owned(), listed.clone()));
        }
    }
    columns
}

/// What to do with a generic node, decided while it's borrowed.
enum Action<'mem> {
    /// Replace the node with this one, then mask it.
    Replace(Unique<'mem, Node<'mem>>),
    ColumnRef,
    Keep(Keep),
}

/// What to do with a generic node that stays in place.
enum Keep {
    Recurse,
    Done,
    Subselect {
        refname: String,
        aliases: Vec<String>,
        lateral: bool,
    },
    Function {
        refname: String,
        /// Column names, when known.
        names: Vec<String>,
    },
}

impl<'c, 'mem> Transform<'mem> for Masker<'c, 'mem> {
    fn transform_node<'mutref>(&mut self, node: Assignable<'mem, 'mutref>) {
        let action = self.action(&node);
        match self.replacement(action, &node) {
            Ok(Some(replacement)) => node.replace(replacement),
            Ok(None) => (),
            Err(keep) => self.descend(keep, node.into_inner()),
        }
    }

    fn transform_join_expr<'mutref>(&mut self, mut node: nodes::JoinExprMut<'mem, 'mutref>) {
        let merging = node.is_natural || !node.using_clause().is_empty();
        let aliased = node.alias().is_some() || node.join_using_alias().is_some();
        let using: Vec<String> = node
            .using_clause()
            .iter()
            .filter_map(|name| name.sval().map(str::to_owned))
            .collect();
        let natural = node.is_natural;
        let before = self.frames.last().map_or(0, |frame| frame.items.len());
        child!(self, node, larg_mut, set_larg);
        child!(self, node, rarg_mut, set_rarg);

        // The ON clause only sees the join's own items, and outer query levels.
        let after = self.frames.last().map_or(0, |frame| frame.items.len());
        let saved = self
            .frames
            .last_mut()
            .map(|frame| frame.visible.replace(before..after));
        self.with_predicate(true, |masker| child!(masker, node, quals_mut, set_quals));
        if let Some(frame) = self.frames.last_mut() {
            frame.visible = saved.flatten();
            frame.merging_join |= merging;
        }

        // Merged columns compare, and combine, both sides' values.
        let merged = self.merged_taint(before..after, &using, natural);
        self.note(merged, false);

        if aliased
            && let Some(frame) = self.frames.last()
            && frame.items[before.min(frame.items.len())..]
                .iter()
                .any(|item| self.item_is_masked(item))
        {
            self.block("aliased joins over masked columns are not supported");
        }
    }

    fn transform_execute_stmt<'mutref>(&mut self, node: nodes::ExecuteStmtMut<'mem, 'mutref>) {
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

    fn transform_explain_stmt<'mutref>(&mut self, node: nodes::ExplainStmtMut<'mem, 'mutref>) {
        // Without ANALYZE, the statement is only planned: values reach no
        // sink, except those the planner itself evaluates.
        let executing = self.executing;
        let explaining = std::mem::replace(&mut self.explaining, true);
        self.executing &= rules::explain_executes(&node);
        transform::transform_explain_stmt(node, self);
        self.executing = executing;
        self.explaining = explaining;
    }

    fn transform_param_ref<'mutref>(&mut self, _node: nodes::ParamRefMut<'mem, 'mutref>) {
        // A parameter of the function body being analyzed for where its
        // parameters go. Anywhere else, parameters are the client's values.
        if self.params.is_some() {
            self.note(Taint::Computed, false);
        }
    }

    fn transform_fetch_stmt<'mutref>(&mut self, node: nodes::FetchStmtMut<'mem, 'mutref>) {
        self.state.runs_earlier = true;
        transform::transform_fetch_stmt(node, self);
    }

    fn transform_declare_cursor_stmt<'mutref>(
        &mut self,
        node: nodes::DeclareCursorStmtMut<'mem, 'mutref>,
    ) {
        self.state.portal = Some(("DECLARE CURSOR", None));
        transform::transform_declare_cursor_stmt(node, self);
    }

    fn transform_prepare_stmt<'mutref>(&mut self, node: nodes::PrepareStmtMut<'mem, 'mutref>) {
        self.state.portal = Some(("PREPARE", node.name().map(str::to_owned)));
        transform::transform_prepare_stmt(node, self);
    }

    fn transform_create_table_as_stmt<'mutref>(
        &mut self,
        node: nodes::CreateTableAsStmtMut<'mem, 'mutref>,
    ) {
        let what = if node.objtype == ObjectType::OBJECT_MATVIEW {
            "CREATE MATERIALIZED VIEW"
        } else {
            "CREATE TABLE AS"
        };
        self.outputs = None;
        transform::transform_create_table_as_stmt(node, self);
        let taint = self.outputs.take().map_or(Taint::Unknown, |o| o.bound());
        self.sink(taint, what);
    }

    // MERGE can appear inside EXPLAIN, PREPARE and CTEs, which `check_statement`
    // allows.
    fn transform_merge_stmt<'mutref>(&mut self, _node: nodes::MergeStmtMut<'mem, 'mutref>) {
        self.block("MERGE is not allowed for masked users");
    }

    fn transform_range_table_func<'mutref>(
        &mut self,
        node: nodes::RangeTableFuncMut<'mem, 'mutref>,
    ) {
        let alias = node.alias();
        let refname = alias
            .and_then(|a| a.aliasname())
            .unwrap_or("xmltable")
            .to_owned();
        let aliases = alias.map(|a| names(a.colnames())).unwrap_or_default();
        let columns: Option<Vec<(String, bool)>> = node
            .columns()
            .iter()
            .map(|column| {
                column
                    .colname()
                    .map(|name| (name.to_owned(), column.for_ordinality))
            })
            .collect();
        let args = self.scoped(|masker| transform::transform_range_table_func(node, masker));
        self.add_table_function(refname, columns, &aliases, args);
    }

    fn transform_json_table<'mutref>(&mut self, node: nodes::JsonTableMut<'mem, 'mutref>) {
        let alias = node.alias();
        let refname = alias
            .and_then(|a| a.aliasname())
            .unwrap_or("json_table")
            .to_owned();
        let aliases = alias.map(|a| names(a.colnames())).unwrap_or_default();
        let mut columns = Some(vec![]);
        for column in node.columns().iter() {
            json_table_columns(column, &mut columns);
        }
        let args = self.scoped(|masker| transform::transform_json_table(node, masker));
        self.add_table_function(refname, columns, &aliases, args);
    }

    // Expressions are checked in their typed hooks, which run for top-level
    // expressions (e.g. a whole WHERE clause) as well as nested ones.
    fn transform_a_expr<'mutref>(&mut self, node: nodes::A_ExprMut<'mem, 'mutref>) {
        if self.predicate {
            self.mark_raw_a_expr(&node);
        }
        let check = match self.checked_calls.get(&expr_address(&node)) {
            Some(check) => check.clone(),
            None => self.check_operator(&node),
        };
        if !check.needs_post_check() {
            transform::transform_a_expr(node, self);
            return;
        }
        let name = node
            .name()
            .iter()
            .next_back()
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_owned();
        let args = self.scoped(|masker| transform::transform_a_expr(node, masker));
        self.call_post_check(&check, args, &name);
    }

    fn transform_null_test<'mutref>(&mut self, node: nodes::NullTestMut<'mem, 'mutref>) {
        if self.predicate {
            self.mark_raw_column(SearchOp::IsNull, node.arg());
        }
        transform::transform_null_test(node, self);
    }

    fn transform_func_call<'mutref>(&mut self, node: nodes::FuncCallMut<'mem, 'mutref>) {
        // Calls in generic positions were checked by `transform_node`.
        let check = match self.checked_calls.get(&call_address(&node)) {
            Some(check) => check.clone(),
            None => self.check_call(&node),
        };
        let name = node
            .funcname()
            .iter()
            .next_back()
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_owned();
        let windows: Vec<String> = node
            .over()
            .into_iter()
            .flat_map(|over| [over.name(), over.refname()])
            .flatten()
            .map(str::to_owned)
            .collect();
        let args = self.scoped(|masker| transform::transform_func_call(node, masker));
        // A named window's PARTITION BY and ORDER BY decide the value too.
        for window in windows {
            if let Some(taint) = self
                .frames
                .last()
                .and_then(|frame| frame.windows.get(&window))
                .copied()
            {
                self.note_from(taint, false, false);
            }
        }
        self.call_post_check(&check, args, &name);
    }

    fn transform_window_def<'mutref>(&mut self, node: nodes::WindowDefMut<'mem, 'mutref>) {
        let named = self.in_window_clause.then(|| {
            (
                node.name().map(str::to_owned),
                node.refname().map(str::to_owned),
            )
        });
        let taint = self.scoped(|masker| transform::transform_window_def(node, masker));
        if let Some((Some(name), refname)) = named
            && let Some(frame) = self.frames.last_mut()
        {
            let inherited = refname
                .and_then(|refname| frame.windows.get(&refname).copied())
                .unwrap_or_default();
            frame.windows.insert(name, taint.join(inherited));
        }
    }

    fn transform_sub_link<'mutref>(&mut self, node: nodes::SubLinkMut<'mem, 'mutref>) {
        let exists = node.sub_link_type == SubLinkType::EXISTS_SUBLINK;
        self.outputs = None;
        transform::transform_sub_link(node, self);
        let outputs = self.outputs.take().unwrap_or_else(Outputs::unknown);
        // A scalar or array subquery is computed, even when it passes a
        // column through. EXISTS only says whether there are rows.
        if !exists {
            self.note_from(outputs.bound().computed(), false, false);
        }
    }

    fn transform_with_clause<'mutref>(&mut self, node: nodes::WithClauseMut<'mem, 'mutref>) {
        let recursive = node.recursive;
        // A recursive CTE can refer to itself, and to CTEs after it.
        if recursive {
            for cte in node.ctes().iter() {
                let cte = pending_cte(cte);
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
        let name = node.ctename().unwrap_or("").to_owned();
        let aliases = names(node.aliascolnames());
        let added = search_cycle_columns(&node);
        let recursive = self
            .frames
            .last()
            .is_some_and(|frame| frame.ctes.iter().any(|cte| cte.name == name && cte.pending));

        self.ctes.push(name.clone());
        // Deferred sinks aren't part of the snapshot: they must survive.
        let (sources, computes) = (self.sources, self.state.computes);
        self.outputs = None;
        transform::transform_common_table_expr(node, self);
        let mut outputs = self
            .outputs
            .take()
            .unwrap_or_else(Outputs::unknown)
            .renamed(&aliases);
        // Nothing but its own pending rows entered it: it's provably clean.
        if recursive && self.sources == sources {
            outputs = outputs.cleaned();
            self.state.computes = computes;
        }
        self.ctes.pop();

        for (column, listed) in added {
            let taint = listed
                .iter()
                .map(|listed| match outputs.lookup(listed) {
                    Lookup::Certain(taint) => taint,
                    _ => Taint::Unknown,
                })
                .fold(Taint::Clean, Taint::join)
                .computed();
            outputs.push(OutputColumn {
                name: Some(column),
                taint,
            });
        }

        if let Some(frame) = self.frames.last_mut() {
            let cte = Cte {
                name,
                outputs,
                pending: false,
            };
            match frame.ctes.iter_mut().find(|c| c.name == cte.name) {
                Some(existing) if existing.pending => *existing = cte,
                Some(_) => (),
                None => frame.ctes.push(cte),
            }
        }
    }

    fn transform_res_target<'mutref>(&mut self, mut node: nodes::ResTargetMut<'mem, 'mutref>) {
        // Pin the output name of column references, which masking would change.
        // This is the name Postgres would give them anyway.
        // Function calls can be inlined, which would change their output name too.
        if node.name().is_none()
            && let Some(name) = self.pinned_name(node.val())
        {
            node.set_name(Some(self.mem.copy_string(&name)));
        }
        match self.writing {
            // A SET target, subscripts included, is written as a whole.
            Some(what) => {
                let taint = self.scoped(|masker| transform::transform_res_target(node, masker));
                self.sink(taint, what);
            }
            None => transform::transform_res_target(node, self),
        }
    }

    fn transform_select_stmt<'mutref>(&mut self, mut node: nodes::SelectStmtMut<'mem, 'mutref>) {
        self.with_frame(|masker| {
            if let Some(with) = node.with_clause_mut() {
                masker.transform_with_clause(with);
            }

            if node.op != SetOperation::SETOP_NONE {
                // Columns are combined by position, and named after the left
                // branch's.
                let mut outputs = Outputs::unknown();
                if let Some(larg) = node.larg_mut() {
                    masker.outputs = None;
                    masker.transform_select_stmt(larg);
                    outputs = masker.outputs.take().unwrap_or_else(Outputs::unknown);
                }
                if let Some(rarg) = node.rarg_mut() {
                    masker.outputs = None;
                    masker.transform_select_stmt(rarg);
                    let right = masker.outputs.take().unwrap_or_else(Outputs::unknown);
                    outputs = outputs.union(right);
                }
                // ORDER BY / LIMIT of a set operation refer to its outputs.
                masker.record_output_refs(
                    &outputs,
                    node.sort_clause().iter().map(|sort| sort.node()),
                    OutputRef::Only,
                );
                masker.setop_sort = true;
                masker.transform_sort_by_list(node.sort_clause_mut());
                masker.setop_sort = false;
                clause!(
                    masker,
                    node,
                    limit_offset,
                    limit_offset_mut,
                    set_limit_offset
                );
                clause!(masker, node, limit_count, limit_count_mut, set_limit_count);
                masker.outputs = Some(outputs);
                return;
            }

            let mut outputs = None;
            if !node.values_lists().is_empty() {
                // One scope over every cell: each column carries what any does.
                let width = node
                    .values_lists()
                    .iter()
                    .next()
                    .and_then(|row| row.as_node_list().map(|row| row.iter().count()))
                    .unwrap_or(0);
                let taint = masker
                    .scoped(|masker| masker.transform_list(node.values_lists_mut()))
                    .computed();
                outputs = Some(Outputs {
                    columns: (1..=width)
                        .map(|i| OutputColumn {
                            name: Some(format!("column{i}")),
                            taint,
                        })
                        .collect(),
                    rest: None,
                });
            }
            masker.transform_from_list(node.from_clause_mut());
            // Named windows first: calls read their definitions' taint.
            masker.in_window_clause = true;
            masker.transform_list(node.window_clause_mut());
            masker.in_window_clause = false;

            let targets: Vec<_> = node.target_list().iter().collect();
            if let Some(targets) = masker.expand_stars(&targets) {
                node.set_target_list(masker.mem.make_list(&targets));
            }
            if node.values_lists().is_empty() {
                let top = masker.result_level();
                let slots = masker.output_slots(node.target_list_mut(), top);
                let (level, expand) = masker.level_outputs(&slots, top);
                if expand {
                    let targets: Vec<_> = node.target_list().iter().collect();
                    if let Some(targets) = masker.expand_slots(&targets, &slots) {
                        node.set_target_list(masker.mem.make_list(&targets));
                    }
                }
                masker.record_output_refs(
                    &level,
                    node.sort_clause()
                        .iter()
                        .map(|sort| sort.node())
                        .chain(node.distinct_clause().iter()),
                    OutputRef::Prefer,
                );
                masker.record_output_refs(&level, node.group_clause().iter(), OutputRef::Fallback);
                outputs = Some(level);
            }
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
            masker.transform_sort_by_list(node.sort_clause_mut());
            clause!(
                masker,
                node,
                limit_offset,
                limit_offset_mut,
                set_limit_offset
            );
            clause!(masker, node, limit_count, limit_count_mut, set_limit_count);
            masker.outputs = outputs;
        });
    }

    fn transform_insert_stmt<'mutref>(&mut self, mut node: nodes::InsertStmtMut<'mem, 'mutref>) {
        self.with_frame(|masker| {
            if let Some(with) = node.with_clause_mut() {
                masker.transform_with_clause(with);
            }
            // The source query doesn't see the target table.
            masker.outputs = None;
            transform::transform_node(node.select_stmt_mut(), masker);
            // DEFAULT VALUES has no source.
            let source = masker.outputs.take().map_or(Taint::Clean, |o| o.bound());
            masker.sink(source, "INSERT");

            let target = masker.add_target(node.relation());
            if let Some(on_conflict) = node.on_conflict_clause_mut() {
                // The proposed row: what the source carries.
                if let Some(frame) = masker.frames.last_mut() {
                    frame.items.push(Item::derived(
                        "excluded".into(),
                        Outputs {
                            columns: vec![],
                            rest: Some(source),
                        },
                    ));
                }
                masker.transform_on_conflict_clause(on_conflict);
                if let Some(frame) = masker.frames.last_mut() {
                    frame.items.pop();
                }
            }
            masker.returning(node.returning_clause_mut(), target);
        });
    }

    fn transform_on_conflict_clause<'mutref>(
        &mut self,
        node: nodes::OnConflictClauseMut<'mem, 'mutref>,
    ) {
        let writing = self.writing.replace("ON CONFLICT DO UPDATE");
        transform::transform_on_conflict_clause(node, self);
        self.writing = writing;
    }

    fn transform_update_stmt<'mutref>(&mut self, mut node: nodes::UpdateStmtMut<'mem, 'mutref>) {
        self.with_frame(|masker| {
            if let Some(with) = node.with_clause_mut() {
                masker.transform_with_clause(with);
            }
            let target = masker.add_target(node.relation());
            masker.transform_dml_from_list(node.from_clause_mut(), target);
            let writing = masker.writing.replace("UPDATE");
            masker.transform_res_target_list(node.target_list_mut());
            masker.writing = writing;
            masker.with_predicate(true, |masker| {
                clause!(
                    masker,
                    node,
                    where_clause,
                    where_clause_mut,
                    set_where_clause
                );
            });
            masker.returning(node.returning_clause_mut(), target);
        });
    }

    fn transform_delete_stmt<'mutref>(&mut self, mut node: nodes::DeleteStmtMut<'mem, 'mutref>) {
        self.with_frame(|masker| {
            if let Some(with) = node.with_clause_mut() {
                masker.transform_with_clause(with);
            }
            let target = masker.add_target(node.relation());
            masker.transform_dml_from_list(node.using_clause_mut(), target);
            masker.with_predicate(true, |masker| {
                clause!(
                    masker,
                    node,
                    where_clause,
                    where_clause_mut,
                    set_where_clause
                );
            });
            masker.returning(node.returning_clause_mut(), target);
        });
    }

    fn transform_copy_stmt<'mutref>(&mut self, mut node: nodes::CopyStmtMut<'mem, 'mutref>) {
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
