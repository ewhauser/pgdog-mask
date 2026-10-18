//! Rewrites a statement so every reference to a SQL-masked column reads the
//! mask instead, and tracks what values carry from proxy-masked columns,
//! which are masked in the results (see `results`).
mod columns;
mod from;
mod functions;
mod results;
mod stars;
mod statements;
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
use super::scope::{Cte, Frame, Item, derived_outputs, exact_name, find_cte};
use super::taint::{Lookup, OutputColumn, Outputs, Taint};
use crate::mask::SearchOp;
use functions::{CallArgs, CallCheck, CallUse, ParamMode, ParamSinks};
use results::{OutputRef, StatementState};
pub(super) use views::{view_allowlisted, view_outputs};

/// Why statements after one that may change name resolution are blocked.
const RESOLUTION_CHANGED: &str = "statements after one that may change name resolution (search_path, role or DDL) can't be checked in the same query; send them separately";

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
    /// SQL-masked, read where nothing is rewritten: by a table-like view's
    /// definition, which runs on real values.
    AsIs,
}

impl MaskTarget<'_> {
    /// The value a reference reads, if it isn't rewritten.
    fn proxy(&self) -> Option<Taint> {
        match self.kind {
            TargetKind::Proxy { proxy, type_oid } => Some(Taint::Proxy { proxy, type_oid }),
            TargetKind::AsIs => Some(Taint::Computed),
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
    /// Its errors need redaction: it writes, or computes on values of
    /// proxy-masked columns.
    redacts: bool,
}

impl BodyInfo {
    /// A body used as it is, without analysis.
    const TRUSTED: Self = Self {
        verdict: Verdict::Safe,
        touched: false,
        reads_proxies: false,
        folds_proxies: false,
        redacts: false,
    };

    /// A function that can't be analyzed, called where it runs on real
    /// values: it may read and write anything.
    const OPAQUE: Self = Self {
        verdict: Verdict::Safe,
        touched: false,
        reads_proxies: true,
        folds_proxies: false,
        redacts: true,
    };

    fn blocked(reason: impl Into<String>) -> Self {
        Self {
            verdict: Verdict::Blocked(reason.into()),
            ..Self::TRUSTED
        }
    }
}

/// Verdicts shared by the masker of a statement and the maskers it starts for
/// view and function bodies.
#[derive(Debug, Default)]
struct Memo {
    views: HashMap<(String, String), BodyInfo>,
    functions: HashMap<i64, BodyInfo>,
    /// Which parameters of a SQL function can reach a sink in its body.
    param_sinks: HashMap<i64, ParamSinks>,
    /// For a relation an unqualified name resolves to, by schema and name, a
    /// namesake in another schema that reads differently, if there's one.
    namesakes: HashMap<(String, String), Option<String>>,
    /// Views and functions being analyzed, to stop recursion.
    active: Vec<String>,
    /// The verdicts of what runs on real values: table-like views'
    /// definitions, and what they use.
    real_values: Option<Rc<RefCell<Memo>>>,
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
    /// `outputs` are a nested level's, and its caller hasn't taken them yet.
    unclaimed: bool,
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
    /// Analyzing what runs on real values: a table-like view's definition,
    /// and what it uses. Nothing is rewritten, and masked columns of every
    /// kind carry their values, like proxy-masked ones.
    real_values: bool,
    /// Analyzing only what a table-like view's definition puts in its
    /// columns (`view_outputs`): where else it moves values is
    /// `view_verdict`'s concern, so sinks don't block.
    outputs_only: bool,
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
            unclaimed: false,
            state: StatementState::default(),
            results: super::Results::default(),
            reads_proxies: false,
            folds_proxies: false,
            executing: true,
            explaining: false,
            params: None,
            real_values: false,
            outputs_only: false,
            in_window_clause: false,
            setop_sort: false,
            writing: None,
            sources: 0,
            ctes: vec![],
            prepared: HashSet::new(),
            path_changed: false,
        }
    }

    /// A masker for the body of a view or function, sharing this one's
    /// verdicts. Verdicts are memoized whatever context first asked for them,
    /// so it starts from a clean state.
    fn nested<'n>(&self, ctx: &'n Context<'n>) -> Masker<'n, 'mem> {
        let mut nested = Masker::new(self.mem, ctx);
        nested.depth = self.depth + 1;
        nested.memo = self.memo.clone();
        nested.real_values = self.real_values;
        nested.outputs_only = self.outputs_only;
        nested
    }

    /// A masker for what runs on real values, sharing the verdicts of
    /// others like it.
    fn real_values_masker(&self) -> Masker<'c, 'mem> {
        let mut masker = Masker::new(self.mem, self.ctx);
        masker.depth = self.depth;
        masker.real_values = true;
        masker.memo = self
            .memo
            .borrow_mut()
            .real_values
            .get_or_insert_with(Rc::default)
            .clone();
        masker
    }

    /// The columns whose values can't reach a sink, for messages: in what
    /// runs on real values, every masked column.
    fn sink_columns(&self) -> &'static str {
        if self.real_values {
            "masked columns"
        } else {
            "proxy-masked columns"
        }
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
            self.finish_statement(i);
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
            redacts: nested.results.redact_errors,
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

    /// Does a type name a relation's row type?
    fn is_row_type(&self, type_name: &nodes::TypeName) -> bool {
        let names: Vec<&str> = type_name.names().iter().filter_map(|n| n.sval()).collect();
        let catalog = self.ctx.catalog;
        match names.as_slice() {
            [schema, name] => catalog.get(schema, name).is_some(),
            [name] => !catalog.relations_named(name).is_empty(),
            _ => false,
        }
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
            writes: rules::writes(node),
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
        if !rules::deparsable(node) {
            self.block("a COPY option is missing its value or has one of the wrong type");
            return;
        }
        self.check_created(node);
        self.check_ddl(node);
        self.check_maintenance(node);
        transform::transform_raw_stmt(stmt, self);
    }

    /// Expand `*` in RETURNING, then mask it and set its outputs. `target` is
    /// the DML target's item in the current frame.
    fn returning(
        &mut self,
        returning: Option<nodes::ReturningClauseMut<'mem, '_>>,
        target: Option<usize>,
    ) {
        let Some(mut returning) = returning else {
            self.set_outputs(Some(Outputs::default()));
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
                    unknown_width: false,
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
        self.set_outputs(Some(outputs));

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
        // A nested level's outputs are its caller's to take.
        self.unclaimed = self.frames.len() > 1 && self.outputs.is_some();
        self.predicate = predicate;
        self.from = from;
        self.taint = taint;
        self.in_window_clause = in_window_clause;
        self.setop_sort = setop_sort;
        self.writing = writing;
        self.frames.pop();
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

    /// The output name `transform_res_target` pins on a target without one,
    /// where masking could change it: column references, and calls and user
    /// operators, which can be inlined.
    fn pinned_name(&self, val: Node<'_>) -> Option<String> {
        match val {
            Node::A_Expr(expr) if self.is_user_operator(expr) => Some("?column?".into()),
            val => exact_name(val),
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
                self.expect_outputs();
                transform::transform_node(node, self);
                let outputs = self
                    .take_outputs()
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
                item.unknown_width = true;
                if let Some(frame) = self.frames.last_mut() {
                    frame.items.push(item);
                }
            }
        }
    }
}

/// A type's name, if it isn't a built-in type.
fn user_type_name(type_name: &nodes::TypeName) -> Option<String> {
    let names: Vec<&str> = type_name.names().iter().filter_map(|n| n.sval()).collect();
    (!rules::builtin_type(&names)).then(|| names.join("."))
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

/// Transforms the arguments of a call one by one, recording what each
/// carries.
struct EachArg<'a, 'c, 'mem> {
    masker: &'a mut Masker<'c, 'mem>,
    taints: Vec<Taint>,
}

impl<'mem> Transform<'mem> for EachArg<'_, '_, 'mem> {
    fn transform_node<'mutref>(&mut self, node: Assignable<'mem, 'mutref>) {
        let taint = self.masker.scoped(|masker| masker.transform_node(node));
        self.taints.push(taint);
    }
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
        let natural = node.is_natural;
        let using: Vec<String> = node
            .using_clause()
            .iter()
            .filter_map(|name| name.sval().map(str::to_owned))
            .collect();
        let merging = natural || !using.is_empty();
        // `(...) AS j (cols)` hides the join's items behind `j`. `USING (...)
        // AS x` adds `x`, which names only the merged columns.
        let alias = node.alias().map(|alias| {
            (
                alias.aliasname().unwrap_or("").to_owned(),
                names(alias.colnames()),
            )
        });
        let using_alias = node
            .join_using_alias()
            .and_then(|alias| alias.aliasname())
            .map(str::to_owned);
        let before = self.frames.last().map_or(0, |frame| frame.items.len());
        let outer_merging = self
            .frames
            .last_mut()
            .is_some_and(|frame| std::mem::take(&mut frame.merging_join));
        child!(self, node, larg_mut, set_larg);
        child!(self, node, rarg_mut, set_rarg);
        let nested_merging = self.frames.last().is_some_and(|frame| frame.merging_join);

        // The ON clause only sees the join's own items, and outer query levels.
        let after = self.frames.last().map_or(0, |frame| frame.items.len());
        let saved = self
            .frames
            .last_mut()
            .map(|frame| frame.visible.replace(before..after));
        self.with_predicate(true, |masker| child!(masker, node, quals_mut, set_quals));
        if let Some(frame) = self.frames.last_mut() {
            frame.visible = saved.flatten();
            // An alias keeps the merged columns, and their order, inside it.
            frame.merging_join = outer_merging || (alias.is_none() && (nested_merging || merging));
        }

        // Merged columns compare, and combine, both sides' values.
        let merged = self.merged_taint(before..after, &using, natural);
        self.note(merged, false);
        if merging {
            let check = self.implicit_operator(&[(None, "=")]);
            if check.needs_post_check() {
                self.call_post_check(&check, &CallArgs::operands(merged), "=");
            }
        }

        if alias.is_none() && using_alias.is_none() {
            return;
        }
        if let Some(frame) = self.frames.last()
            && frame.items[before.min(frame.items.len())..]
                .iter()
                .any(|item| self.item_is_masked(item))
        {
            self.block("aliased joins over masked columns are not supported");
            return;
        }
        if let Some(refname) = using_alias {
            let mut outputs = Outputs::default();
            for name in &using {
                outputs.push(OutputColumn {
                    name: Some(name.clone()),
                    taint: self.merged_taint(before..after, std::slice::from_ref(name), false),
                });
            }
            let mut item = Item::derived(refname, outputs);
            item.qualified_only = true;
            if let Some(frame) = self.frames.last_mut() {
                frame.items.push(item);
            }
        }
        if let Some((refname, aliases)) = alias {
            self.alias_join(
                before..after,
                refname,
                &aliases,
                &using,
                natural || nested_merging,
            );
        }
    }

    fn transform_execute_stmt<'mutref>(&mut self, node: nodes::ExecuteStmtMut<'mem, 'mutref>) {
        self.execute_stmt(node);
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

    // Type modifiers are constants or identifiers, never column references:
    // in `mytype(ssn) 'x'`, `ssn` is a name Postgres passes to the type.
    // Values converted to a type that isn't built in outside a cast, e.g.
    // `RETURNING`, count against the whole statement. The conversion may
    // run user code, which may write.
    fn transform_type_name<'mutref>(&mut self, node: nodes::TypeNameMut<'mem, 'mutref>) {
        if let Some(data_type) = user_type_name(&node) {
            self.state.user_type.get_or_insert(data_type);
            self.state.writes = true;
        }
    }

    // A cast to a type that isn't built in can run a user-defined cast
    // function or domain check on the value. `ROW(...)` cast to a table's
    // row type is converted field by field.
    fn transform_type_cast<'mutref>(&mut self, mut node: nodes::TypeCastMut<'mem, 'mutref>) {
        let row = matches!(node.arg(), Node::RowExpr(_));
        let user_type = node
            .type_name()
            .filter(|type_name| !(row && self.is_row_type(type_name)))
            .and_then(user_type_name);
        let taint = self.scoped(|masker| child!(masker, node, arg_mut, set_arg));
        // The cast function or domain check may write, whatever the value.
        self.state.writes |= user_type.is_some();
        if let Some(data_type) = user_type
            && self.executing
        {
            self.sink_with(taint, |masker| {
                format!(
                    "a cast to {data_type}, which isn't a built-in type, can run a user-defined cast function or domain check on values of {}",
                    masker.sink_columns()
                )
            });
        }
    }

    fn transform_param_ref<'mutref>(&mut self, node: nodes::ParamRefMut<'mem, 'mutref>) {
        // A parameter of the function body being analyzed for where its
        // parameters go. Anywhere else, parameters are the client's values.
        if let Some(params) = &self.params {
            let taint = params.positional(node.number);
            self.note(taint, false);
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
        self.expect_outputs();
        transform::transform_create_table_as_stmt(node, self);
        let taint = self.take_outputs().map_or(Taint::Unknown, |o| o.bound());
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
        let operands = self.scoped(|masker| transform::transform_a_expr(node, masker));
        self.call_post_check(&check, &CallArgs::operands(operands), &name);
    }

    fn transform_null_test<'mutref>(&mut self, node: nodes::NullTestMut<'mem, 'mutref>) {
        if self.predicate {
            self.mark_raw_column(SearchOp::IsNull, node.arg());
        }
        transform::transform_null_test(node, self);
    }

    fn transform_func_call<'mutref>(&mut self, mut node: nodes::FuncCallMut<'mem, 'mutref>) {
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
        let names: Vec<Option<String>> = node
            .args()
            .iter()
            .map(|arg| match arg {
                Node::NamedArgExpr(named) => named.name().map(str::to_owned),
                _ => None,
            })
            .collect();
        let variadic = node.func_variadic;

        // What each argument carries, then the rest of the call.
        self.transform_list(node.funcname_mut());
        let mut each = EachArg {
            masker: self,
            taints: vec![],
        };
        transform::transform_list(node.args_mut(), &mut each);
        let taints = each.taints;
        let mut rest = self.scoped(|masker| {
            masker.transform_sort_by_list(node.agg_order_mut());
            child!(masker, node, agg_filter_mut, set_agg_filter);
            if let Some(over) = node.over_mut() {
                masker.transform_window_def(over);
            }
        });
        // A named window's PARTITION BY and ORDER BY decide the value too.
        for window in windows {
            if let Some(taint) = self
                .frames
                .last()
                .and_then(|frame| frame.windows.get(&window))
                .copied()
            {
                self.note_from(taint, false, false);
                rest = rest.join(taint);
            }
        }
        let args = CallArgs {
            args: names.into_iter().zip(taints).collect(),
            variadic,
            rest,
            operands: false,
        };
        self.call_post_check(&check, &args, &name);
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
        // `x op ANY|ALL (query)` and `x IN (query)` apply an operator to
        // the expression and the query's rows.
        let compares = matches!(
            node.sub_link_type,
            SubLinkType::ANY_SUBLINK | SubLinkType::ALL_SUBLINK | SubLinkType::ROWCOMPARE_SUBLINK
        );
        let operator = compares.then(|| {
            functions::qualified_name(node.oper_name())
                .map(|(schema, name)| (schema.map(str::to_owned), name.to_owned()))
                .unwrap_or((None, "=".to_owned()))
        });
        let check = operator
            .as_ref()
            .map(|(schema, name)| self.implicit_operator(&[(schema.as_deref(), name)]));
        self.expect_outputs();
        let operand = self.scoped(|masker| transform::transform_sub_link(node, masker));
        let outputs = self.take_outputs().unwrap_or_else(Outputs::unknown);
        // A scalar or array subquery is computed, even when it passes a
        // column through. EXISTS only says whether there are rows.
        if !exists {
            self.note_from(outputs.bound().computed(), false, false);
        }
        if let (Some(check), Some((_, name))) = (check, operator)
            && check.needs_post_check()
        {
            let operands = CallArgs::operands(operand.join(outputs.bound()));
            self.call_post_check(&check, &operands, &name);
        }
    }

    fn transform_case_expr<'mutref>(&mut self, mut node: nodes::CaseExprMut<'mem, 'mutref>) {
        // `CASE x WHEN v` compares `x = v`.
        let check = match node.arg() {
            Node::None => CallCheck::TRUSTED,
            _ => self.implicit_operator(&[(None, "=")]),
        };
        if !check.needs_post_check() {
            transform::transform_case_expr(node, self);
            return;
        }
        let mut operands = self.scoped(|masker| child!(masker, node, arg_mut, set_arg));
        for when in node.args_mut() {
            match when {
                NodeMut::CaseWhen(mut when) => {
                    operands = operands
                        .join(self.scoped(|masker| child!(masker, when, expr_mut, set_expr)));
                    child!(self, when, result_mut, set_result);
                }
                other => transform::transform_node(other, self),
            }
        }
        child!(self, node, defresult_mut, set_defresult);
        self.call_post_check(&check, &CallArgs::operands(operands), "=");
    }

    fn transform_sort_by<'mutref>(&mut self, node: nodes::SortByMut<'mem, 'mutref>) {
        // `ORDER BY x USING op` compares values of `x` with `op`.
        let operator = functions::qualified_name(node.use_op())
            .map(|(schema, name)| (schema.map(str::to_owned), name.to_owned()));
        let Some((schema, name)) = operator else {
            transform::transform_sort_by(node, self);
            return;
        };
        let check = self.implicit_operator(&[(schema.as_deref(), &name)]);
        let operands = self.scoped(|masker| transform::transform_sort_by(node, masker));
        if check.needs_post_check() {
            self.call_post_check(&check, &CallArgs::operands(operands), &name);
        }
    }

    fn transform_json_array_query_constructor<'mutref>(
        &mut self,
        node: nodes::JsonArrayQueryConstructorMut<'mem, 'mutref>,
    ) {
        // JSON_ARRAY(query) aggregates the query's rows, like ARRAY(query).
        self.expect_outputs();
        transform::transform_json_array_query_constructor(node, self);
        let outputs = self.take_outputs().unwrap_or_else(Outputs::unknown);
        self.note_from(outputs.bound().computed(), false, false);
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
        self.expect_outputs();
        transform::transform_common_table_expr(node, self);
        let mut outputs = self
            .take_outputs()
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
                    masker.expect_outputs();
                    masker.transform_select_stmt(larg);
                    outputs = masker.take_outputs().unwrap_or_else(Outputs::unknown);
                }
                if let Some(rarg) = node.rarg_mut() {
                    masker.expect_outputs();
                    masker.transform_select_stmt(rarg);
                    let right = masker.take_outputs().unwrap_or_else(Outputs::unknown);
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
                masker.set_outputs(Some(outputs));
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
            masker.set_outputs(outputs);
        });
    }

    fn transform_insert_stmt<'mutref>(&mut self, mut node: nodes::InsertStmtMut<'mem, 'mutref>) {
        self.with_frame(|masker| {
            if let Some(with) = node.with_clause_mut() {
                masker.transform_with_clause(with);
            }
            // The source query doesn't see the target table.
            masker.expect_outputs();
            transform::transform_node(node.select_stmt_mut(), masker);
            // DEFAULT VALUES has no source.
            let source = masker.take_outputs().map_or(Taint::Clean, |o| o.bound());
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

    fn transform_copy_stmt<'mutref>(&mut self, node: nodes::CopyStmtMut<'mem, 'mutref>) {
        self.copy_stmt(node);
    }
}
