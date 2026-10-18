//! Function calls and operators.
//!
//! Built-in functions are allowed, except those that run SQL or read data out of
//! band, and those that store their arguments where they can be read back, when
//! called with values of proxy-masked columns. A user-defined SQL function is
//! analyzed: if its body reads no SQL-masked columns, the call is allowed as is
//! (its result is NULL in results if the body reads proxy-masked columns, or if
//! it's called with their values). A call that passes values of proxy-masked
//! columns to a parameter its body can move where PgDog can't mask it is
//! blocked: the body is analyzed once more with parameters as sources, and
//! once per parameter if one reaches a sink. If the body
//! reads SQL-masked columns, and the function can be inlined, the call is
//! replaced by its body with masks applied:
//!
//! - a scalar call becomes
//!   `(SELECT (<body value>)::<return type> FROM (SELECT <arg>::<type> AS <param>, ...) AS __pgdog_args)`;
//! - a set-returning call in FROM becomes a `LATERAL` subquery with the same columns.
//!
//! Arguments are evaluated once, in the arguments subquery, and parameters are
//! read from it by name. Columns of the body take precedence over parameter
//! names, as in SQL functions. Everything else (procedural languages, `SECURITY
//! DEFINER`, `SET` options, volatile or polymorphic functions) is blocked unless
//! it's in `udf_allowlist` or `extension_allowlist`.
use std::rc::Rc;

use pg_raw_parse::{
    ConstValue, Node, NodeMut,
    make::Unique,
    nodes,
    raw::A_Expr_Kind,
    transform::{self},
};

use super::{
    BodyInfo, Masker, RESOLUTION_CHANGED, Verdict, call_address, expr_address, fields, ident, rules,
};
use crate::analyzer::taint::Taint;
use crate::catalog::{Function, RelationKind, parse_search_path};

/// What to do with a call.
pub(in crate::analyzer) enum CallUse<'mem> {
    Allow,
    /// Replace the call with this node.
    Inline(Unique<'mem, Node<'mem>>),
    Block,
}

/// What's left to check about a call or operator once its arguments are
/// transformed.
#[derive(Debug, Clone)]
pub(in crate::analyzer) struct CallCheck<'c> {
    /// A built-in that stores its arguments where they can be read back.
    side_effect: bool,
    kind: CallKind<'c>,
}

#[derive(Debug, Clone)]
enum CallKind<'c> {
    /// Built-in or allowlisted: the result is computed from the arguments.
    Trusted,
    /// User-defined SQL functions left as calls, one per candidate overload.
    Udf(Vec<&'c Function>),
    /// Inlined or blocked: nothing more to check.
    Done,
}

impl CallCheck<'_> {
    const TRUSTED: Self = Self {
        side_effect: false,
        kind: CallKind::Trusted,
    };
    const DONE: Self = Self {
        side_effect: false,
        kind: CallKind::Done,
    };

    pub(super) fn needs_post_check(&self) -> bool {
        self.side_effect || matches!(self.kind, CallKind::Udf(_))
    }
}

/// What a function name resolves to, for this user.
enum CallTarget<'c> {
    /// Built-in, or allowlisted.
    Trusted,
    /// Its body reads SQL-masked columns: it must be inlined.
    Inline(&'c Function),
    /// User-defined SQL functions left as calls.
    Udf(Vec<&'c Function>),
}

/// A SQL function's body analyzed for where its parameters can go: they
/// carry values of proxy-masked columns.
#[derive(Debug)]
pub(super) struct ParamMode {
    /// Parameter names by position, empty for unnamed ones; positional
    /// references (`$1`) are parameters too.
    names: Vec<String>,
    /// The function's name, which can qualify its parameters.
    function: String,
    /// The parameter followed, by position: `None` follows all of them.
    source: Option<usize>,
    /// A followed parameter can reach a sink.
    pub(super) sinks: bool,
}

impl ParamMode {
    fn new(function: &Function, source: Option<usize>) -> Self {
        Self {
            names: function.argument_names.clone(),
            function: function.name.clone(),
            source,
            sinks: false,
        }
    }

    /// What a parameter carries: values of proxy-masked columns if it's
    /// followed, nothing that matters otherwise.
    fn taint(&self, position: usize) -> Taint {
        if self.source.is_none_or(|source| source == position) {
            Taint::Computed
        } else {
            Taint::Clean
        }
    }

    /// What `$n` carries.
    pub(super) fn positional(&self, number: i32) -> Taint {
        match usize::try_from(number).ok().and_then(|n| n.checked_sub(1)) {
            Some(position) => self.taint(position),
            None => Taint::Unknown,
        }
    }

    /// What a name that resolves to no column carries if it's a parameter:
    /// `param`, `function.param`, or a field of a composite parameter.
    pub(super) fn named(&self, names: &[&str]) -> Option<Taint> {
        let param = |name: &str| {
            self.names
                .iter()
                .position(|param| !param.is_empty() && param == name)
        };
        let position = match names {
            [name, ..] if let Some(position) = param(name) => position,
            [function, name, ..] if *function == self.function => param(name)?,
            _ => return None,
        };
        Some(self.taint(position))
    }
}

/// A call's arguments, once transformed.
#[derive(Debug, Default)]
pub(super) struct CallArgs {
    /// Each argument in call order: its name in named notation, and what it
    /// carries.
    pub(super) args: Vec<(Option<String>, Taint)>,
    /// `VARIADIC` marks the last argument.
    pub(super) variadic: bool,
    /// What the rest of the call carries: aggregate `ORDER BY`, `FILTER`
    /// and `OVER`.
    pub(super) rest: Taint,
}

impl CallArgs {
    /// What the call's inputs carry, together.
    pub(super) fn taint(&self) -> Taint {
        self.args
            .iter()
            .map(|(_, taint)| *taint)
            .fold(self.rest, Taint::join)
    }
}

/// Which parameters of a SQL function can reach a sink in its body, by
/// position.
pub(super) type ParamSinks = Rc<[bool]>;

/// What a function name resolves to.
enum Target<'c> {
    Builtin,
    Allowlisted,
    Functions(Vec<&'c Function>),
    Unknown(String),
}

const ARGS: &str = "__pgdog_args";
const ARG_PREFIX: &str = "__pgdog_arg_";
const BODY: &str = "__pgdog_body";
const BODY_PLACEHOLDER: &str = "__pgdog_body_placeholder";
const SCALAR_PLACEHOLDER: &str = "__pgdog_scalar_placeholder";

/// Functions with more parameters whose body has a sink count it as
/// reachable from every parameter, rather than analyzing the body once per
/// parameter.
const MAX_PARAM_PASSES: usize = 16;

impl<'c, 'mem> Masker<'c, 'mem> {
    /// A function call in an expression.
    pub(super) fn call(&mut self, call: &nodes::FuncCall) -> CallUse<'mem> {
        if self.checked_calls.contains_key(&call_address(call)) {
            return CallUse::Allow;
        }
        let function = match self.call_target(call) {
            Ok(None) => return CallUse::Allow,
            Ok(Some(function)) => function,
            Err(()) => return CallUse::Block,
        };

        let args: Vec<Node<'_>> = call.args().iter().collect();
        let result = plain_call(call).and_then(|()| self.inline_scalar(function, &args));
        match result {
            Ok(inlined) => CallUse::Inline(inlined),
            Err(why) => {
                self.block(format!(
                    "function {}() reads masked columns and can't be inlined: {why}",
                    function.qualified_name()
                ));
                CallUse::Block
            }
        }
    }

    /// A call in a position where it can't be replaced.
    pub(super) fn check_call(&mut self, call: &nodes::FuncCall) -> CallCheck<'c> {
        if let Ok(Some(function)) = self.call_target(call) {
            self.block(format!(
                "function {}() reads masked columns and can't be inlined here",
                function.qualified_name()
            ));
        }
        self.checked_calls
            .get(&call_address(call))
            .cloned()
            .unwrap_or(CallCheck::DONE)
    }

    /// Check a call, and record what's left to check once its arguments are
    /// transformed. `Ok(Some(function))` if it must be inlined.
    fn call_target(&mut self, call: &nodes::FuncCall) -> Result<Option<&'c Function>, ()> {
        let (target, check) = match self.resolve_call(call) {
            Ok((target, side_effect)) => {
                let kind = match &target {
                    CallTarget::Trusted => CallKind::Trusted,
                    CallTarget::Udf(candidates) => CallKind::Udf(candidates.clone()),
                    CallTarget::Inline(_) => CallKind::Done,
                };
                (Ok(target), CallCheck { side_effect, kind })
            }
            Err(()) => (Err(()), CallCheck::DONE),
        };
        self.checked_calls.insert(call_address(call), check);
        target.map(|target| match target {
            CallTarget::Inline(function) => Some(function),
            CallTarget::Trusted | CallTarget::Udf(_) => None,
        })
    }

    /// What a call resolves to, and whether it's a built-in that stores its
    /// arguments.
    fn resolve_call(&mut self, call: &nodes::FuncCall) -> Result<(CallTarget<'c>, bool), ()> {
        let names: Vec<&str> = call.funcname().iter().filter_map(|n| n.as_str()).collect();
        let (schema, name) = match names.as_slice() {
            [name] => (None, *name),
            [.., schema, name] => (Some(*schema), *name),
            [] => return Ok((CallTarget::Trusted, false)),
        };
        if let Some(reason) = rules::denied_function(name) {
            self.block(reason);
            return Err(());
        }
        // By name: Postgres prefers the built-in to a user-defined function
        // with the same signature, as pg_catalog is searched first.
        let builtin_name = matches!(schema, None | Some("pg_catalog"));
        let side_effect = builtin_name && rules::side_effect(name);
        if builtin_name && name == "set_config" {
            self.check_set_config(call)?;
        }
        if schema.is_none()
            && self.path_changed
            && (self.ctx.catalog.has_function_named(name)
                || !self.ctx.catalog.is_system_function(name))
        {
            self.block(RESOLUTION_CHANGED);
            return Err(());
        }

        let target = match self.resolve_function(schema, name, call.args().iter().count()) {
            Target::Builtin | Target::Allowlisted => CallTarget::Trusted,
            Target::Unknown(reason) => {
                self.block(reason);
                return Err(());
            }
            // Function bodies resolve names with the new search_path too,
            // even when the call is qualified.
            Target::Functions(_) if self.path_changed => {
                self.block(RESOLUTION_CHANGED);
                return Err(());
            }
            Target::Functions(functions) => self.functions_target(name, &functions)?,
        };
        Ok((target, side_effect))
    }

    /// After a call's arguments are transformed: built-ins that store their
    /// arguments are sinks, user-defined functions whose body reads
    /// proxy-masked columns return values computed from them, and those
    /// that can move a parameter to a sink can't be passed their values in
    /// that parameter.
    pub(super) fn call_post_check(&mut self, check: &CallCheck<'c>, args: &CallArgs, name: &str) {
        if check.side_effect {
            self.sink(args.taint(), &format!("{name}()"));
        }
        let CallKind::Udf(candidates) = &check.kind else {
            return;
        };
        if candidates
            .iter()
            .any(|function| self.body_info(function, |info| info.reads_proxies))
        {
            self.note(Taint::Computed, false);
            self.state.reads_proxies = true;
        }
        // Its triggers and constraints run on real values.
        if candidates
            .iter()
            .any(|function| self.body_info(function, |info| info.redacts))
        {
            self.state.writes = true;
        }
        if let Some(function) = candidates
            .iter()
            .find(|function| self.folds_proxies(function))
        {
            self.folds_proxies = true;
            if self.explaining {
                let why = if function.volatility == "immutable" {
                    "reads proxy-masked columns and is IMMUTABLE"
                } else {
                    "calls an IMMUTABLE function that reads proxy-masked columns"
                };
                self.block(format!(
                    "function {}() {why}: the planner can compute the result in advance, and EXPLAIN would show it",
                    function.qualified_name()
                ));
            }
        }
        // Planning alone can call an operator's function on values from
        // pg_statistic (RESTRICT = eqsel), so this applies under plain
        // EXPLAIN too.
        if args.taint().is_clean() {
            return;
        }
        let mut reaching = Taint::Clean;
        let mut why = None;
        for function in candidates {
            let (taint, param) = self.reaching_sinks(function, args);
            if !taint.is_clean() {
                reaching = reaching.join(taint);
                why.get_or_insert_with(|| {
                    let name = function.qualified_name();
                    match param {
                        Some(param) => format!(
                            "function {name}() can pass a parameter to a write or a side effect, so its argument for {param} can't carry values of proxy-masked columns"
                        ),
                        None => format!(
                            "function {name}() can pass a parameter to a write or a side effect, and the call's arguments can't be matched to its parameters, so it can't be called with values of proxy-masked columns"
                        ),
                    }
                });
            }
        }
        if let Some(why) = why {
            self.sink_with(reaching, |_| why);
        }
    }

    /// What the arguments passed to parameters of a user-defined SQL
    /// function that can reach a sink carry, and the first such parameter
    /// given a non-Clean argument. When the arguments can't be matched to
    /// the parameters, every argument may reach one.
    fn reaching_sinks(
        &mut self,
        function: &'c Function,
        args: &CallArgs,
    ) -> (Taint, Option<String>) {
        let sinks = self.param_sinks(function);
        if !sinks.contains(&true) {
            return (Taint::Clean, None);
        }
        let Some(positions) = parameter_positions(function, args) else {
            return (args.taint(), None);
        };
        // Aggregate and window syntax is an error for a plain function, but
        // fail closed.
        let mut taint = args.rest;
        let mut param = None;
        for ((_, arg), position) in args.args.iter().zip(positions) {
            if arg.is_clean() || sinks.get(position) == Some(&false) {
                continue;
            }
            taint = taint.join(*arg);
            param.get_or_insert_with(|| match function.argument_names.get(position) {
                Some(name) if !name.is_empty() => name.clone(),
                _ => format!("${}", position + 1),
            });
        }
        (taint, param)
    }

    /// Something about a user-defined function's body, once analyzed.
    fn body_info(&self, function: &Function, f: impl FnOnce(&BodyInfo) -> bool) -> bool {
        self.memo
            .borrow()
            .functions
            .get(&function.oid)
            .is_some_and(f)
    }

    /// Can the planner run a call that reads proxy-masked columns in advance,
    /// when the arguments are constants? An IMMUTABLE function is evaluated
    /// while planning, and a function whose body is inlined exposes the
    /// calls in it.
    fn folds_proxies(&self, function: &Function) -> bool {
        self.body_info(function, |info| {
            info.folds_proxies || (info.reads_proxies && function.volatility == "immutable")
        })
    }

    /// Which parameters of a user-defined SQL function can pass a value
    /// to a sink in its body, by position? Memoized; recursion and bodies
    /// that can't be analyzed count as sinks for every parameter.
    ///
    /// The body is analyzed with every parameter as a source first: most
    /// bodies have no sink. If a parameter reaches one, it's analyzed once
    /// per parameter, each alone as a source.
    fn param_sinks(&mut self, function: &'c Function) -> ParamSinks {
        if let Some(sinks) = self.memo.borrow().param_sinks.get(&function.oid) {
            return sinks.clone();
        }
        let count = function.argument_types.len();
        let all: ParamSinks = vec![true; count].into();
        let active = format!("parameters of function {}", function.oid);
        if self.memo.borrow().active.contains(&active) {
            return all;
        }
        let sinks = match function_body(function) {
            Some(body) if function.language == "sql" => {
                let search_path = self.function_search_path(function);
                self.memo.borrow_mut().active.push(active);
                let reaches = |masker: &Self, source| {
                    masker.body_param_sinks(
                        &body,
                        search_path.clone(),
                        ParamMode::new(function, source),
                    )
                };
                let sinks = if !reaches(self, None) {
                    vec![false; count].into()
                } else if count <= 1 || count > MAX_PARAM_PASSES {
                    all.clone()
                } else {
                    let each: Vec<bool> = (0..count).map(|i| reaches(self, Some(i))).collect();
                    // A sink no parameter reaches alone: fail closed.
                    if each.contains(&true) {
                        each.into()
                    } else {
                        all.clone()
                    }
                };
                self.memo.borrow_mut().active.pop();
                sinks
            }
            _ => all,
        };
        self.memo
            .borrow_mut()
            .param_sinks
            .insert(function.oid, sinks.clone());
        sinks
    }

    /// The search_path a function's body resolves names with: its own SET
    /// option, or the caller's.
    fn function_search_path(&self, function: &Function) -> Vec<String> {
        function
            .search_path()
            .map(|path| parse_search_path(path, ""))
            .unwrap_or_else(|| self.ctx.search_path.clone())
    }

    /// `set_config` changes settings out of PgDog's sight: PgDog doesn't
    /// always follow a `search_path` it sets (not at all while its query
    /// parser is off), so names would resolve differently here and in
    /// Postgres. A role change alters `$user` for later statements.
    fn check_set_config(&mut self, call: &nodes::FuncCall) -> Result<(), ()> {
        let setting = match call.args().iter().next() {
            Some(Node::A_Const(constant)) => match constant.val() {
                Some(ConstValue::String(setting)) => Some(setting),
                _ => None,
            },
            _ => None,
        };
        match setting {
            Some(setting) if !setting.eq_ignore_ascii_case("search_path") => {
                self.state.changes_resolution |= rules::changes_resolution_setting(setting);
                Ok(())
            }
            _ => {
                self.block("set_config() can't change search_path for masked users: PgDog may not follow the change; use SET search_path");
                Err(())
            }
        }
    }

    /// Resolve a function name the way Postgres would, without argument types:
    /// every user-defined function the call could resolve to is a candidate.
    fn resolve_function(&self, schema: Option<&str>, name: &str, count: usize) -> Target<'c> {
        let catalog = self.ctx.catalog;
        let general = &self.ctx.policies.config.general;
        let candidates: Vec<&'c Function> = match schema {
            Some("pg_catalog") => vec![],
            schema => catalog.functions(schema, name),
        }
        .into_iter()
        .filter(|function| function.accepts(count))
        .collect();

        // Postgres may resolve an unqualified call with another search_path
        // than the session's, which PgDog doesn't always follow: once one
        // is on the session's, namesakes in other schemas are candidates too.
        if candidates
            .iter()
            .any(|function| schema.is_some() || self.ctx.search_path.contains(&function.schema))
        {
            return Target::Functions(candidates);
        }
        if rules::allowlisted(schema, name, &general.udf_allowlist) {
            return Target::Allowlisted;
        }
        if matches!(schema, None | Some("pg_catalog")) && catalog.is_system_function(name) {
            return Target::Builtin;
        }
        let qualified = match schema {
            Some(schema) => format!("{schema}.{name}"),
            None => name.to_owned(),
        };
        if !catalog.full {
            return Target::Unknown(format!(
                "the catalog has no functions, so {qualified}() can't be checked"
            ));
        }
        Target::Unknown(format!(
            "function {qualified}() is not a built-in function and isn't in the catalog or udf_allowlist"
        ))
    }

    /// Combine the verdicts of every candidate: any block blocks, and a function
    /// can only be inlined if it's the only candidate. Candidates that are all
    /// allowlisted are trusted.
    fn functions_target(
        &mut self,
        name: &str,
        functions: &[&'c Function],
    ) -> Result<CallTarget<'c>, ()> {
        let mut inline = vec![];
        let mut udfs = vec![];
        for function in functions {
            if self.function_allowlisted(function) {
                continue;
            }
            match self.function_verdict(function) {
                Verdict::Safe => udfs.push(*function),
                Verdict::Inline => inline.push(*function),
                Verdict::Blocked(reason) => {
                    self.block(reason);
                    return Err(());
                }
            }
        }
        match inline.as_slice() {
            [] if udfs.is_empty() => Ok(CallTarget::Trusted),
            [] => Ok(CallTarget::Udf(udfs)),
            [function] if functions.len() == 1 => Ok(CallTarget::Inline(function)),
            _ => {
                self.block(format!(
                    "function {name}() has several overloads, or namesakes in other schemas, and one reads masked columns, so it can't be inlined"
                ));
                Err(())
            }
        }
    }

    /// Is a function trusted by the configuration?
    fn function_allowlisted(&self, function: &Function) -> bool {
        let general = &self.ctx.policies.config.general;
        rules::allowlisted(
            Some(&function.schema),
            &function.name,
            &general.udf_allowlist,
        ) || function
            .extension
            .as_ref()
            .is_some_and(|extension| general.extension_allowlist.contains(extension))
    }

    /// What calling a user-defined function means for this user.
    fn function_verdict(&mut self, function: &Function) -> Verdict {
        if let Some(info) = self.memo.borrow().functions.get(&function.oid).cloned() {
            self.touched |= info.touched;
            return info.verdict;
        }

        let label = function.qualified_name();
        let active = format!("function {}", function.oid);

        let info = if self.function_allowlisted(function) {
            BodyInfo::TRUSTED
        } else if self.memo.borrow().active.contains(&active) {
            BodyInfo::blocked(format!("function {label}() is recursive"))
        } else if function.kind != "function" {
            BodyInfo::blocked(format!(
                "{} {label}() is not allowed for masked users; add it to udf_allowlist if it's safe",
                function.kind
            ))
        } else if function.language != "sql" {
            BodyInfo::blocked(format!(
                "function {label}() is written in {} and can't be analyzed; add it to udf_allowlist if it's safe",
                function.language
            ))
        } else if let Some(body) = function_body(function) {
            let search_path = self.function_search_path(function);
            self.memo.borrow_mut().active.push(active);
            let mut info = self.analyze_body(&body, search_path, |stmt| inlinable(function, stmt));
            self.memo.borrow_mut().active.pop();
            if let Verdict::Blocked(reason) = &info.verdict {
                info.verdict = Verdict::Blocked(format!("function {label}(): {reason}"));
            }
            info
        } else {
            BodyInfo::blocked(format!("function {label}() has an unreadable body"))
        };

        self.memo
            .borrow_mut()
            .functions
            .insert(function.oid, info.clone());
        self.touched |= info.touched;
        info.verdict
    }

    /// Column names of a function in FROM, when they're known: the column
    /// definition list, or the catalog's, renamed by the alias's column list.
    pub(super) fn range_function_names(
        &self,
        range_function: &nodes::RangeFunction,
        refname: &str,
    ) -> Vec<String> {
        let mut names: Vec<String> = range_function
            .coldeflist()
            .iter()
            .filter_map(|column| column.colname().map(str::to_owned))
            .collect();
        if names.is_empty() {
            names = self
                .catalog_output_names(range_function, refname)
                .unwrap_or_default();
        }
        let aliases = range_function
            .alias()
            .map(|alias| super::names(alias.colnames()))
            .unwrap_or_default();
        for (i, alias) in aliases.into_iter().enumerate() {
            match names.get_mut(i) {
                Some(name) => *name = alias,
                None => names.push(alias),
            }
        }
        names
    }

    /// Output column names of a single user-defined function in FROM, if every
    /// overload it could resolve to agrees on them.
    fn catalog_output_names(
        &self,
        range_function: &nodes::RangeFunction,
        refname: &str,
    ) -> Option<Vec<String>> {
        let mut calls = range_function
            .functions()
            .iter()
            .filter_map(|pair| pair.as_node_list().and_then(|list| list.iter().next()));
        let (Some(Node::FuncCall(call)), None) = (calls.next(), calls.next()) else {
            return None;
        };
        let names: Vec<&str> = call.funcname().iter().filter_map(|n| n.as_str()).collect();
        let (schema, name) = match names.as_slice() {
            [name] => (None, *name),
            [.., "pg_catalog", _] => return None,
            [.., schema, name] => (Some(*schema), *name),
            [] => return None,
        };
        let count = call.args().iter().count();
        let mut outputs = self
            .ctx
            .catalog
            .functions(schema, name)
            .into_iter()
            .filter(|function| function.accepts(count))
            .map(|function| {
                self.function_outputs(function, refname)
                    .ok()
                    .map(|(names, _)| names)
            });
        let first = outputs.next()??;
        outputs
            .all(|names| names.as_ref() == Some(&first))
            .then_some(first)
    }

    /// A function call in FROM. `None` if it can stay as it is.
    pub(super) fn range_function(
        &mut self,
        range_function: &nodes::RangeFunction,
    ) -> Option<CallUse<'mem>> {
        let calls: Vec<&nodes::FuncCall> = range_function
            .functions()
            .iter()
            .filter_map(|pair| pair.as_node_list().and_then(|list| list.iter().next()))
            .filter_map(|call| match call {
                Node::FuncCall(call) => Some(call),
                _ => None,
            })
            .collect();

        let mut inline = vec![];
        for call in &calls {
            match self.call_target(call) {
                Ok(None) => (),
                Ok(Some(function)) => inline.push((*call, function)),
                Err(()) => return Some(CallUse::Block),
            }
        }

        let [(call, function)] = inline.as_slice() else {
            if inline.is_empty() {
                return None;
            }
            self.block("functions that read masked columns can't be inlined in ROWS FROM");
            return Some(CallUse::Block);
        };

        let result = if calls.len() != 1
            || range_function.ordinality
            || range_function.is_rowsfrom
            || !range_function.coldeflist().is_empty()
        {
            Err("it's called with ROWS FROM, WITH ORDINALITY or a column definition list".into())
        } else {
            plain_call(call).and_then(|()| self.inline_from(function, call, range_function))
        };

        Some(match result {
            Ok(inlined) => CallUse::Inline(inlined),
            Err(why) => {
                self.block(format!(
                    "function {}() reads masked columns and can't be inlined: {why}",
                    function.qualified_name()
                ));
                CallUse::Block
            }
        })
    }

    /// An operator expression. Operators defined outside `pg_catalog` are calls to
    /// their functions.
    pub(super) fn operator(&mut self, expr: &nodes::A_Expr) -> CallUse<'mem> {
        let (use_, check) = self.operator_use(expr);
        self.checked_calls.insert(expr_address(expr), check);
        use_
    }

    /// An operator in a position where it can't be replaced.
    pub(super) fn check_operator(&mut self, expr: &nodes::A_Expr) -> CallCheck<'c> {
        if let CallUse::Inline(_) = self.operator(expr) {
            self.block("an operator that reads masked columns can't be inlined here");
        }
        self.checked_calls
            .get(&expr_address(expr))
            .cloned()
            .unwrap_or(CallCheck::DONE)
    }

    /// What to do with an operator, and what's left to check once its operands
    /// are transformed.
    fn operator_use(&mut self, expr: &nodes::A_Expr) -> (CallUse<'mem>, CallCheck<'c>) {
        let Some((schema, name)) = operator_name(expr) else {
            return (CallUse::Allow, CallCheck::TRUSTED);
        };
        let catalog = self.ctx.catalog;
        if self.path_changed && catalog.has_operator_named(name) {
            self.block(RESOLUTION_CHANGED);
            return (CallUse::Block, CallCheck::DONE);
        }
        let operators = catalog.operators(schema, name, &self.ctx.search_path);
        if operators.is_empty() {
            return (CallUse::Allow, CallCheck::TRUSTED);
        }

        let mut functions: Vec<&'c Function> = vec![];
        for operator in &operators {
            match catalog.function(operator.function_oid) {
                Some(function) if !functions.iter().any(|f| f.oid == function.oid) => {
                    functions.push(function)
                }
                Some(_) => (),
                None => {
                    self.block(format!(
                        "operator {}.{} uses function {}.{}(), which isn't in the catalog",
                        operator.schema,
                        operator.name,
                        operator.function_schema,
                        operator.function_name
                    ));
                    return (CallUse::Block, CallCheck::DONE);
                }
            }
        }

        let function = match self.functions_target(name, &functions) {
            Ok(CallTarget::Trusted) => return (CallUse::Allow, CallCheck::TRUSTED),
            Ok(CallTarget::Udf(candidates)) => {
                return (
                    CallUse::Allow,
                    CallCheck {
                        side_effect: false,
                        kind: CallKind::Udf(candidates),
                    },
                );
            }
            Ok(CallTarget::Inline(function)) => function,
            Err(()) => return (CallUse::Block, CallCheck::DONE),
        };
        if operators.len() != 1 || expr.kind != A_Expr_Kind::AEXPR_OP {
            self.block(format!(
                "operator {name} reads masked columns and can't be inlined"
            ));
            return (CallUse::Block, CallCheck::DONE);
        }

        let args: Vec<Node<'_>> = [expr.lexpr(), expr.rexpr()]
            .into_iter()
            .filter(|node| !matches!(node, Node::None))
            .collect();
        match self.inline_scalar(function, &args) {
            Ok(inlined) => (CallUse::Inline(inlined), CallCheck::DONE),
            Err(why) => {
                self.block(format!(
                    "operator {name} reads masked columns and can't be inlined: {why}"
                ));
                (CallUse::Block, CallCheck::DONE)
            }
        }
    }

    /// Is this an operator defined outside `pg_catalog`?
    pub(super) fn is_user_operator(&self, expr: &nodes::A_Expr) -> bool {
        operator_name(expr).is_some_and(|(schema, name)| {
            !self
                .ctx
                .catalog
                .operators(schema, name, &self.ctx.search_path)
                .is_empty()
        })
    }

    /// A scalar call replaced by its masked body.
    fn inline_scalar(
        &mut self,
        function: &Function,
        args: &[Node<'_>],
    ) -> Result<Unique<'mem, Node<'mem>>, String> {
        if args.len() != function.argument_types.len() {
            return Err("the call relies on argument defaults".into());
        }
        if function.returns_set {
            return Err("it returns a set, and is only inlined in FROM".into());
        }
        if !function.output_names.is_empty()
            || matches!(
                function.return_type.as_str(),
                "record" | "void" | "trigger" | "event_trigger"
            )
        {
            return Err("it doesn't return a single value".into());
        }

        let params = param_names(function);
        let body = self.function_select(function, &params, 1)?;
        let mut value = format!(
            "(SELECT {BODY}.__pgdog_out FROM (SELECT {BODY_PLACEHOLDER}) AS {BODY}(__pgdog_out) LIMIT 1)"
        );
        if function.strict && !params.is_empty() {
            value = format!(
                "CASE WHEN {} THEN NULL ELSE {value} END",
                params
                    .iter()
                    .map(|param| format!("{ARGS}.{} IS NULL", ident(param)))
                    .collect::<Vec<_>>()
                    .join(" OR ")
            );
        }
        let sql = if params.is_empty() {
            format!("({value})::{}", function.return_type)
        } else {
            format!(
                "(SELECT ({value})::{} FROM ({}) AS {ARGS})",
                function.return_type,
                args_select(function, &params)
            )
        };

        let mut inlined = self
            .parse_expr(&sql)
            .ok_or_else(|| "its call couldn't be built".to_owned())?;
        self.substitute(&mut inlined, args, body)?;
        Ok(inlined)
    }

    /// A set-returning call in FROM replaced by a LATERAL subquery over its masked body.
    fn inline_from(
        &mut self,
        function: &Function,
        call: &nodes::FuncCall,
        range_function: &nodes::RangeFunction,
    ) -> Result<Unique<'mem, Node<'mem>>, String> {
        let args: Vec<Node<'_>> = call.args().iter().collect();
        if args.len() != function.argument_types.len() {
            return Err("the call relies on argument defaults".into());
        }

        let alias = range_function.alias();
        let refname = alias
            .and_then(|a| a.aliasname())
            .unwrap_or(&function.name)
            .to_owned();
        let aliases = alias
            .map(|a| super::names(a.colnames()))
            .unwrap_or_default();

        // A scalar function in FROM is one row, even if its body returns none.
        if !function.returns_set && function.output_names.is_empty() {
            let column = ident(aliases.first().unwrap_or(&refname));
            let sql = format!(
                "SELECT * FROM LATERAL (SELECT {SCALAR_PLACEHOLDER} AS {column}) AS {}({column})",
                ident(&refname)
            );
            let value = self.inline_scalar(function, &args)?;
            let mut inlined = self
                .parse_from_item(&sql)
                .ok_or_else(|| "its call couldn't be built".to_owned())?;
            let mut value = Some(value);
            transform::transform(&mut inlined, |node| {
                let replacement = match &*node {
                    NodeMut::ColumnRef(column) if fields(column).0 == [SCALAR_PLACEHOLDER] => {
                        value.take()
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
            return Ok(inlined);
        }

        let (outputs, types) = self.function_outputs(function, &refname)?;
        let columns: Vec<String> = outputs
            .iter()
            .enumerate()
            .map(|(i, name)| ident(aliases.get(i).unwrap_or(name)))
            .collect();

        let params = param_names(function);
        let body = self.function_select(function, &params, outputs.len())?;
        let out: Vec<String> = (1..=outputs.len())
            .map(|i| format!("__pgdog_c{i}"))
            .collect();
        let casts: Vec<String> = out
            .iter()
            .zip(&types)
            .zip(&outputs)
            .map(|((out, data_type), name)| {
                format!("({BODY}.{out})::{data_type} AS {}", ident(name))
            })
            .collect();
        let from_args = if params.is_empty() {
            String::new()
        } else {
            format!("({}) AS {ARGS}, ", args_select(function, &params))
        };
        let filter = if function.strict && !params.is_empty() {
            format!(
                " WHERE {}",
                params
                    .iter()
                    .map(|param| format!("{ARGS}.{} IS NOT NULL", ident(param)))
                    .collect::<Vec<_>>()
                    .join(" AND ")
            )
        } else {
            String::new()
        };
        // Functions with OUT parameters return one row.
        let limit = if function.returns_set { "" } else { " LIMIT 1" };
        let sql = format!(
            "SELECT * FROM LATERAL (SELECT {} FROM {from_args}LATERAL (SELECT {BODY_PLACEHOLDER}) AS {BODY}({}){filter}{limit}) AS {}({})",
            casts.join(", "),
            out.join(", "),
            ident(&refname),
            columns.join(", ")
        );

        let mut inlined = self
            .parse_from_item(&sql)
            .ok_or_else(|| "its call couldn't be built".to_owned())?;
        self.substitute(&mut inlined, &args, body)?;
        Ok(inlined)
    }

    /// Output column names and types of a function used in FROM.
    fn function_outputs(
        &self,
        function: &Function,
        refname: &str,
    ) -> Result<(Vec<String>, Vec<String>), String> {
        if !function.output_names.is_empty() {
            let names = function
                .output_names
                .iter()
                .enumerate()
                .map(|(i, name)| {
                    if name.is_empty() {
                        format!("column{}", i + 1)
                    } else {
                        name.clone()
                    }
                })
                .collect();
            return Ok((names, function.output_types.clone()));
        }

        // SETOF <table>: the table's columns.
        if let Some((schema, name)) = function.return_type.split_once('.')
            && let Some(relation) = self
                .ctx
                .catalog
                .get(schema.trim_matches('"'), name.trim_matches('"'))
            && relation.kind != RelationKind::Other
        {
            let types = relation
                .columns
                .iter()
                .map(|column| {
                    if column.type_name.is_empty() {
                        column.data_type.clone()
                    } else {
                        column.type_name.clone()
                    }
                })
                .collect();
            let names = relation.columns.iter().map(|c| c.name.clone()).collect();
            return Ok((names, types));
        }

        if function.return_type == "record" {
            return Err("it returns record".into());
        }
        Ok((vec![refname.to_owned()], vec![function.return_type.clone()]))
    }

    /// The function's `SELECT` body, with parameters replaced by columns of
    /// the arguments subquery. It must return `columns` columns.
    fn function_select(
        &self,
        function: &Function,
        params: &[String],
        columns: usize,
    ) -> Result<Unique<'mem, Node<'mem>>, String> {
        let body = function_body(function).ok_or("its body is unreadable")?;
        let parsed = self
            .mem
            .parse(&body)
            .map_err(|err| format!("its body doesn't parse: {err}"))?;
        let stmt = parsed.as_ref().iter().next().ok_or("its body is empty")?;
        let Node::SelectStmt(select) = stmt.stmt() else {
            return Err("its body isn't a SELECT".into());
        };
        let mut first = select;
        while let Some(larg) = first.larg() {
            first = larg;
        }
        let targets: Vec<_> = first.target_list().iter().collect();
        if targets
            .iter()
            .any(|target| matches!(target.val(), Node::ColumnRef(column) if fields(column).1))
        {
            return Err("its body selects *".into());
        }
        if targets.len() != columns {
            return Err(format!(
                "its body returns {} columns instead of {columns}",
                targets.len()
            ));
        }

        let mut node = self.mem.make_unique(stmt.stmt());
        let mem = self.mem;
        let name = function.name.as_str();
        transform::transform(&mut node, |node| {
            let replacement = match &*node {
                NodeMut::ParamRef(param) => usize::try_from(param.number)
                    .ok()
                    .and_then(|number| params.get(number.checked_sub(1)?))
                    .map(|param| column_ref(mem, &[ARGS, param])),
                NodeMut::ColumnRef(column) => match fields(column) {
                    (fields, false) => match fields.as_slice() {
                        [qualifier, param]
                            if *qualifier == name && params.iter().any(|p| p == param) =>
                        {
                            Some(column_ref(mem, &[ARGS, param]))
                        }
                        _ => None,
                    },
                    _ => None,
                },
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
        Ok(node)
    }

    /// Put the call's arguments and the function body into an inlining template.
    fn substitute(
        &self,
        template: &mut Unique<'mem, Node<'mem>>,
        args: &[Node<'_>],
        body: Unique<'mem, Node<'mem>>,
    ) -> Result<(), String> {
        let mem = self.mem;
        let mut body = Some(body);
        transform::transform(template, |node| {
            let replacement = match &*node {
                NodeMut::ColumnRef(column) => match fields(column).0.as_slice() {
                    [name] => name
                        .strip_prefix(ARG_PREFIX)
                        .and_then(|index| index.parse::<usize>().ok())
                        .and_then(|index| args.get(index.checked_sub(1)?))
                        .map(|arg| mem.make_unique(*arg)),
                    _ => None,
                },
                NodeMut::SelectStmt(select) if is_body_placeholder(select) => body.take(),
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
        match body {
            None => Ok(()),
            Some(_) => Err("its call couldn't be built".into()),
        }
    }
}

/// Inlining is only done for plain calls: no aggregate or window syntax,
/// `VARIADIC` or named arguments.
fn plain_call(call: &nodes::FuncCall) -> Result<(), String> {
    let named = call
        .args()
        .iter()
        .any(|arg| matches!(arg, Node::NamedArgExpr(_)));
    if call.agg_star
        || call.agg_distinct
        || call.func_variadic
        || call.over().is_some()
        || !call.agg_order().is_empty()
        || !matches!(call.agg_filter(), Node::None)
        || named
    {
        return Err(
            "it's called with aggregate or window syntax, VARIADIC or named arguments".into(),
        );
    }
    Ok(())
}

/// The parameter each argument of a call is passed to, by position, the
/// way Postgres matches them: positional arguments in order, the extra ones
/// of a `VARIADIC` function to its last parameter, and named arguments by
/// name. Parameters left out take their defaults. `None` if the arguments
/// don't match the function's parameters.
fn parameter_positions(function: &Function, args: &CallArgs) -> Option<Vec<usize>> {
    let count = function.argument_types.len();
    args.args
        .iter()
        .enumerate()
        .map(|(i, (name, _))| match name {
            Some(name) => function
                .argument_names
                .iter()
                .position(|param| !param.is_empty() && param == name),
            None if i < count => Some(i),
            None if function.variadic && !args.variadic => count.checked_sub(1),
            None => None,
        })
        .collect()
}

/// Can a function that reads masked columns be inlined? Mirrors the conditions
/// under which Postgres inlines SQL functions.
fn inlinable(function: &Function, stmt: &nodes::RawStmt) -> Result<(), String> {
    let polymorphic = function
        .argument_types
        .iter()
        .chain([&function.return_type])
        .any(|t| t.starts_with("any") || t == "record");
    if function.security_definer {
        Err("it's SECURITY DEFINER".into())
    } else if !function.config.is_empty() {
        Err("it has SET options".into())
    } else if function.variadic {
        Err("it's VARIADIC".into())
    } else if polymorphic && function.output_names.is_empty() {
        Err("it's polymorphic".into())
    } else if !matches!(function.volatility.as_str(), "immutable" | "stable") {
        Err("it's VOLATILE".into())
    } else {
        match stmt.stmt() {
            Node::SelectStmt(select) if select.into_clause().is_none() => Ok(()),
            _ => Err("its body isn't a single SELECT".into()),
        }
    }
}

/// SQL text of a function body.
fn function_body(function: &Function) -> Option<String> {
    let Some(body) = function.sql_body.as_deref() else {
        return Some(function.source.clone());
    };
    // pg_get_function_sqlbody: `RETURN <expr>` or `BEGIN ATOMIC <stmts>; END`.
    let body = body.trim();
    let upper = body.to_ascii_uppercase();
    if upper.starts_with("RETURN") {
        Some(format!("SELECT {}", &body["RETURN".len()..]))
    } else if upper.starts_with("BEGIN ATOMIC") && upper.ends_with("END") {
        Some(body["BEGIN ATOMIC".len()..body.len() - "END".len()].to_owned())
    } else {
        None
    }
}

/// Names of the columns parameters are read from.
fn param_names(function: &Function) -> Vec<String> {
    (0..function.argument_types.len())
        .map(|i| match function.argument_names.get(i) {
            Some(name) if !name.is_empty() => name.clone(),
            _ => format!("__pgdog_p{}", i + 1),
        })
        .collect()
}

/// `SELECT (__pgdog_arg_1)::<type> AS <param>, ...`
fn args_select(function: &Function, params: &[String]) -> String {
    let columns: Vec<String> = params
        .iter()
        .zip(&function.argument_types)
        .enumerate()
        .map(|(i, (param, data_type))| {
            format!("({ARG_PREFIX}{})::{data_type} AS {}", i + 1, ident(param))
        })
        .collect();
    format!("SELECT {}", columns.join(", "))
}

fn is_body_placeholder(select: &nodes::SelectStmt) -> bool {
    let targets: Vec<_> = select.target_list().iter().collect();
    matches!(targets.as_slice(), [target] if matches!(
        target.val(),
        Node::ColumnRef(column) if fields(column).0 == [BODY_PLACEHOLDER]
    ))
}

/// Operator name of an operator expression.
fn operator_name(expr: &nodes::A_Expr) -> Option<(Option<&str>, &str)> {
    if !matches!(
        expr.kind,
        A_Expr_Kind::AEXPR_OP | A_Expr_Kind::AEXPR_OP_ANY | A_Expr_Kind::AEXPR_OP_ALL
    ) {
        return None;
    }
    let names: Vec<&str> = expr.name().iter().filter_map(|n| n.as_str()).collect();
    match names.as_slice() {
        [name] => Some((None, *name)),
        [.., schema, name] => Some((Some(*schema), *name)),
        [] => None,
    }
}

fn column_ref<'mem>(
    mem: pg_raw_parse::make::MemoryToken<'mem>,
    names: &[&str],
) -> Unique<'mem, Node<'mem>> {
    let fields: Vec<_> = names
        .iter()
        .map(|name| mem.make_string(Some(name)).uncast())
        .collect();
    mem.make_column_ref(mem.make_list(&fields)).uncast()
}
