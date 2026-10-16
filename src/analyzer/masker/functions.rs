//! Function calls and operators.
//!
//! Built-in functions are allowed, except those that run SQL or read data out of
//! band. A user-defined SQL function is analyzed: if its body reads no masked
//! columns, the call is allowed as is. If it does, and the function can be
//! inlined, the call is replaced by its body with masks applied:
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
use pg_raw_parse::{
    Node, NodeMut,
    make::Unique,
    nodes,
    raw::A_Expr_Kind,
    transform::{self},
};

use super::{Masker, Verdict, call_address, fields, ident, rules};
use crate::catalog::{Function, RelationKind, parse_search_path};

/// What to do with a call.
pub(in crate::analyzer) enum CallUse<'mem> {
    Allow,
    /// Replace the call with this node.
    Inline(Unique<'mem, Node<'mem>>),
    Block,
}

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

impl<'c, 'mem> Masker<'c, 'mem> {
    /// A function call in an expression.
    pub(super) fn call(&mut self, call: &nodes::FuncCall) -> CallUse<'mem> {
        if self.checked_calls.contains(&call_address(call)) {
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
    pub(super) fn check_call(&mut self, call: &nodes::FuncCall) {
        if let Ok(Some(function)) = self.call_target(call) {
            self.block(format!(
                "function {}() reads masked columns and can't be inlined here",
                function.qualified_name()
            ));
        }
    }

    /// Check a call. `Ok(Some(function))` if it must be inlined.
    fn call_target(&mut self, call: &nodes::FuncCall) -> Result<Option<&'c Function>, ()> {
        self.checked_calls.insert(call_address(call));
        let names: Vec<&str> = call.funcname().iter().filter_map(|n| n.as_str()).collect();
        let (schema, name) = match names.as_slice() {
            [name] => (None, *name),
            [.., schema, name] => (Some(*schema), *name),
            [] => return Ok(None),
        };
        if let Some(reason) = rules::denied_function(name) {
            self.block(reason);
            return Err(());
        }

        match self.resolve_function(schema, name, call.args().iter().count()) {
            Target::Builtin | Target::Allowlisted => Ok(None),
            Target::Unknown(reason) => {
                self.block(reason);
                Err(())
            }
            Target::Functions(functions) => self.functions_target(name, &functions),
        }
    }

    /// Resolve a function name the way Postgres would, without argument types:
    /// every user-defined function the call could resolve to is a candidate.
    fn resolve_function(&self, schema: Option<&str>, name: &str, count: usize) -> Target<'c> {
        let catalog = self.ctx.catalog;
        let general = &self.ctx.policies.config.general;
        let candidates: Vec<&'c Function> = match schema {
            Some("pg_catalog") => vec![],
            Some(_) => catalog.functions(schema, name, &[]),
            None => catalog.functions(None, name, &self.ctx.search_path),
        }
        .into_iter()
        .filter(|function| function.accepts(count))
        .collect();

        if !candidates.is_empty() {
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
                "the schema snapshot has no functions, so {qualified}() can't be checked"
            ));
        }
        Target::Unknown(format!(
            "function {qualified}() is not a built-in function and isn't in the schema snapshot or udf_allowlist"
        ))
    }

    /// Combine the verdicts of every candidate: any block blocks, and a function
    /// can only be inlined if it's the only candidate.
    fn functions_target(
        &mut self,
        name: &str,
        functions: &[&'c Function],
    ) -> Result<Option<&'c Function>, ()> {
        let mut inline = vec![];
        for function in functions {
            match self.function_verdict(function) {
                Verdict::Safe => (),
                Verdict::Inline => inline.push(*function),
                Verdict::Blocked(reason) => {
                    self.block(reason);
                    return Err(());
                }
            }
        }
        match inline.as_slice() {
            [] => Ok(None),
            [function] if functions.len() == 1 => Ok(Some(*function)),
            _ => {
                self.block(format!(
                    "function {name}() has several overloads and one reads masked columns, so it can't be inlined"
                ));
                Err(())
            }
        }
    }

    /// What calling a user-defined function means for this user.
    fn function_verdict(&mut self, function: &Function) -> Verdict {
        if let Some((verdict, touched)) = self.memo.borrow().functions.get(&function.oid).cloned() {
            self.touched |= touched;
            return verdict;
        }

        let general = &self.ctx.policies.config.general;
        let label = function.qualified_name();
        let active = format!("function {}", function.oid);
        let allowlisted = rules::allowlisted(
            Some(&function.schema),
            &function.name,
            &general.udf_allowlist,
        ) || function
            .extension
            .as_ref()
            .is_some_and(|extension| general.extension_allowlist.contains(extension));

        let (verdict, touched) = if allowlisted {
            (Verdict::Safe, false)
        } else if self.memo.borrow().active.contains(&active) {
            (
                Verdict::Blocked(format!("function {label}() is recursive")),
                false,
            )
        } else if function.kind != "function" {
            (
                Verdict::Blocked(format!(
                    "{} {label}() is not allowed for masked users; add it to udf_allowlist if it's safe",
                    function.kind
                )),
                false,
            )
        } else if function.language != "sql" {
            (
                Verdict::Blocked(format!(
                    "function {label}() is written in {} and can't be analyzed; add it to udf_allowlist if it's safe",
                    function.language
                )),
                false,
            )
        } else if let Some(body) = function_body(function) {
            let search_path = function
                .search_path()
                .map(|path| parse_search_path(path, ""))
                .unwrap_or_else(|| self.ctx.search_path.clone());
            self.memo.borrow_mut().active.push(active);
            let (verdict, touched) =
                self.analyze_body(&body, search_path, |stmt| inlinable(function, stmt));
            self.memo.borrow_mut().active.pop();
            let verdict = match verdict {
                Verdict::Blocked(reason) => {
                    Verdict::Blocked(format!("function {label}(): {reason}"))
                }
                verdict => verdict,
            };
            (verdict, touched)
        } else {
            (
                Verdict::Blocked(format!("function {label}() has an unreadable body")),
                false,
            )
        };

        self.memo
            .borrow_mut()
            .functions
            .insert(function.oid, (verdict.clone(), touched));
        self.touched |= touched;
        verdict
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
        let Some((schema, name)) = operator_name(expr) else {
            return CallUse::Allow;
        };
        let catalog = self.ctx.catalog;
        let operators = catalog.operators(schema, name, &self.ctx.search_path);
        if operators.is_empty() {
            return CallUse::Allow;
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
                        "operator {}.{} uses function {}.{}(), which isn't in the schema snapshot",
                        operator.schema,
                        operator.name,
                        operator.function_schema,
                        operator.function_name
                    ));
                    return CallUse::Block;
                }
            }
        }

        let function = match self.functions_target(name, &functions) {
            Ok(None) => return CallUse::Allow,
            Ok(Some(function)) => function,
            Err(()) => return CallUse::Block,
        };
        if operators.len() != 1 || expr.kind != A_Expr_Kind::AEXPR_OP {
            self.block(format!(
                "operator {name} reads masked columns and can't be inlined"
            ));
            return CallUse::Block;
        }

        let args: Vec<Node<'_>> = [expr.lexpr(), expr.rexpr()]
            .into_iter()
            .filter(|node| !matches!(node, Node::None))
            .collect();
        match self.inline_scalar(function, &args) {
            Ok(inlined) => CallUse::Inline(inlined),
            Err(why) => {
                self.block(format!(
                    "operator {name} reads masked columns and can't be inlined: {why}"
                ));
                CallUse::Block
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
