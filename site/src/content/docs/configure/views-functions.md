---
title: Views and functions
description: How views and SQL functions over masked columns are masked, and how to allow code the plugin can't analyze.
---

Views and functions could otherwise read masked columns on a masked user's behalf. The plugin analyzes them using the definitions in the catalog PgDog loads.

## Views

A view whose definition reads masked columns, with SQL or proxy masks, is **inlined**: `FROM user_ssns` becomes `FROM (<its definition>) AS user_ssns`, masked like any subquery. Nested views are inlined recursively. Inlining doesn't change the plan, because Postgres expands views into subqueries the same way. A proxy-masked column the view passes through keeps its proxy mask, and columns the view computes from it return `NULL`.

Some views are queried **like tables** instead:

- views with `security_barrier` or `security_invoker`;
- materialized views;
- views with masked columns of their own (assigned in `[[masked_columns]]` or by tags);
- every view, with `inline_views = false`.

Columns of a table-like view that pass a masked column through unchanged get its mask, SQL or proxy. Columns computed from masked columns are blocked, unless you assign them a policy. When every masked column one is computed from has a proxy mask for the user, it returns `NULL` instead, and conditions on it use real values.

Writes through views that read masked columns are blocked, and views without a definition in the catalog are blocked. For users with proxy masks, every write has its [errors redacted](../errors/#per-statement-redaction), through a view or not: the triggers and constraints of the tables it writes run on real values.

`view_allowlist` lists views masked users may query without analysis. Listing one attests that it doesn't return masked data.

## SQL functions

SQL-language functions are analyzed:

- A function that reads no masked columns is called as is.
- One that reads SQL-masked columns is **inlined** with masks applied, if both the function and the call allow it (below). Otherwise the statement is blocked.
- One that reads only proxy-masked columns is called as is, never inlined, since inlining could change the plan. Its result is `NULL`, and the statement's [errors are redacted](../errors/#per-statement-redaction). `SECURITY DEFINER` and `SET` options don't matter for these. Volatility matters only under `EXPLAIN`: `EXPLAIN [ANALYZE]` of a call to one that is `IMMUTABLE`, or to a function that calls one, is blocked, because the planner can compute the result in advance and the plan would show it. Declare such functions `STABLE`.
- One whose body writes, such as an `UPDATE`, makes the statement's errors redacted for users with proxy masks, as the write itself would.
- A call that passes proxy-masked values as arguments, such as `last4(ssn)`, returns `NULL`. The plugin also checks the function's body for each parameter: a call is blocked if it passes proxy-masked values to a parameter that could reach a write or a side effect, such as an `INSERT` or `pg_notify`, directly or through another function. A parameter used only in conditions, such as the `WHERE` of the `INSERT`, can take them. A function call's arguments are matched to parameters the way Postgres does it, by position or by name, with the extra arguments of a `VARIADIC` function going to its last parameter; an operator's operands are handled differently (below). When they can't be matched, such as a named argument that one overload doesn't have, or the function has more than 16 parameters, every parameter counts as reaching the sink. Every overload the call could resolve to is checked. This check applies under plain `EXPLAIN` too: the planner can call an operator's function on values from the column's statistics.
- A function whose body changes name resolution, with `SET search_path`, `SET ROLE`, `RESET ALL`, `DISCARD ALL`, or `set_config` of `search_path` or `role`, is blocked for every masked user. The change would outlive the call without the plugin seeing it. A function's own `SET search_path` option is fine: Postgres restores it when the function returns.

Converting a value to a type that isn't built in, such as a domain, can run user-defined code: the domain's `CHECK` constraints, or the function of a cast created with `CREATE CAST`. So a call passing proxy-masked values to a parameter of such a type is blocked, as is a call to a function returning one, other than a table's row type, if its result is computed from proxy-masked values. Casts follow the same rule.

User-defined operators are treated as calls to their functions, however they're applied: `a op b`, `IN` and `NOT IN`, `LIKE`, `BETWEEN`, `NULLIF`, `IS DISTINCT FROM`, `CASE x WHEN`, `ANY`, `ALL` or `IN` over a subquery, `ORDER BY … USING`, and the merged columns of `JOIN … USING` and `NATURAL JOIN`. Only `a op b` can be inlined; the others are blocked if the operator's function reads SQL-masked columns.

The planner can also run an operator's commutator, with the operands swapped, for instance to estimate `1 < col` from the column's statistics, and its negator, for `NOT (a op b)`. The catalog doesn't say which operators those are. So for proxy-masked values, each operand counts as reaching every parameter of the operator's function, and of the function of every user-defined operator with the same operand types or swapped ones: an operator is blocked with proxy-masked operands if any of these functions can pass a parameter to a write or a side effect, or can't be analyzed. Their bodies also count as the operator's own: the result is `NULL` if one reads proxy-masked columns, errors are redacted if one writes, and the operator is blocked if one reads SQL-masked columns, since it can't be inlined in the planner's place.

### When a function can be inlined

These conditions only concern functions whose body reads SQL-masked columns. The function must:

- have a body that's a single `SELECT`, not selecting `*`;
- be `IMMUTABLE` or `STABLE`, not `SECURITY DEFINER`, with no `SET` options;
- not be polymorphic, `VARIADIC` or recursive;
- be the only function the call could resolve to: if several overloads match the name and number of arguments, and one reads masked columns, the call is blocked. Functions of the same name in schemas outside the `search_path` count, since Postgres may resolve the call with another `search_path` than the one PgDog reports.

The call must be a plain call:

| Call | Inlined? |
| --- | --- |
| `SELECT get_ssn(id) FROM users` | yes |
| `SELECT * FROM user_ssns_for(42)`, a set-returning function in `FROM` | yes |
| `SELECT get_ssn(42)` when the function has a second argument with a default | no: calls relying on argument defaults are blocked |
| `SELECT get_ssn(uid => 42)` | no: named arguments |
| `SELECT user_ssns_for(42)`, a set-returning function in the select list | no: set-returning functions are only inlined in `FROM` |
| `SELECT * FROM ROWS FROM (user_ssns_for(42))`, `… WITH ORDINALITY`, or with a column definition list | no |
| `SELECT f(VARIADIC arr)`, or `f(x) OVER (…)`, `f(DISTINCT x)`, `f(x) FILTER (…)`, `f(x ORDER BY y)` | no: `VARIADIC`, window or aggregate syntax |
| A scalar call to a function returning `record`, or with `OUT` parameters | no: it doesn't return a single value |

Pass every argument explicitly, by position, to keep a call inlinable. Blocked calls fail with SQLSTATE `42501` and a message naming the function and the reason.

## Code the plugin can't analyze

Functions in PL/pgSQL, C or other languages, functions of extensions, and functions not in the catalog are blocked for masked users. If such a function can't return masked data, allow it:

```toml
[general]
udf_allowlist = ["public.normalize_phone"]   # functions, schema-qualified
extension_allowlist = ["citext"]             # all functions and operators of an extension
```

Listing a function or extension attests that it doesn't return or leak masked data. The plugin calls it without analysis. Listed functions may also be called with proxy-masked values; their results return `NULL`.
