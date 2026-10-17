---
title: Views and functions
description: How views and SQL functions over masked columns are masked, and how to allow code the plugin can't analyze.
---

Views and functions could otherwise read masked columns on a masked user's behalf. The plugin analyzes them using the definitions in the catalog PgDog loads.

## Views

A view whose definition reads masked columns is **inlined**: `FROM user_ssns` becomes `FROM (<its definition>) AS user_ssns`, masked like any subquery. Nested views are inlined recursively.

Some views are queried **like tables** instead:

- views with `security_barrier` or `security_invoker`;
- materialized views;
- views with masked columns of their own (assigned in `[[masked_columns]]` or by tags);
- every view, with `inline_views = false`.

Columns of a table-like view that pass a masked column through unchanged get its mask. Columns computed from masked columns are blocked, unless you assign them a policy.

Writes through views that read masked columns are blocked, and views without a definition in the catalog are blocked.

`view_allowlist` lists views masked users may query without analysis. Listing one attests that it doesn't return masked data.

## SQL functions

SQL-language functions are analyzed:

- A function that reads no masked columns is called as is.
- One that does is **inlined** with masks applied, if both the function and the call allow it (below).
- Otherwise the statement is blocked.

User-defined operators are treated as calls to their functions.

### When a function can be inlined

The function must:

- have a body that's a single `SELECT`, not selecting `*`;
- be `IMMUTABLE` or `STABLE`, not `SECURITY DEFINER`, with no `SET` options;
- not be polymorphic, `VARIADIC` or recursive;
- be the only function the call could resolve to: if several overloads match the name and number of arguments, and one reads masked columns, the call is blocked.

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

Listing a function or extension attests that it doesn't return or leak masked data. The plugin calls it without analysis.
