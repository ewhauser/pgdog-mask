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
- One that does is **inlined** with masks applied, if it's a single `SELECT`, `IMMUTABLE` or `STABLE`, not `SECURITY DEFINER`, has no `SET` options, and isn't polymorphic or variadic. Set-returning functions are inlined in `FROM`.
- Otherwise the statement is blocked.

User-defined operators are treated as calls to their functions.

## Code the plugin can't analyze

Functions in PL/pgSQL, C or other languages, functions of extensions, and functions not in the catalog are blocked for masked users. If such a function can't return masked data, allow it:

```toml
[general]
udf_allowlist = ["public.normalize_phone"]   # functions, schema-qualified
extension_allowlist = ["citext"]             # all functions and operators of an extension
```

Listing a function or extension attests that it doesn't return or leak masked data. The plugin calls it without analysis.
