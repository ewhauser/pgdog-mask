---
title: Policies and rules
description: Define masks, choose them per role, and mask conditionally on other columns.
---

A policy defines how one kind of data is masked. Its top-level mask is the **default**; **rules** choose a different mask for some roles.

```toml
[[policies]]
name = "ssn"
data_type = "text"
mask = "sql"
expression = "'XXX-XX-' || right(val, 4)"

[[policies.rules]]
roles = ["pii_admin"]
mask = "none"

[[policies.rules]]
roles = ["support"]
mask = "partial"
keep_suffix = 4
```

- `name` identifies the policy; columns and tags refer to it.
- `data_type` is the type the policy applies to, as `information_schema` spells it: `text`, `character varying`, `numeric`, `date`, `timestamp with time zone`, and so on. Masks are checked against it when the configuration loads.
- Rules are checked in order. The **first rule whose `roles` include any of the user's roles wins**. If none matches, the default applies.

Mask parameters are flat keys next to `mask`, on the policy or the rule. See the [mask reference](../../reference/masks/) for every mask and its keys.

## SQL expressions

`mask = "sql"` takes any expression over `val`, the column's value:

```toml
[[policies]]
name = "dob"
data_type = "date"
mask = "sql"
expression = "make_date(extract(year FROM val)::int, 1, 1)"
```

Expressions may only reference `val` and the policy's `arguments`, and can't contain subqueries. Every mask is cast back to the column's type, so drivers and ORMs see the type they expect.

## Conditional masking

`arguments` bind other columns of the same row to names the expression can use. Each masked column provides its own columns for them:

```toml
[[policies]]
name = "marketing_email"
data_type = "text"
arguments = ["opted_in"]
mask = "sql"
expression = "CASE WHEN opted_in THEN val ELSE NULL END"

[[masked_columns]]
name = "users"
column = "email"
policy = "marketing_email"
arguments = ["marketing_opt_in"]    # users.marketing_opt_in is bound to opted_in
```

## Masks computed in code

`mask = "proxy"` computes the mask in the plugin instead of in SQL, for keyed hashes, format-preserving encryption, vault tokens, or masks you write. Proxy masks apply to results: Postgres runs the statement on real values, output columns that pass the column through get the proxy mask, and outputs computed from it return `NULL`. Since conditions and ordering use real values, give them to trusted roles in a rule, and keep a SQL mask as the default. See [Proxy masks](../proxy-masks/).
