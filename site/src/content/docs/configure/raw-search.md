---
title: Search on masked columns
description: Let some roles find rows by a masked column's real value while still seeing it masked.
---

By default a masked column is masked everywhere, including `WHERE`: `WHERE ssn = '123-45-6789'` compares masked values and finds nothing. That's what stops a masked user from confirming a guessed value.

Some workflows need to look rows up by the real value. A support agent finds a customer by SSN, but should still see it masked. A rule can allow that with `search = "raw"`:

```toml
[[policies.rules]]
roles = ["support"]
mask = "partial"
keep_suffix = 4
search = "raw"
search_operators = ["=", "in"]   # optional; this is roughly the default
```

```sql
-- as support: finds the row, and the result is still masked
SELECT id, ssn FROM users WHERE ssn = $1;
```

## What stays raw

A reference is left unmasked only in a search shape. Everywhere else, including the select list of the same statement, it's masked.

- **Position:** a `WHERE` clause, or a join condition, of `SELECT`, `UPDATE` or `DELETE`.
- **Shape:** `column <operator> operand`, where the operand is a parameter, a constant, a list or array of those, or another column (a join key). The column and the operand may be wrapped in `lower`, `upper`, `btrim`, `ltrim` or `rtrim`.
- **Operators:** by default the equality family: `=`, `<>`, `IN`, `= ANY`, `IS [NOT] DISTINCT FROM`, `IS [NOT] NULL`. `search_operators` replaces the list. Accepted values: `=`, `<>`, `!=`, `in`, `any`, `distinct`, `is_null`, `<`, `>`, `<=`, `>=`, `between`, `range`, `like`, `ilike`.

Casts, arithmetic, `CASE` and other function calls around the column stay masked. Without this restriction, `WHERE ssn::int = 0` would return the real value inside the cast error, and `WHERE set_config('x', ssn, false) <> ''` would store it in a setting.

## What you're allowing

Raw search deliberately allows confirming a guess, so treat it as a privilege:

- **Range and pattern operators make extraction fast.** With `<`/`>` or `LIKE`, a value can be recovered by binary search or prefix probing in a few dozen queries. Only add them when you need them.
- **Low-entropy columns can be brute-forced** even with equality alone, for example dates of birth or ZIP codes.
- **Every raw search is logged** at `info`, with the user and the columns searched. Parameter values are never logged:

  ```text
  [pgdog_mask] user "support_app" searched raw values of {"public.users.ssn"}
  ```

Raw predicates also keep using indexes on the column, unlike masked ones. See [performance](../../operate/performance/#indexes).
