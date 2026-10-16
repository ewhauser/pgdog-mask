---
title: How masking works
description: Who gets masked, and the two ways pgdog-mask masks a column, SQL masks and proxy masks.
---

pgdog-mask runs inside [PgDog](https://github.com/pgdogdev/pgdog), the Postgres connection pooler. Applications connect to PgDog as before. For each statement a client sends, PgDog asks the plugin what to do before PgDog parses, routes or shards it.

## Who gets masked

Every PgDog user has a set of masking **roles**, from the plugin's configuration (users not listed have none). Every **policy** has a default mask and rules that pick a different mask for some roles. The masks that apply to one user form their **profile**.

A user whose profile masks nothing is **exempt**: their statements go through untouched, at the cost of one lookup. Everyone else is **masked**.

The identity is the PgDog user the client authenticated as, fixed for the session. `SET ROLE` and client-supplied values such as `application_name` don't change it. See [Users and roles](../../configure/users/).

## Two ways to mask a column

Each policy masks its columns in one of two ways, chosen by its `mask` setting:

- **SQL masks** mask the column **in the statement**. The plugin rewrites the statement so Postgres computes the masked value. Most masks work this way.
- **Proxy masks** mask the column **in the results**. Postgres returns the real value, and the plugin replaces it with the masked value before the row reaches the client.

| | SQL masks | Proxy masks |
| --- | --- | --- |
| Configured with | `mask = "partial"`, `"email"`, `"round"`, `"sql"`, … | `mask = "proxy"` |
| Computed by | Postgres, as part of the rewritten statement | the plugin, on the rows Postgres returns |
| Covers | every reference to the column | plain output columns of a single `SELECT` |
| Good for | hiding, redacting, rounding, truncating, your own SQL | keyed hashes, format-preserving encryption, vault tokens, your own Rust code |
| Cost | none in the plugin per row | every masked value passes through the plugin |

## SQL masks: masking in the statement

For a masked user, the plugin parses the statement, resolves every column reference to the table column it reads, and **replaces each reference to a masked column with the policy's mask expression**. It does this wherever the reference appears: the select list, `WHERE`, `JOIN`, `GROUP BY`, `ORDER BY`, window clauses, `RETURNING`, subqueries, CTEs, `INSERT … SELECT` and `COPY`. `SELECT *` over a table with masked columns is expanded so each column can be masked.

```sql
-- sent by a masked user
SELECT name, ssn FROM users WHERE ssn = '123-45-6789';
-- sent to Postgres
SELECT name, ('XXX-XX-' || right(ssn, 4))::text AS ssn
FROM users WHERE ('XXX-XX-' || right(ssn, 4))::text = '123-45-6789';
```

PgDog sends the rewritten statement, and Postgres computes everything on masked values: results, filters, ordering and aggregates. That's why a masked user can't use a `WHERE` clause to confirm a guessed value: the condition above compares masked values and finds nothing. Roles that need to look rows up by the real value can be allowed to, with [raw search](../../configure/raw-search/).

Each mask is cast back to the column's type, so drivers and ORMs see the types they expect. See the [mask reference](../../reference/masks/) for every SQL mask.

## Proxy masks: masking in the results

Some masks can't, or shouldn't, be computed by Postgres: a keyed hash whose key must never appear in a statement, where logs and `pg_stat_statements` would expose it; format-preserving encryption; tokens from a vault; or logic you write in Rust. A proxy mask is computed by the plugin instead.

When a masked column is a plain output column of a single `SELECT`, the plugin leaves it in the statement as is. Postgres returns the real value, and the plugin masks it, in batches of rows, before PgDog sends the rows to the client:

```sql
-- sent by a masked user, and to Postgres, unchanged
SELECT id, card FROM payments WHERE id = 42;
-- returned by Postgres:   42 | 4111-1111-1111-1111
-- sent to the client:     42 | 5291-0484-7703-6612   (ff1 encryption)
```

Because Postgres works with the real value, a proxy mask can only cover a column that Postgres passes straight through to the result. Anything that computes with the column, such as a filter, a join, `ORDER BY`, `DISTINCT`, a function call, a subquery or `COPY`, would reveal real values through its effect on the results. So **every other reference to the column gets the policy's `fallback`**: an SQL mask, `null` by default, applied in the statement:

```sql
-- sent by a masked user
SELECT id, card FROM payments WHERE card = '4111-1111-1111-1111';
-- sent to Postgres: the output is masked in the results, the condition by the fallback
SELECT id, card FROM payments WHERE NULL::varchar = '4111-1111-1111-1111';
```

Masked values keep the column's type, in the text or binary format the client asked for. See [Proxy masks](../../configure/proxy-masks/) to configure them, and [Write a proxy mask](../../develop/proxy-masks/) to add your own.

## What both share

Whichever way a column is masked, the plugin analyzes the statement first, and the same protections apply:

- **Views and SQL functions** that read masked columns are inlined with masks applied, so they can't be used to read around a policy. See [Views and functions](../../configure/views-functions/).
- **Anything the plugin can't prove safe is blocked** with SQLSTATE `42501`: procedural functions it can't analyze, statistics views, DDL on masked tables, and more. See [What masked users can’t do](../../reference/limitations/).
- **Errors.** Postgres errors can quote row values, like a check constraint's `Failing row contains (...)`. The plugin removes `DETAIL` from every error and notice masked users get. See [Error details](../../configure/errors/).
- **Prepared statements** are checked when they're prepared, and again only after the configuration or the catalog changes. PgDog re-prepares them transparently when their masked SQL changes.
- **Caching.** Decisions are cached per statement and profile, and statements that differ only in literal values share one analysis. See [Performance](../../operate/performance/).
