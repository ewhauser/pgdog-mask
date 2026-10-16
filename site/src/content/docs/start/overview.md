---
title: How masking works
description: What pgdog-mask does to a statement, who gets masked, and where masking happens.
---

pgdog-mask runs inside [PgDog](https://github.com/pgdogdev/pgdog), the Postgres connection pooler. Applications connect to PgDog as before. For each statement a client sends, PgDog asks the plugin what to do before PgDog parses, routes or shards it.

## Who gets masked

Every PgDog user has a set of masking **roles**, from the plugin's configuration (users not listed have none). Every **policy** has a default mask and rules that pick a different mask for some roles. The masks that apply to one user form their **profile**.

A user whose profile masks nothing is **exempt**: their statements go through untouched, at the cost of one lookup. Everyone else is **masked**.

The identity is the PgDog user the client authenticated as, fixed for the session. `SET ROLE` and client-supplied values such as `application_name` don't change it. See [Users and roles](../../configure/users/).

## What happens to a statement

For a masked user, the plugin parses the statement and resolves every column reference to the base table column it reads, using the database catalog PgDog loads. Then:

1. **References to masked columns are replaced with their mask**, wherever they appear: the select list, `WHERE`, `JOIN`, `GROUP BY`, `ORDER BY`, window clauses, `RETURNING`, subqueries, CTEs, `INSERT … SELECT` and `COPY`. `SELECT *` over a table with masked columns is expanded so each column can be masked.
2. **Views and SQL functions that read masked columns are inlined** with masks applied, so they can't be used to read around a policy. See [Views and functions](../../configure/views-functions/).
3. **Anything the plugin can't prove safe is blocked** with SQLSTATE `42501`: procedural functions it can't analyze, statistics views, DDL on masked tables, and more. See [What masked users can’t do](../../reference/limitations/).

The rewritten statement is what PgDog parses, routes and sends. Postgres computes the masked values, so results, row counts, ordering and aggregates are all computed on masked data. Each mask is cast back to the column's type, so drivers and ORMs see the types they expect.

```sql
-- sent by a masked user
SELECT u.name, u.ssn FROM users u WHERE u.ssn = '123-45-6789';
-- sent to Postgres
SELECT u.name, ('XXX-XX-' || right(u.ssn, 4))::text AS ssn
FROM users u WHERE ('XXX-XX-' || right(u.ssn, 4))::text = '123-45-6789';
```

The `WHERE` clause compares masked values, so this finds nothing: a masked user can't confirm a guess. Roles that need to look rows up by the real value can be allowed to, with [raw search](../../configure/raw-search/).

## Masks in SQL and masks in code

Most masks are **SQL masks**: an expression in the rewritten statement, like `partial`, `email`, `round` or your own SQL. Postgres evaluates them.

**Proxy masks** are computed by the plugin, in Rust, on the rows Postgres returns: keyed hashes whose key must never appear in a statement, format-preserving encryption, vault tokens, or code you write. They apply to plain output columns; every other reference to the column gets the policy's SQL fallback. See [Proxy masks](../../configure/proxy-masks/).

## Around the statement

- **Errors.** Postgres errors can quote row values, like a check constraint's `Failing row contains (...)`. The plugin removes `DETAIL` from every error and notice masked users get. See [Error details](../../configure/errors/).
- **Prepared statements.** Decisions are deterministic, so prepared statements are checked when they're prepared, and again only after the configuration or the catalog changes. PgDog re-prepares them transparently when their masked SQL changes.
- **Caching.** Decisions are cached per statement and profile, and statements that differ only in literal values share one analysis. See [Performance](../../operate/performance/).
