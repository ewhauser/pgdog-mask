---
title: How masking works
description: Who gets masked, and the two ways pgdog-mask masks a column, SQL masks and proxy masks.
---

pgdog-mask runs inside [PgDog](https://github.com/pgdogdev/pgdog), the Postgres connection pooler. Applications connect to PgDog as before. For each statement a client sends, PgDog asks the plugin what to do before PgDog parses, routes or shards it: send it unchanged, send a rewritten statement, or refuse it.

## Who gets masked

Every PgDog user has a set of masking **roles**, from the plugin's configuration (users not listed have none). Every **policy** has a default mask and rules that pick a different mask for some roles. The masks that apply to one user form their **profile**.

A user whose profile masks nothing is **exempt**: their statements go through unchanged, at the cost of one lookup. Everyone else is **masked**. A masked user's statement that touches no masked column is also sent unchanged.

The identity is the PgDog user the client authenticated as, fixed for the session. `SET ROLE` and client-supplied values such as `application_name` don't change it. See [Users and roles](../../configure/users/).

## Two ways to mask a column

Each policy masks its columns in one of two ways, chosen by its `mask` setting:

- **SQL masks** mask the column **in the statement**. The plugin rewrites the statement so Postgres computes the masked value. Most masks work this way.
- **Proxy masks** mask the column **in the results**. Postgres runs the statement unchanged and returns the real value, and the plugin replaces it with the masked value before the row reaches the client.

| | SQL masks | Proxy masks |
| --- | --- | --- |
| Configured with | `mask = "partial"`, `"email"`, `"round"`, `"sql"`, … | `mask = "proxy"` |
| What Postgres runs | A rewritten statement: every reference to the column is replaced with the mask | The statement as sent: references to the column are never rewritten |
| Conditions, joins, ordering | Compare and sort masked values | Compare and sort real values |
| Indexes and plans | Conditions on the column can't use its index, except [raw searches](../../configure/raw-search/), and the plan can differ | The same indexes and plan as for an unmasked user; `EXPLAIN` shows the real plan |
| What results contain | Masked values, computed by Postgres | Columns that pass the column through get the mask, computed by the plugin |
| Expressions over the column | Computed on the masked value: `upper(ssn)` is `upper` of the mask | Return `NULL` |
| Writes and side effects | Run on masked values | Blocked when they'd move values: `INSERT … SELECT`, `UPDATE … SET`, `COPY … TO`, `set_config`, … |
| Errors | `DETAIL` removed | `DETAIL` removed, and messages of statements that compute with the column replaced |
| What users can learn | Nothing the mask hides, except by raw search | Values, by filtering and sorting on them |
| Good for | Hiding, redacting, rounding, truncating, your own SQL | Keyed hashes, format-preserving encryption, vault tokens, your own Rust code |
| Cost | None in the plugin per row | Every masked value passes through the plugin |
| Use when | By default, for everyone | A trusted role needs the real plan and rows, e.g. to debug production queries or `EXPLAIN` them |

## SQL masks: masking in the statement

For a masked user, the plugin parses the statement, resolves each column reference to the table column it reads, and **replaces each reference to a masked column with the policy's mask expression**. It does this wherever the reference appears: the select list, `WHERE`, `JOIN`, `GROUP BY`, `ORDER BY`, window clauses, `RETURNING`, subqueries, CTEs, `INSERT … SELECT` and `COPY`. `SELECT *` over a table with masked columns is expanded so each column can be masked.

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

The plugin never rewrites references to a proxy-masked column, wherever they appear. It only expands `*` into column names and inlines views, which doesn't change the plan. Postgres runs the statement on real values, with the same plan and indexes as for an unmasked user. Before PgDog sends the rows to the client, the plugin masks each output column that passes the column through, and replaces each output computed from it with `NULL`:

```sql
-- sent by an engineer, and to Postgres, unchanged
SELECT id, card, right(card, 4) AS last4 FROM payments WHERE card = '4111-1111-1111-1111';
-- returned by Postgres:   42 | 4111-1111-1111-1111 | 1111
-- sent to the client:     42 | 5291-0484-7703-6612 | NULL   (ff1 encryption)
```

The condition compared the real card and found the row. That's what keeps the statement's meaning and plan, and it's also why proxy masks are for **trusted roles**: a user can confirm a guessed value with a condition, or rank rows with `ORDER BY`, without ever receiving the value. Statements that would move values where PgDog can't mask them, such as `INSERT … SELECT`, `COPY … TO` or `UPDATE … SET name = card`, are blocked, and the error messages of statements that compute with the column are redacted.

Masked values keep the column's type, in the text or binary format the client asked for. See [Proxy masks](../../configure/proxy-masks/) to configure them and for their security model, and [Write a proxy mask](../../develop/proxy-masks/) to add your own.

## What both share

Whichever way a column is masked, the plugin analyzes the statement first, and the same protections apply:

- **Views** that read masked columns are inlined, so they can't be used to read around a policy. **SQL functions** that read SQL-masked columns are inlined with masks applied; functions that read proxy-masked columns are called as is, and their results are `NULL`. See [Views and functions](../../configure/views-functions/).
- **Statements the plugin can't prove safe are blocked** with SQLSTATE `42501`: procedural functions it can't analyze, statistics views, DDL on masked tables, and more. See [What masked users can’t do](../../reference/limitations/).
- **Errors.** Postgres errors can quote row values, like a check constraint's `Failing row contains (...)`. The plugin removes `DETAIL` from the errors and notices masked users get, unless `scrub_error_detail` is off (it's always on for users with proxy masks). PgDog replaces the whole message for statements that compute with proxy-masked columns. See [Error and notice redaction](../../configure/errors/).
- **Prepared statements** are checked when they're prepared, and again at their next execution after the configuration, the catalog or the session's `search_path` changes. If their masked SQL changed, PgDog re-prepares named statements it tracks under the same name. The unnamed statement, and every statement when PgDog's `prepared_statements` is `disabled`, fail with `26000` instead, and the client must prepare them again. See [Reload configuration](../../operate/reload/#prepared-statements).
- **Caching.** Decisions are cached per statement and profile, and statements that differ only in literal values share one analysis. Decisions are logged when they're made, not when they're reused; see [Logs and maintenance](../../operate/logs/). For costs, see [Performance](../../operate/performance/).
