---
title: What masked users can’t do
description: Statements blocked for masked users, and why.
---

The plugin blocks what it can't prove safe. All of these fail with SQLSTATE `42501`, and blocks are logged with their reason when the statement is analyzed (see [Logs and maintenance](../../operate/logs/)). Exempt users are never blocked.

## Functions

- Functions in procedural languages or C, functions of extensions, and SQL functions that read SQL-masked columns but [can't be inlined](../../configure/views-functions/#when-a-function-can-be-inlined), unless they're in `udf_allowlist` or their extension is in `extension_allowlist`. Inlining depends on the call as well as the function: calls relying on argument defaults, named arguments, set-returning calls outside `FROM`, and aggregate or window syntax are blocked.
- Functions that aren't in the catalog. This includes functions created after PgDog last loaded the schema.
- Built-ins that execute SQL or reach outside the statement, such as `query_to_xml`, `dblink*`, `lo_*` and `pg_logical_slot_*`.
- SQL functions whose body changes name resolution: `SET search_path`, `SET ROLE`, `RESET ALL`, `DISCARD ALL`, or `set_config` of `search_path` or `role`. A function's own `SET search_path` option is fine.
- Fast-path function calls, which carry no SQL to analyze.

## Catalog and statistics

- `pg_stats`, `pg_statistic` and `pg_stat_statements`, whose statistics and texts include column values.

## Statements

- `DO` blocks, `MERGE` anywhere (including under `EXPLAIN`, in `PREPARE` and in CTEs), and `COPY … TO PROGRAM` or to a file.
- DDL other than creating tables, `DROP`, sequences, and `ALTER TABLE`, `CREATE INDEX` or renames of relations without masked columns. DDL on masked relations is blocked: expressions in `ALTER … USING` or index definitions could leak values through errors, renames would unmask columns, and `ATTACH PARTITION` or `INHERIT` would expose rows through another table.
- Creating a table that would shadow a table with masked columns.
- Statements after one that may change name resolution, in the same query. After `SET` or `RESET` of `search_path`, `SET ROLE`, `RESET ROLE`, `SET SESSION AUTHORIZATION`, `RESET ALL`, `DISCARD ALL`, `set_config` of `role`, or DDL that creates, drops, renames or alters relations, a later statement that names a table, a user-defined operator or a user-defined function is blocked: the plugin can't know what its names resolve to. Send it as a separate query. `SET search_path TO public; SELECT ssn FROM users` is blocked; the two statements sent one after the other aren't.
- `set_config` setting `search_path`, except as a query of its own: `SELECT set_config('search_path', 'public', false)`. PgDog tracks that form and `SET search_path`, and nothing else. A `set_config` whose first argument isn't a string literal is blocked too.
- SQL `EXECUTE` of a statement not prepared by a `PREPARE` earlier in the same query. The plugin can't know what a name prepared elsewhere runs. Prepare statements through your driver, with the extended protocol, or send `PREPARE` and `EXECUTE` together.

## Views and queries

- Writing through views that read masked columns.
- Reading columns of table-like views computed from SQL-masked columns, unless they're assigned a policy. Columns computed only from proxy-masked columns return `NULL` instead.
- Views missing from the catalog's definitions, and relations missing from the catalog (unless `on_unresolved = "allow"`).
- `*` across `JOIN … USING` or `NATURAL` joins, and aliased joins, over masked columns. List the columns instead.
- Column alias lists on a table with masked columns, when they name its first masked column or a later one, such as `SELECT c FROM users AS x(a, b, c)`. Alias the columns in the select list instead: `SELECT ssn AS c FROM users x`.
- Attribute notation on a table with masked columns, such as `SELECT u.row_to_json FROM users u`: Postgres reads it as `row_to_json(u)`, a call on the whole row. Write `row_to_json(u)`, which is masked.
- SQL-masked columns used directly as a boolean condition, such as `WHERE is_vip` on a masked column.

## With proxy masks

These apply to users with [proxy masks](../../configure/proxy-masks/), on top of the rules above.

Blocked:

- **Moving proxy-masked values** where PgDog can't mask them: `INSERT … SELECT` or `VALUES` of them, `UPDATE … SET` from them, including `UPDATE users SET ssn = ssn`, `CREATE TABLE AS`, `CREATE MATERIALIZED VIEW`, `SELECT INTO`, `COPY … TO`, and functions with side effects such as `set_config`, `pg_notify`, `setval`, `nextval`, advisory locks and large-object functions. Conditions are fine: `INSERT INTO orders (user_id, total) SELECT id, 0 FROM users WHERE ssn = $1` runs.
- **`DECLARE` and SQL `PREPARE`** of a statement that uses a proxy-masked column anywhere, even only in a condition.
- **A `*` of unknown width** before, or covering, a column that carries proxy-masked values: `*` over a function in `FROM`, such as a set-returning function that reads them, over a catalog table such as `pg_class`, over `(expression).*`, or over a join with `USING` or `NATURAL`. List the columns instead.
- **DDL expressions** computed from proxy-masked columns, or calling functions that read them: defaults, generated columns, checks, `ALTER … TYPE … USING` and index expressions, such as `ALTER TABLE orders ADD COLUMN x text DEFAULT public.user_ssn(1)`.
- **Function calls** whose proxy-masked arguments could reach a write or a side effect in the function's body. See [Views and functions](../../configure/views-functions/#sql-functions).
- **Attribute notation** on a subquery or CTE that returns proxy-masked values, such as `SELECT s.to_json FROM (SELECT ssn FROM users) s`.

Conservatively return `NULL`:

- Outputs computed from the column, including casts to its own type (`ssn::varchar`), window functions ordered or partitioned by it, aggregates with `FILTER` or `ORDER BY` on it, and `CASE` conditions on it.
- Scalar and `ARRAY` subqueries, even when they return the column unchanged.
- `UNION`, `INTERSECT` and `EXCEPT` columns where a branch returns anything other than the same proxy-masked column, including a literal.
- Columns a recursive CTE carries from one iteration to the next.
- Subquery and CTE columns without an `AS` name, read by name from outside, when the subquery returns proxy-masked values. Name such columns with `AS`.

Not redacted:

- Errors and notices that a row security policy, or a function in a view, raises during a read that doesn't compute with proxy-masked columns. Writes to tables with proxy-masked columns are always redacted.

## Not covered

- **Inference from unmasked columns** correlated with masked ones, such as ZIP code and birth date together.
- **Inference through proxy-masked columns**, whose conditions and ordering use real values by design. See [Proxy masks](../../configure/proxy-masks/#security-model).
- **Timing side channels.**
- **Copies made by exempt users** into tables masked users can read.
- **Sharding keys.** Masking a column PgDog shards by breaks routing for masked users; the plugin doesn't check this. See [Choose masked columns](../../configure/columns/#dont-mask-sharding-keys).

See the [security model](../security/) for the assumptions masking relies on.
