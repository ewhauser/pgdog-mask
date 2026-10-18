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
- `COPY` with an option missing its value, or with a value of the wrong type, such as `COPY t TO STDOUT WITH (delimiter)`. Postgres rejects these anyway.
- DDL other than creating tables and sequences, `DROP`, and `ALTER TABLE` or `CREATE INDEX` on relations without masked columns. DDL on masked relations is blocked: expressions in `ALTER … USING` or index definitions could leak values through errors, and `ATTACH PARTITION` or `INHERIT` would expose rows through another table.
- DDL that changes what a name resolves to. The plugin resolves names with the catalog PgDog loaded, which PgDog reloads only after the statement, and not before the transaction ends; a column reference that no longer resolves in an inner query would resolve in an outer one, where it may read masked values. So masked users can't:
  - create temporary tables or sequences (`TEMP`, a `pg_temp` schema, `SELECT … INTO TEMP`): Postgres resolves names to them first, and the plugin can't see them;
  - create a table or sequence named like a relation in the catalog, in any schema: it could hide that relation;
  - drop columns, rename relations, columns or schemas, use `DROP … CASCADE`, drop extensions, or drop a relation whose name a relation in another schema shares.
- Statements after one that may change name resolution, in the same query. After DDL that creates, drops or alters relations, or a `set_config` of `role`, a later statement that names a table, a user-defined operator or a user-defined function is blocked: the plugin can't know what its names resolve to. Send it as a separate query.
- Changes to `search_path` or the role (`SET` or `RESET` of `search_path`, `SET ROLE`, `RESET ROLE`, `SET SESSION AUTHORIZATION`, `RESET ALL`, `DISCARD ALL`), unless they're a query of their own that starts with `SET`, `RESET` or `DISCARD`. PgDog only follows those: it misses a `SET` after another statement, after a comment or `;`, or after a lot of whitespace, and the change would stay on the pooled server connection for its next client. `SELECT 1; SET search_path TO public` is blocked; `SET search_path TO public` sent on its own isn't.
- `set_config` setting `search_path`, in any form, such as `SELECT set_config('search_path', 'public', false)`, and any `set_config` whose first argument isn't a string literal. PgDog doesn't follow it while its query parser is off. Use `SET search_path`.
- Unqualified names that may refer to relations that read differently. Postgres resolves an unqualified name with the session's `search_path`, which may not be the one PgDog follows (see above, and [Security model](../security/#known-limits)). So every relation of that name, in any schema, must have the same columns, masked the same way for the user, and be a table or a view the plugin reads as it is; otherwise the name must be qualified: `"users" may refer to public.users or to backup.users, which read differently for masked users; qualify it with its schema`. Schemas with identical tables and policies, such as one per tenant, aren't affected.
- SQL `EXECUTE` of a statement not prepared by a `PREPARE` earlier in the same query. The plugin can't know what a name prepared elsewhere runs. Prepare statements through your driver, with the extended protocol, or send `PREPARE` and `EXECUTE` together.

## Views and queries

- Writing through views that read masked columns.
- Reading columns of table-like views computed from SQL-masked columns, unless they're assigned a policy. Columns computed only from proxy-masked columns return `NULL` instead.
- Views missing from the catalog's definitions, and relations missing from the catalog (unless `on_unresolved = "allow"`).
- `*` across `JOIN … USING` or `NATURAL` joins, and aliased joins, over masked columns. List the columns instead. An aliased join, `(a JOIN b ON …) AS j`, hides `a` and `b`: columns are read as `j.col`, and `*` over it is `j.*`.
- Column alias lists on a table with masked columns, when they name its first masked column or a later one, such as `SELECT c FROM users AS x(a, b, c)`. Alias the columns in the select list instead: `SELECT ssn AS c FROM users x`.
- Attribute notation on a table with masked columns, such as `SELECT u.row_to_json FROM users u`: Postgres reads it as `row_to_json(u)`, a call on the whole row. Write `row_to_json(u)`, which is masked.
- Queries embedded in an expression the plugin doesn't follow: `a subquery is used in a way the plugin can't analyze`. Subqueries, `ARRAY(…)`, `EXISTS`, `IN` and `JSON_ARRAY(query)` are followed.
- SQL-masked columns used directly as a boolean condition, such as `WHERE is_vip` on a masked column.

## With proxy masks

These apply to users with [proxy masks](../../configure/proxy-masks/), on top of the rules above.

Blocked:

- **Moving proxy-masked values** where PgDog can't mask them: `INSERT … SELECT` or `VALUES` of them, `UPDATE … SET` from them, including `UPDATE users SET ssn = ssn`, `CREATE TABLE AS`, `CREATE MATERIALIZED VIEW`, `SELECT INTO`, `COPY … TO`, and functions with side effects such as `set_config`, `pg_notify`, `setval`, `nextval`, advisory locks and large-object functions. Conditions are fine: `INSERT INTO orders (user_id, total) SELECT id, 0 FROM users WHERE ssn = $1` runs.
- **`DECLARE` and SQL `PREPARE`** of a statement that uses a proxy-masked column anywhere, even only in a condition.
- **A `*` of unknown width** before, or covering, a column that carries proxy-masked values: `*` over a function in `FROM`, such as a set-returning function that reads them, over a catalog table such as `pg_class`, over `(expression).*`, over a join with `USING` or `NATURAL`, or over an aliased join of tables, such as `SELECT * FROM (orders a JOIN orders b ON true) j, users u`. List the columns instead.
- **DDL expressions** computed from proxy-masked columns, or calling functions that read them: defaults, generated columns, checks, `ALTER … TYPE … USING` and index expressions, such as `ALTER TABLE orders ADD COLUMN x text DEFAULT public.user_ssn(1)`.
- **Function calls** that pass proxy-masked values to a parameter that could reach a write or a side effect in the function's body. Parameters used only in conditions are fine. Without argument types, every overload the call could resolve to is checked, and arguments that can't be matched to parameters count as reaching the sink. See [Views and functions](../../configure/views-functions/#sql-functions).
- **Conversions to types that aren't built in**, such as domains and composite or enum types, of proxy-masked values: a domain's check, or a user-defined cast's function, runs on the value. This covers casts (`ssn::my_domain`), arguments passed to parameters of such a type, and results of functions returning one, other than a table's row type, when they're computed from proxy-masked values. Elsewhere, such as `JSON_VALUE(… RETURNING my_domain)`, a statement that reads proxy-masked columns can't use such a type at all.
- **User-defined operators** with proxy-masked operands, however they're applied (`=`, `IN`, `LIKE`, `BETWEEN`, `CASE x WHEN`, `= ANY (subquery)`, `ORDER BY … USING`, `JOIN … USING`, …), if any parameter of their function, or of the function of a user-defined operator with the same or swapped operand types, could reach a write or a side effect: the planner may run such an operator as a commutator or negator, with the operands in either order.
- **Attribute notation** on a subquery or CTE that returns proxy-masked values, such as `SELECT s.to_json FROM (SELECT ssn FROM users) s`, and qualified names of its columns without an `AS` name, such as `s.case` for a `CASE` column: Postgres may name it differently. Name the column with `AS`.
- **`EXPLAIN` of a call to an `IMMUTABLE` SQL function that reads proxy-masked columns**, or to a function that calls one, under `EXPLAIN` and `EXPLAIN ANALYZE`: the planner can compute the result in advance, and the plan would show it. Declare such functions `STABLE`, or run the statement without `EXPLAIN`.

Conservatively return `NULL`:

- Outputs computed from the column, including casts to its own type (`ssn::varchar`), window functions ordered or partitioned by it, aggregates with `FILTER` or `ORDER BY` on it, and `CASE` conditions on it.
- Scalar and `ARRAY` subqueries, even when they return the column unchanged.
- `UNION`, `INTERSECT` and `EXCEPT` columns where a branch returns anything other than the same proxy-masked column, including a literal.
- Columns a recursive CTE carries from one iteration to the next.
- Subquery and CTE columns without an `AS` name, read by an unqualified name from outside, when the subquery returns proxy-masked values. Read as `s.name`, they're blocked (above). Name such columns with `AS`.

Not redacted:

- Errors and notices that a row security policy raises during a read that doesn't compute with proxy-masked columns. Reading a view whose definition computes with them, or calls a function that writes, is redacted, whether the view is inlined or queried like a table. Statements that write, maintain, alter or commit are always redacted, whatever table they write, so triggers, constraints and defaults of any table are covered, including deferred constraint triggers firing at `COMMIT`. See [Per-statement redaction](../../configure/errors/#per-statement-redaction).
- Functions in `udf_allowlist` or `extension_allowlist`, and views in `view_allowlist`, aren't analyzed: reading or calling one that writes doesn't make the statement redacted.

Not supported:

- A proxy mask on a column whose type is a domain over another domain. PgDog's catalog gives the inner domain's type, while results carry the base type, so PgDog refuses the mask and closes the connection with a `FATAL` error. Nothing leaks. Use a domain over a base type, or mask the column with a SQL mask.

## Not covered

- **Inference from unmasked columns** correlated with masked ones, such as ZIP code and birth date together.
- **Inference through proxy-masked columns**, whose conditions and ordering use real values by design. See [Proxy masks](../../configure/proxy-masks/#security-model).
- **Timing side channels.**
- **Copies made by exempt users** into tables masked users can read.
- **Sharding keys.** Masking a column PgDog shards by breaks routing for masked users; the plugin doesn't check this. See [Choose masked columns](../../configure/columns/#dont-mask-sharding-keys).

See the [security model](../security/) for the assumptions masking relies on.
