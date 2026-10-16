---
title: What masked users can’t do
description: Statements blocked for masked users, and why.
---

The plugin blocks what it can't prove safe. All of these fail with SQLSTATE `42501`, and each block is logged with its reason. Exempt users are never blocked.

## Functions

- Functions in procedural languages or C, functions of extensions, and SQL functions that read masked columns but [can't be inlined](../../configure/views-functions/#sql-functions), unless they're in `udf_allowlist` or their extension is in `extension_allowlist`.
- Functions that aren't in the catalog. This includes functions created after PgDog last loaded the schema.
- Built-ins that execute SQL or reach outside the statement, such as `query_to_xml`, `dblink*` and `lo_*`.
- Fast-path function calls, which carry no SQL to analyze.

## Catalog and statistics

- `pg_stats`, `pg_statistic` and `pg_stat_statements`, whose statistics and texts include column values.

## Statements

- `DO` blocks, `MERGE`, and `COPY … TO PROGRAM` or to a file.
- DDL other than creating tables, `DROP`, sequences, and `ALTER TABLE`, `CREATE INDEX` or renames of relations without masked columns. DDL on masked relations is blocked: expressions in `ALTER … USING` or index definitions could leak values through errors, renames would unmask columns, and `ATTACH PARTITION` or `INHERIT` would expose rows through another table.
- Creating a table that would shadow a table with masked columns.

## Views and queries

- Writing through views that read masked columns.
- Reading columns of table-like views computed from masked columns, unless they're assigned a policy.
- Views missing from the catalog's definitions, and relations missing from the catalog (unless `on_unresolved = "allow"`).
- `*` across `JOIN … USING` or `NATURAL` joins, and aliased joins, over masked columns. List the columns instead.
- Masked columns used directly as a boolean condition, such as `WHERE is_vip` on a masked column.

## Not covered

- **Inference from unmasked columns** correlated with masked ones, such as ZIP code and birth date together.
- **Timing side channels.**
- **Copies made by exempt users** into tables masked users can read.
- **Sharding keys.** Masking a column PgDog shards by breaks routing for masked users; the plugin doesn't check this. See [Choose masked columns](../../configure/columns/#dont-mask-sharding-keys).

See the [security model](../security/) for the assumptions masking relies on.
