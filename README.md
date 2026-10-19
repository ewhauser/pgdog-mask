# pgdog-mask

Dynamic data masking for [PgDog](https://github.com/pgdogdev/pgdog), modeled on Snowflake's dynamic data masking.

Documentation: https://ewhauser.github.io/pgdog-mask/ (source in [`site/`](site)). Design: [docs/DESIGN.md](docs/DESIGN.md).

For PgDog users with masking policies, the plugin parses each statement before PgDog does. It then resolves every column reference to `schema.table.column`, and replaces each reference to a masked column with the policy's mask expression. This applies wherever the reference appears:
- the select list, `WHERE`, `JOIN`, `GROUP BY`, `ORDER BY` and window clauses;
- `RETURNING`, subqueries and CTEs;
- `INSERT … SELECT` and `COPY`;
- views and SQL functions that read masked columns, which are inlined with masks applied.

Postgres then computes the masked values, so filters, sorting and aggregates can't reveal the real ones. Users whose policies mask nothing are passed through untouched. [Proxy masks](#proxy-masks) work the other way: the statement runs unchanged, and the plugin masks its results.

## Requirements

The plugin uses PgDog's plugin API 0.8 (statement, transform, error and catalog hooks), which is only on [`ewhauser/pgdog`](https://github.com/ewhauser/pgdog) (branch `masking/plugin-api`). It has been proposed upstream in [pgdogdev/pgdog#1835](https://github.com/pgdogdev/pgdog/issues/1835), but there's no guarantee it will be accepted, or accepted in this form. `Cargo.toml` pins `pgdog-plugin` to a commit there.

PgDog only loads plugins with the same plugin API version that were built by the same Rust compiler. Build PgDog from the pinned commit with the same toolchain as this plugin. `rust-toolchain.toml` matches PgDog's.

## Building

```bash
cargo build --release
# target/release/libpgdog_mask.so (Linux) or libpgdog_mask.dylib (macOS)
# target/release/pgdog-mask, which validates a configuration (see below)
```

Put the library where PgDog can `dlopen` it, such as `LD_LIBRARY_PATH` or a system library path, or give its full path as the plugin `name`.

## Enabling

```toml
# pgdog.toml
[[plugins]]
name = "pgdog_mask"
config = "masking.toml"
required = true   # never serve traffic without masking
```

The plugin needs the database catalog, which PgDog loads and sends to it automatically. Masked users get an error (SQLSTATE `57P03`) until the catalog has loaded.

## Configuration

```toml
# masking.toml
[general]
mode = "enforce"            # enforce | shadow (log decisions only) | off
on_unresolved = "block"     # relations missing from the catalog
udf_allowlist = []          # functions masked users may call without analysis, e.g. "public.normalize_phone"
extension_allowlist = []    # extensions whose functions and operators are trusted, e.g. "citext"
view_allowlist = []         # views masked users may query without analysis
inline_views = true         # inline views over masked columns; false: treat views like tables
scrub_error_detail = true   # remove DETAIL from the errors and notices masked users get
tag_source = "config"       # config | comment | security_label
security_label_provider = "pgdog"
cache_size = 100000

# Masking roles for PgDog users. Users not listed have no roles.
[[users]]
name = "support_app"
database = "prod"           # optional
roles = ["support"]

# A policy's top-level mask is the default. Rules are checked in order;
# the first whose roles match the user's roles wins.
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
search = "raw"              # may search on the raw value; results stay masked
search_operators = ["=", "in"]

# Conditional masking: arguments are bound to other columns of the same row.
[[policies]]
name = "marketing_email"
data_type = "text"
arguments = ["opted_in"]
mask = "sql"
expression = "CASE WHEN opted_in THEN val ELSE NULL END"

[[masked_columns]]
database = "prod"           # optional
schema = "public"           # optional
name = "users"              # optional: omit to mask the column in every table
column = "ssn"
policy = "ssn"              # or: tag = "pii.ssn" with a [[tags]] entry

[[masked_columns]]
name = "users"
column = "email"
policy = "marketing_email"
arguments = ["marketing_opt_in"]

[[tags]]
name = "pii.ssn"
policy = "ssn"

# Tag columns by name. The regex must match the whole column name.
[[classifiers]]
database = "prod"           # optional
schema = "public"           # optional
name = "users"              # optional
column_regex = "ssn|social_security_number"
tag = "pii.ssn"
```

### Tags in the database

With `tag_source = "comment"`, a column comment containing `pgdog:tag=<name>` tags the column, e.g. `COMMENT ON COLUMN users.ssn IS 'Social security number. pgdog:tag=pii.ssn'`. With `tag_source = "security_label"`, the label set by `SECURITY LABEL FOR pgdog ON COLUMN users.ssn IS 'pii.ssn'` does; this needs a label provider loaded in Postgres. Tags map to policies through `[[tags]]`, so policies stay in the config file.

Database tags only add masking: `[[masked_columns]]` wins, then database tags, then classifiers. Tags that can't be resolved fail closed: a tag with no `[[tags]]` entry, or tags (or classifiers) for different policies, make the column read as `NULL` for masked users, with an error in the log. Tags that disappear between schema loads are logged at `warn`, since that unmasks a column.

Tag changes apply when PgDog next loads the schema. `COMMENT ON COLUMN` and `SECURITY LABEL … ON COLUMN` sent through PgDog reload it right away (with `reload_schema_on_ddl`, the default); changes made directly on Postgres apply at the next reload or restart. See [Tags in the database](https://ewhauser.github.io/pgdog-mask/configure/columns/#tags-in-the-database).

### Views and functions

A view whose definition reads masked columns is inlined: `FROM v` becomes `FROM (<definition>) AS v(...)`, masked like any subquery. `security_barrier` and `security_invoker` views, materialized views, views with masked columns of their own, and all views with `inline_views = false` are queried like tables: columns passed through from masked columns get their masks, and columns computed from masked columns are blocked unless they're assigned a policy.

SQL functions are analyzed. A function that reads no masked columns is called as is. One that does is inlined with masks applied if it's a single `SELECT`, `IMMUTABLE` or `STABLE`, not `SECURITY DEFINER`, has no `SET` options, and isn't polymorphic or variadic. Set-returning functions are inlined in `FROM`. User-defined operators are treated as calls to their functions. Proxy masks never cause inlining: functions that read proxy-masked columns are called as is, and their results return NULL.

Built-in masks are `none`, `null`, `constant` (`value`), `default`, `partial` (`keep_prefix`, `keep_suffix`, `fill`), `email`, `hash`, `round` (`digits`), `truncate` (`unit`), and `sql` (`expression`, over `val` and the policy's `arguments`). Every mask is cast back to the column's type.

### Proxy masks

`mask = "proxy"` masks a column in code, in the plugin, instead of in SQL: for keyed hashes whose key must never appear in statements, format-preserving encryption, vault tokens, or your own logic.

```toml
[[policies]]
name = "card"
data_type = "character varying"
mask = "partial"                           # everyone else: a SQL mask
keep_suffix = 4

[[policies.rules]]
roles = ["engineer"]
mask = "proxy"
proxy = "ff1"                              # or "hmac_sha256", or your own
options = { key_env = "CARD_FF1_KEY" }     # hex AES key, from the environment
```

Proxy masks mask every output that passes the column through, and return NULL for outputs computed from it. Conditions, joins and ordering use real values, so use them for trusted roles.

References to a proxy-masked column are never rewritten, so Postgres runs the statement with the same plan and indexes as for an unmasked user, and `EXPLAIN` shows that plan. The plugin only expands `*` into column names and inlines views, which doesn't change the plan. Statements that would move values where PgDog can't mask them (`INSERT … SELECT`, `UPDATE … SET`, `CREATE TABLE AS`, `COPY … TO`, cursors, `set_config`) are blocked, and the errors of statements that compute with the column are redacted. `search = "raw"` and SQL mask keys such as `keep_suffix` on proxy rules are configuration errors. See [Proxy masks](https://ewhauser.github.io/pgdog-mask/configure/proxy-masks/).

Built-in proxy masks: `hmac_sha256` (options `key_env` or `key_file`, `length`) and `ff1` (options `key_env` or `key_file`, `alphabet`, `tweak`).

To write your own, implement `pgdog_mask::proxy::ProxyMask` and build your own plugin with `pgdog_mask::masking_plugin!`, depending on `pgdog-mask` with `default-features = false`. See [`example/custom-mask`](example/custom-mask) and `docs/DESIGN.md` §7.2.

### Raw search

`search = "raw"` lets a role find rows by a masked column's real value: `WHERE ssn = $1`, `IN`, `= ANY`, `IS NULL`, `IS DISTINCT FROM`, optionally wrapped in `lower`/`upper`/`trim`. Results are still masked. This deliberately allows guessing a value and confirming it. It does not allow extracting values: casts, arbitrary functions, and other expressions around the column remain masked. Range and `LIKE` operators are opt-in via `search_operators` because they let a value be recovered quickly. Every raw search is logged.

### Validating

The plugin checks the file when it loads it, without a database. `pgdog-mask validate` also checks it against the database, for local runs and CI:

```bash
pgdog-mask validate masking.toml --url "postgres://pgdog:pgdog@127.0.0.1:5432/app"
```

It prepares every SQL mask for the types it's applied to, as `SELECT (<mask>)::T FROM (SELECT NULL::T AS val) s LIMIT 0`, so type errors show up before a statement uses the mask. It warns about `[[masked_columns]]` and `[[classifiers]]` that match no column, tags that fail closed, and raw searches that allow range or pattern operators or apply to `date`, `boolean` or enum columns. It exits with 1 on errors (and warnings, with `--deny-warnings`). `--skip-proxy-masks` skips building proxy masks, which needs their keys. See [Validate a configuration](https://ewhauser.github.io/pgdog-mask/operate/validate/).

## What masked users can't do

All of these fail closed with SQLSTATE `42501`:
- call functions in procedural languages or C, extension functions and operators, and SQL functions that read SQL-masked columns but can't be inlined, unless they're in `udf_allowlist` or `extension_allowlist`;
- call functions that aren't in the catalog;
- call SQL-executing built-ins such as `query_to_xml`, `dblink*` and `lo_*`;
- query `pg_stats`, `pg_statistic` or `pg_stat_statements`;
- run `DO`, `MERGE` (anywhere, including under `EXPLAIN`), `COPY … TO PROGRAM/file`, or DDL other than creating tables and sequences, `DROP`, and `ALTER TABLE`/`CREATE INDEX` on relations without masked columns. DDL on masked relations is blocked: expressions in `ALTER … USING` or index definitions can leak values through errors, and `ATTACH PARTITION`/`INHERIT` would expose their rows through another table;
- run DDL that changes what a name resolves to before PgDog reloads its catalog: create temporary relations, or relations named like one in the catalog; drop columns; rename anything; `DROP … CASCADE`; drop a relation whose name another schema shares;
- write through views that read masked columns, or read columns of table-like views computed from masked columns;
- query views missing from the catalog's view definitions;
- query relations missing from the catalog;
- expand `*` across `JOIN … USING`/`NATURAL`, or alias a join, over masked columns;
- alias a masked table's columns in `FROM` (`users AS x(a, b, c)`), or use attribute notation on it (`u.row_to_json`);
- send a statement after DDL in the same query; change `search_path` or the role other than in a query of its own that starts with `SET`, `RESET` or `DISCARD`; or call `set_config` on `search_path` (use `SET search_path`);
- use an unqualified relation name whose namesakes in other schemas have different columns or masks (qualify it);
- `EXECUTE` a statement that wasn't `PREPARE`d in the same query;
- make fast-path function calls.

Users with proxy masks also can't move proxy-masked values where PgDog can't mask them, `DECLARE` or `PREPARE` statements that use them, or place a `*` of unknown width (a function, a catalog table) before columns that carry them. See [What masked users can't do](https://ewhauser.github.io/pgdog-mask/reference/limitations/).

## Tests

Tests need Postgres on `127.0.0.1:5432` with a `pgdog` superuser (password `pgdog`) and a `pgdog` database. Override these with the usual `PG*` variables.

```bash
cargo test                       # unit tests, canary leak tests, pgdog-mask validate
bash integration/run.sh          # end-to-end and protocol matrix through PgDog
bash integration/compat.sh       # Go drivers and ORMs (pgx, pq, gorm) with every user masked
bash integration/bench/bench.sh  # pgbench: Postgres, PgDog, PgDog + plugin (see integration/bench/README.md)
```

The integration scripts build PgDog from the repository and commit `pgdog-plugin` is pinned to in `Cargo.toml`, in `.pgdog/<commit>`. Set `PGDOG_BIN` to use your own build instead.
- `compat.sh` also uses PgDog's integration suites and needs its databases (`integration/setup.sh` in PgDog's repository).
- `bench.sh` loads its own data into a `masking_bench` database and writes reports to `integration/bench/results/`. See [integration/bench/README.md](integration/bench/README.md).

`compat.sh` runs the Go integration suites through PgDog with every user masked, so every statement the drivers send is analyzed. Results should match `integration/go/run.sh`, which runs without the plugin.

The canary tests seed masked columns with unique values, run an adversarial corpus through the analyzer as a masked user, execute the result in Postgres, and fail if a canary appears anywhere in rows, errors, notices or `COPY` output. They load the schema with PgDog's own catalog queries.

## Performance

Decisions are cached per statement and masking profile, and statements that differ only in their literals share one analysis (statement shapes), so simple-protocol clients that inline values don't re-analyze every statement. Per statement, measured with `cargo bench -p pgdog-mask --bench overhead`:

| | |
|---|---|
| exempt user | ~30ns |
| masked user, cached statement | 120–320ns |
| masked user, new literals (simple protocol) | 2–6µs |
| masked user, new statement shape | 3–35µs (once per shape) |

End to end, `integration/bench/bench.sh` runs pgbench against Postgres directly, PgDog, and PgDog with the plugin for exempt and masked users, and for masked lookups with and without raw search (see [integration/bench/README.md](integration/bench/README.md)). Against PgDog without the plugin: exempt users are within noise; SQL masks cost 1–4% on point queries and joins; a 34-column `SELECT *` costs about 25% over the simple and extended protocols and 5% prepared, mostly Postgres planning the masked select list; masked lookups can't use the column's index unless the rule allows raw search; and proxy masks cost per value (within variation for 20 rows, 39–48% for 500). Full results: [Performance](https://ewhauser.github.io/pgdog-mask/operate/performance/).

## Upgrading PgDog

1. Point both `pgdog-plugin` and `pgdog-stats` in `Cargo.toml` at the new commit.
2. Copy PgDog's schema loader queries (`pgdog/src/backend/schema/{relations,columns_catalog,views,functions,operators}.sql`) into `tests/support/sql`.
3. Run the tests and `integration/run.sh`.

## Error details

Errors and notices can carry row values in their `DETAIL`, e.g. a `CHECK` violation's `Failing row contains (...)`. For masked users, the plugin removes `DETAIL` from every `ErrorResponse` and `NoticeResponse` before it reaches the client; the severity and SQLSTATE are kept. `scrub_error_detail = false` turns this off, except for users with proxy masks.

Statements that compute with proxy-masked columns run on real values, so their errors could quote them (`SELECT card::int …`). For those, and for writes to tables with proxy-masked columns, `FETCH`, `MOVE` and `EXECUTE`, PgDog replaces the message of every error and notice with a generic one, keeping the severity, SQLSTATE, position and object names.
