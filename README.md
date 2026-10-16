# pgdog-mask

Dynamic data masking for [PgDog](https://github.com/pgdogdev/pgdog), modeled on Snowflake's dynamic data masking. Design: [docs/DESIGN.md](docs/DESIGN.md).

For PgDog users with masking policies, the plugin parses each statement before PgDog does. It then resolves every column reference to `schema.table.column`, and replaces each reference to a masked column with the policy's mask expression. This applies wherever the reference appears:
- the select list, `WHERE`, `JOIN`, `GROUP BY`, `ORDER BY` and window clauses;
- `RETURNING`, subqueries and CTEs;
- `INSERT … SELECT` and `COPY`;
- views and SQL functions that read masked columns, which are inlined with masks applied.

Postgres then computes the masked values, so filters, sorting and aggregates can't reveal the real ones. Users whose policies mask nothing are passed through untouched.

## Requirements

The plugin uses PgDog's plugin API 0.7 (statement, error and catalog hooks), which lives on [`ewhauser/pgdog`](https://github.com/ewhauser/pgdog) (branch `masking/plugin-api`) until it's upstream. `Cargo.toml` pins `pgdog-plugin` to a commit there.

PgDog only loads plugins with the same plugin API version that were built by the same Rust compiler. Build PgDog from the pinned commit with the same toolchain as this plugin. `rust-toolchain.toml` matches PgDog's.

## Building

```bash
cargo build --release
# target/release/libpgdog_mask.so (Linux) or libpgdog_mask.dylib (macOS)
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

Database tags only add masking: `[[masked_columns]]` wins, then database tags, then classifiers. Tags that disappear between schema loads are logged at `warn`, since that unmasks a column.

### Views and functions

A view whose definition reads masked columns is inlined: `FROM v` becomes `FROM (<definition>) AS v(...)`, masked like any subquery. `security_barrier` and `security_invoker` views, materialized views, views with masked columns of their own, and all views with `inline_views = false` are queried like tables: columns passed through from masked columns get their masks, and columns computed from masked columns are blocked unless they're assigned a policy.

SQL functions are analyzed. A function that reads no masked columns is called as is. One that does is inlined with masks applied if it's a single `SELECT`, `IMMUTABLE` or `STABLE`, not `SECURITY DEFINER`, has no `SET` options, and isn't polymorphic or variadic. Set-returning functions are inlined in `FROM`. User-defined operators are treated as calls to their functions.

Built-in masks are `none`, `null`, `constant` (`value`), `default`, `partial` (`keep_prefix`, `keep_suffix`, `fill`), `email`, `hash`, `round` (`digits`), `truncate` (`unit`), and `sql` (`expression`, over `val` and the policy's `arguments`). Every mask is cast back to the column's type.

### Raw search

`search = "raw"` lets a role find rows by a masked column's real value: `WHERE ssn = $1`, `IN`, `= ANY`, `IS NULL`, `IS DISTINCT FROM`, optionally wrapped in `lower`/`upper`/`trim`. Results are still masked. This deliberately allows guessing a value and confirming it. It does not allow extracting values: casts, arbitrary functions, and other expressions around the column remain masked. Range and `LIKE` operators are opt-in via `search_operators` because they let a value be recovered quickly. Every raw search is logged.

## What masked users can't do

All of these fail closed with SQLSTATE `42501`:
- call functions in procedural languages or C, extension functions and operators, and SQL functions that read masked columns but can't be inlined, unless they're in `udf_allowlist` or `extension_allowlist`;
- call functions that aren't in the catalog;
- call SQL-executing built-ins such as `query_to_xml`, `dblink*` and `lo_*`;
- query `pg_stats`, `pg_statistic` or `pg_stat_statements`;
- run `DO`, `MERGE`, `COPY … TO PROGRAM/file`, or DDL other than creating tables, `DROP`, sequences, and `ALTER TABLE`/`CREATE INDEX`/renames of relations without masked columns. DDL on masked relations is blocked: expressions in `ALTER … USING` or index definitions can leak values through errors, renames would unmask columns, and `ATTACH PARTITION`/`INHERIT` would expose their rows through another table;
- write through views that read masked columns, or read columns of table-like views computed from masked columns;
- query views missing from the catalog's view definitions;
- query relations missing from the catalog;
- expand `*` across `JOIN … USING`/`NATURAL`, or alias a join, over masked columns;
- create tables that shadow a masked table;
- make fast-path function calls.

## Tests

Tests need Postgres on `127.0.0.1:5432` with a `pgdog` superuser (password `pgdog`) and a `pgdog` database. Override these with the usual `PG*` variables.

```bash
cargo test                       # unit tests + canary leak tests
bash integration/run.sh          # end-to-end through PgDog
bash integration/compat.sh       # Go drivers and ORMs (pgx, pq, gorm) with every user masked
bash integration/bench/bench.sh  # pgbench: Postgres, PgDog, PgDog + plugin
```

The integration scripts build PgDog from the repository and commit `pgdog-plugin` is pinned to in `Cargo.toml`, in `.pgdog/<commit>`. Set `PGDOG_BIN` to use your own build instead.
- `compat.sh` also uses PgDog's integration suites and needs its databases (`integration/setup.sh` in PgDog's repository).
- `bench.sh` needs `pgbench -i -s 20 masking_bench` and `integration/bench/setup.sql`.

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

End to end, `integration/bench/bench.sh` runs pgbench against Postgres, PgDog, and PgDog with the plugin for exempt and masked users. Prepared statements and point queries show no measurable overhead. A 34-column `SELECT table.*` with masked columns over the simple protocol runs about 16% slower for masked users. Most of that is Postgres planning and evaluating the expanded, masked select list, which `*` expansion requires.

## Upgrading PgDog

1. Point both `pgdog-plugin` and `pgdog-stats` in `Cargo.toml` at the new commit.
2. Copy PgDog's schema loader queries (`pgdog/src/backend/schema/{relations,columns_catalog,views,functions,operators}.sql`) into `tests/support/sql`.
3. Run the tests and `integration/run.sh`.

## Error details

Errors and notices can carry row values in their `DETAIL`, e.g. a `CHECK` violation's `Failing row contains (...)`. For statements that read or write relations with masked columns, the plugin removes `DETAIL` from `ErrorResponse` and `NoticeResponse` before they reach the client.
