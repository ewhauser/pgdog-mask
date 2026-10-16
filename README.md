# pgdog-masking

Dynamic data masking for PgDog, modeled on Snowflake's dynamic data masking. Design: [docs/DATA_MASKING.md](../../docs/DATA_MASKING.md).

For PgDog users with masking policies, the plugin parses each statement before PgDog does. It then resolves every column reference to `schema.table.column`, and replaces each reference to a masked column with the policy's mask expression. This applies wherever the reference appears:
- the select list, `WHERE`, `JOIN`, `GROUP BY`, `ORDER BY` and window clauses;
- `RETURNING`, subqueries and CTEs;
- `INSERT … SELECT` and `COPY`;
- views and SQL functions that read masked columns, which are inlined with masks applied.

Postgres then computes the masked values, so filters, sorting and aggregates can't reveal the real ones. Users whose policies mask nothing are passed through untouched.

## Enabling

```toml
# pgdog.toml
[[plugins]]
name = "pgdog_masking"
config = "masking.toml"
required = true   # never serve traffic without masking
```

The plugin needs PgDog's schema snapshot and loads it automatically. Masked users get an error (SQLSTATE `57P03`) until the snapshot has loaded.

## Configuration

```toml
# masking.toml
[general]
mode = "enforce"            # enforce | shadow (log decisions only) | off
on_unresolved = "block"     # relations missing from the schema snapshot
udf_allowlist = []          # functions masked users may call without analysis, e.g. "public.normalize_phone"
extension_allowlist = []    # extensions whose functions and operators are trusted, e.g. "citext"
view_allowlist = []         # views masked users may query without analysis
inline_views = true         # inline views over masked columns; false: treat views like tables
scrub_error_detail = true   # remove DETAIL from errors/notices of statements touching masked tables
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
- call functions that aren't in the schema snapshot;
- call SQL-executing built-ins such as `query_to_xml`, `dblink*` and `lo_*`;
- query `pg_stats`, `pg_statistic` or `pg_stat_statements`;
- run `DO`, DDL other than tables, `MERGE`, or `COPY … TO PROGRAM/file`;
- write through views that read masked columns, or read columns of table-like views computed from masked columns;
- query views missing from the schema snapshot's definitions;
- query relations missing from the schema snapshot;
- expand `*` across `JOIN … USING`/`NATURAL`, or alias a join, over masked columns;
- create tables that shadow a masked table;
- make fast-path function calls.

## Tests

```bash
cargo test -p pgdog-masking            # unit tests + canary leak tests (needs Postgres)
bash integration/masking/run.sh        # end-to-end through PgDog
```

The canary tests seed masked columns with unique values, run an adversarial corpus through the analyzer as a masked user, execute the result in Postgres, and fail if a canary appears anywhere in rows, errors, notices or `COPY` output. They load the schema with PgDog's own catalog queries.

## Error details

Errors and notices can carry row values in their `DETAIL`, e.g. a `CHECK` violation's `Failing row contains (...)`. For statements that read or write relations with masked columns, the plugin removes `DETAIL` from `ErrorResponse` and `NoticeResponse` before they reach the client.
