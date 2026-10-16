# pgdog-masking

Dynamic data masking for PgDog, modeled on Snowflake's dynamic data masking. Design: [docs/DATA_MASKING.md](../../docs/DATA_MASKING.md).

For PgDog users with masking policies, the plugin parses each statement before PgDog does. It then resolves every column reference to `schema.table.column`, and replaces each reference to a masked column with the policy's mask expression. This applies wherever the reference appears:
- the select list, `WHERE`, `JOIN`, `GROUP BY`, `ORDER BY` and window clauses;
- `RETURNING`, subqueries and CTEs;
- `INSERT … SELECT` and `COPY`.

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
udf_allowlist = []          # user-defined functions masked users may call, e.g. "public.normalize_phone"
view_allowlist = []         # views masked users may query without masking their columns
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
```

Built-in masks are `none`, `null`, `constant` (`value`), `default`, `partial` (`keep_prefix`, `keep_suffix`, `fill`), `email`, `hash`, `round` (`digits`), `truncate` (`unit`), and `sql` (`expression`, over `val` and the policy's `arguments`). Every mask is cast back to the column's type.

### Raw search

`search = "raw"` lets a role find rows by a masked column's real value: `WHERE ssn = $1`, `IN`, `= ANY`, `IS NULL`, `IS DISTINCT FROM`, optionally wrapped in `lower`/`upper`/`trim`. Results are still masked. This deliberately allows guessing a value and confirming it. It does not allow extracting values: casts, arbitrary functions, and other expressions around the column remain masked. Range and `LIKE` operators are opt-in via `search_operators` because they let a value be recovered quickly. Every raw search is logged.

## What masked users can't do

All of these fail closed with SQLSTATE `42501`:
- call user-defined functions not in `udf_allowlist`;
- call SQL-executing built-ins such as `query_to_xml`, `dblink*` and `lo_*`;
- query `pg_stats`, `pg_statistic` or `pg_stat_statements`;
- run `DO`, DDL other than tables, `MERGE`, or `COPY … TO PROGRAM/file`;
- query views that aren't allowlisted and don't have masked columns of their own;
- query relations missing from the schema snapshot;
- expand `*` across `JOIN … USING`/`NATURAL`, or alias a join, over masked columns;
- create tables that shadow a masked table;
- make fast-path function calls.

## Tests

```bash
cargo test -p pgdog-masking            # unit tests + canary leak tests (needs Postgres)
bash integration/masking/run.sh        # end-to-end through PgDog
```

The canary tests seed masked columns with unique values, run an adversarial corpus through the analyzer as a masked user, execute the result in Postgres, and fail if a canary appears anywhere in rows, errors or `COPY` output.
