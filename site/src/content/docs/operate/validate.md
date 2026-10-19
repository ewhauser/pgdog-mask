---
title: Validate a configuration
description: Check masking.toml against a database before PgDog loads it, locally or in CI, with pgdog-mask validate.
---

When the plugin loads `masking.toml`, it checks what it can without a database: unknown keys, mask and type compatibility, proxy mask options, and that every SQL mask parses and only references `val` and the policy's arguments. A mask with a type error, such as `val + 1` on a `text` column, still loads, and fails with an error when a masked user's statement uses it.

`pgdog-mask validate` adds the checks that need the database. Run it before deploying or reloading a change, and in CI:

```bash
pgdog-mask validate masking.toml --url "postgres://pgdog:pgdog@127.0.0.1:5432/app"
```

```text
error: policy "plus", default mask on data_type text, public.users.ssn: operator does not exist: text + integer (in SELECT (val + 1)::text FROM (SELECT NULL::text AS val) s LIMIT 0)
warning: [[masked_columns]] public.users.phone: public.users has no column "phone" in database "app", so it masks nothing
masking.toml: 1 error, 1 warning (6 mask checks prepared against database "app")
```

It's built with the plugin: `cargo build --release` writes `target/release/pgdog-mask` next to the library.

## What it checks

- **Everything the plugin checks when it loads the file.** It reports every error, not only the first.
- **Every SQL mask, against the database.** Each mask is prepared, not run, as `SELECT (<mask>)::T FROM (SELECT NULL::T AS val) s LIMIT 0`: once for the policy's `data_type`, and once for each column type it's applied to, with the policy's arguments typed by the columns bound to them. Postgres reports unknown functions, operators and casts as it would for a masked user's statement. Columns get their masks from `[[masked_columns]]`, database tags and `[[classifiers]]`, resolved as the plugin resolves them.
- **Assignments against the catalog.** It warns about `[[masked_columns]]` entries whose table or column doesn't exist, and `[[classifiers]]` that match no column, since they mask nothing. Arguments bound to columns the table doesn't have, or a policy with arguments that a column gets without them (through a tag or a classifier), are errors.
- **Tags that fail closed.** It warns about columns that read as `NULL` for every masked user because their database tags have no `[[tags]]` entry or map to different policies, or because classifiers for different policies match them.
- **Risky raw searches.** It warns about rules with [`search = "raw"`](../../configure/raw-search/#what-youre-allowing) that allow range (`<`, `BETWEEN`) or pattern (`LIKE`) operators, or apply to `date`, `boolean` or enum columns, whose values can be found by trying each possible one.

It doesn't check whether masked sharding keys or tenant columns would break PgDog's routing: the plugin can't see PgDog's sharding configuration.

## Options

| Option | Meaning |
| --- | --- |
| `--url <URL>` | The Postgres database to check against, as a URL or a `key=value` connection string. Without it, the `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD` and `PGDATABASE` variables are used; their defaults are `localhost`, `5432`, and the current user's name for both the user and the database. TLS isn't supported. |
| `--database <NAME>` | The PgDog database name that `database` keys in `[[masked_columns]]` and `[[classifiers]]` are matched against. Defaults to the Postgres database's name. |
| `--skip-proxy-masks` | Don't build [proxy masks](../../configure/proxy-masks/). Building them reads their keys, from `key_env` or `key_file`, which CI often doesn't have. Their other settings are still checked. |
| `--deny-warnings` | Fail on warnings too. |

Connect as the `server_user` PgDog uses, to the database PgDog serves, or to a copy with the same schema. Masks are prepared with that role's privileges and `search_path`, as statements through PgDog are.

Proxy masks from [your own plugin](../../develop/proxy-masks/) aren't built into `pgdog-mask`, so their options aren't checked; it says so with a `note`.

## Exit status

| Status | Meaning |
| --- | --- |
| `0` | No errors, and no warnings with `--deny-warnings`. |
| `1` | The configuration has errors, or warnings with `--deny-warnings`. |
| `2` | The checks couldn't run: a usage error, or the database couldn't be reached or read. |

## In CI

Load your schema into a scratch database, as your migrations do, then validate against it:

```bash
psql -v ON_ERROR_STOP=1 -f schema.sql
pgdog-mask validate masking.toml --skip-proxy-masks --deny-warnings
```

## Warnings when the plugin loads

The plugin logs the raw-search warnings it can tell from the file alone, at `warn`, each time it loads the configuration: rules that allow range or pattern operators, and rules on policies whose `data_type` is `date` or `boolean`. Column types and the catalog are only checked by `pgdog-mask validate`.
