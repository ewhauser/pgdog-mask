---
title: Choose masked columns
description: Assign policies to columns directly, through tags, by column name, or from comments and security labels in the database.
---

There are three ways to say which columns a policy masks. They can be combined.

## List columns

```toml
[[masked_columns]]
database = "prod"     # optional: only in this PgDog database
schema = "public"     # optional: only in this schema
name = "users"        # optional: omit to mask the column in every table
column = "ssn"
policy = "ssn"
```

`database`, `schema` and `name` narrow where the assignment applies; omitted, they match everything. Partitions and inheritance children of a table inherit its masked columns, so querying `users_2024` directly is masked like `users`.

## Tag columns

Tags separate *what a column contains* from *how it's masked*. Map tags to policies, then tag columns:

```toml
[[tags]]
name = "pii.ssn"
policy = "ssn"

[[masked_columns]]
name = "users"
column = "ssn"
tag = "pii.ssn"       # instead of policy
```

## Classify columns by name

Classifiers tag every column whose name matches a regular expression. The expression must match the whole name.

```toml
[[classifiers]]
database = "prod"     # optional
schema = "public"     # optional
name = "users"        # optional: omit to check every table
column_regex = "ssn|social_security_number"
tag = "pii.ssn"
```

## Tags in the database

Teams that manage schema in migrations can keep tags next to the columns, in column comments or security labels. Set `tag_source`:

```toml
[general]
tag_source = "comment"          # or "security_label"; default "config": this file only
```

The database only says which columns carry a tag. What a tag means stays in this file, through `[[tags]]`:

```toml
[[tags]]
name = "pii.ssn"
policy = "ssn"
```

### Comments

With `tag_source = "comment"`, a column comment containing `pgdog:tag=<name>` tags the column. The rest of the comment is free text:

```sql
COMMENT ON COLUMN users.ssn IS 'Social security number. pgdog:tag=pii.ssn';
```

- A tag is letters, digits, `_`, `.`, `-` and `:`. It ends at any other character, and a trailing `.` or `,` isn't part of it.
- Several tags can be listed with commas, `pgdog:tag=pii.ssn,pii.gov_id`, or by repeating the marker.

### Security labels

With `tag_source = "security_label"`, the column's security label from the provider named by `security_label_provider` (default `pgdog`) holds its tags, separated by commas:

```sql
SECURITY LABEL FOR pgdog ON COLUMN users.ssn IS 'pii.ssn';
```

Postgres only accepts `SECURITY LABEL FOR pgdog` if a label provider named `pgdog` is loaded, and neither Postgres nor pgdog-mask ships one. Use an existing provider, set its name in `security_label_provider`, or write a minimal one. Comments need nothing installed.

### Which relations

Database tags apply to columns of tables, partitioned and foreign tables, views and materialized views. Partitions inherit their parent's masked columns.

### Tags that can't be resolved fail closed

If a column's tags don't resolve to exactly one policy, the column **reads as `NULL`** for every masked user, wherever it appears, and the plugin logs an error:

- a tag with no `[[tags]]` entry, such as a typo:

  ```text
  [pgdog_mask] column public.users.ssn has tags ["pii.snn"] with no [[tags]] entry; it reads as NULL for masked users
  ```

- tags that map to different policies:

  ```text
  [pgdog_mask] column public.users.ssn has tags {"pii.email", "pii.ssn"} for different policies; it reads as NULL for masked users
  ```

The same applies to a column that classifiers match with different policies. Exempt users still see the real value. A column assigned in `[[masked_columns]]` uses that assignment, whatever its database tags.

### When tag changes apply

The plugin reads tags from the catalog PgDog loads. A tag change applies when PgDog next loads the schema:

- **Through PgDog:** `COMMENT ON COLUMN` and `SECURITY LABEL … ON COLUMN` sent through PgDog reload the schema right away, like other DDL, when PgDog's `reload_schema_on_ddl` is on (the default). Masked users can't run them; an exempt user or your migration role must.
- **Directly on Postgres:** PgDog doesn't see changes made without going through it, such as migrations run against Postgres directly. They apply at the next [reload](../../operate/reload/) or restart.

Statements and prepared statements use the new tags as soon as the plugin has the new catalog.

:::caution[Removing a tag unmasks the column]
Database tags only add masking, but removing one removes the masking it added, at the next schema load. The plugin logs a warning when a tag disappears. Whoever can change a column's comment or security label can unmask it: treat that like editing this file. See the [security model](../../reference/security/).
:::

## Precedence

When several sources assign a column, `[[masked_columns]]` wins, then database tags, then classifiers. Within the configuration file:

- a tag can only be defined once in `[[tags]]`;
- a column can only be assigned once in `[[masked_columns]]` for the same database, schema and table.

Both are configuration errors, reported when the file loads.

## Don't mask sharding keys

Masking runs before PgDog routes a statement, so PgDog extracts sharding keys from the masked statement. A masked sharding key, or the tenant column in multi-tenant mode, can't be used to route: masked users' statements on that column would go to every shard, or fail. The plugin doesn't see PgDog's sharding configuration, so it can't check this for you.
