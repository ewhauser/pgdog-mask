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

Teams that manage schema in migrations can keep tags next to the columns. Set `tag_source`:

```toml
[general]
tag_source = "comment"          # or "security_label"
```

- With `comment`, a column comment containing `pgdog:tag=<name>` tags the column:

  ```sql
  COMMENT ON COLUMN users.ssn IS 'Social security number. pgdog:tag=pii.ssn';
  ```

- With `security_label`, the column's label from the provider named by `security_label_provider` (default `pgdog`) is its tag. This needs a label provider loaded in Postgres:

  ```sql
  SECURITY LABEL FOR pgdog ON COLUMN users.ssn IS 'pii.ssn';
  ```

Tags still map to policies through `[[tags]]`, so policies stay in the configuration file. The plugin reads tags from the catalog PgDog loads, so new tags apply when the schema next reloads.

:::caution[Removing a tag unmasks the column]
Database tags only add masking, but removing one removes the masking it added. The plugin logs a warning when a tag disappears between schema loads.
:::

## Precedence

When several sources assign a column, `[[masked_columns]]` wins, then database tags, then classifiers.

## Don't mask sharding keys

Masking runs before PgDog routes a statement, so PgDog extracts sharding keys from the masked statement. A masked sharding key, or the tenant column in multi-tenant mode, can't be used to route: masked users' statements on that column would go to every shard, or fail. The plugin doesn't see PgDog's sharding configuration, so it can't check this for you.
