---
title: Configuration
description: Every key of the plugin's configuration file.
---

The configuration file is TOML in the style of PgDog's own files: top-level `[[array tables]]`, flat keys, and the same `database`/`schema`/`name`/`column` keys as PgDog's `[[sharded_tables]]`. Unknown keys are errors.

## `[general]`

| Key | Default | Description |
| --- | --- | --- |
| `mode` | `"enforce"` | `enforce`: rewrite and block statements. `shadow`: analyze and log what would happen, without changing statements. `off`: do nothing. See [shadow mode](../../start/shadow-mode/). |
| `on_unresolved` | `"block"` | What to do when a masked user's statement references a relation that isn't in the catalog: `block` or `allow`. |
| `udf_allowlist` | `[]` | Functions masked users may call without analysis, schema-qualified, e.g. `"public.normalize_phone"`. Listing one attests that it doesn't return masked data. |
| `extension_allowlist` | `[]` | Extensions whose functions and operators masked users may call, e.g. `"citext"`. |
| `view_allowlist` | `[]` | Views masked users may query without analysis. Listing one attests that it doesn't return masked data. |
| `inline_views` | `true` | Inline views over masked columns with masks applied. `false` queries every view like a table. See [Views and functions](../../configure/views-functions/). |
| `scrub_error_detail` | `true` | Remove `DETAIL` from the errors and notices masked users get. See [Error details](../../configure/errors/). |
| `tag_source` | `"config"` | Where column tags come from besides this file: `config`, `comment` (`pgdog:tag=<name>` in column comments) or `security_label`. |
| `security_label_provider` | `"pgdog"` | Label provider read with `tag_source = "security_label"`. |
| `cache_size` | `100000` | Number of analyzed statements to cache. |

## `[[users]]`

Masking roles granted to a PgDog user. See [Users and roles](../../configure/users/).

| Key | Required | Description |
| --- | --- | --- |
| `name` | yes | PgDog user, as in `users.toml`. |
| `database` | no | PgDog database. All databases if omitted. |
| `roles` | no | Masking roles. |

## `[[policies]]`

A policy and its default mask. See [Policies and rules](../../configure/policies/).

| Key | Required | Description |
| --- | --- | --- |
| `name` | yes | Policy name. |
| `data_type` | yes | Type the policy applies to, as `information_schema.columns.data_type` spells it. |
| `arguments` | no | Names of other columns bound per masked column, for conditional masks. |
| `mask` | yes | The default [mask](../masks/), plus its keys. |
| `rules` | no | `[[policies.rules]]`, checked in order. |

### `[[policies.rules]]`

| Key | Required | Description |
| --- | --- | --- |
| `roles` | yes | The rule applies to users with any of these roles. |
| `mask` | yes | The [mask](../masks/) for them, plus its keys. |
| `search` | no | `"raw"` lets these roles [search on real values](../../configure/raw-search/). Default `"masked"`. |
| `search_operators` | no | Operators allowed in raw searches. |

`search` and `search_operators` can also be set on the policy itself, for its default mask.

## `[[masked_columns]]`

Assigns a policy to columns. See [Choose masked columns](../../configure/columns/).

| Key | Required | Description |
| --- | --- | --- |
| `column` | yes | Column name. |
| `policy` or `tag` | one of them | The policy, or a tag mapped to one in `[[tags]]`. |
| `database` | no | PgDog database. |
| `schema` | no | Schema. |
| `name` | no | Table. Every table with the column if omitted. |
| `arguments` | no | Columns of the same table bound, by position, to the policy's `arguments`. |

## `[[tags]]`

| Key | Required | Description |
| --- | --- | --- |
| `name` | yes | Tag, e.g. `pii.ssn`. |
| `policy` | yes | Policy for columns with the tag. |

## `[[classifiers]]`

Tags columns by name.

| Key | Required | Description |
| --- | --- | --- |
| `column_regex` | yes | Regular expression matched against the whole column name. |
| `tag` | yes | Tag for matching columns. |
| `database`, `schema`, `name` | no | Narrow where the classifier applies. |

## Complete example

```toml
[general]
mode = "enforce"
tag_source = "comment"

[[users]]
name = "support_app"
roles = ["support"]

[[users]]
name = "admin"
roles = ["pii_admin"]

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
search = "raw"

[[policies]]
name = "card"
data_type = "character varying"
mask = "proxy"
proxy = "ff1"
options = { key_env = "CARD_FF1_KEY" }
fallback = "partial"
keep_suffix = 4

[[tags]]
name = "pii.ssn"
policy = "ssn"

[[masked_columns]]
name = "payments"
column = "card"
policy = "card"

[[classifiers]]
column_regex = "ssn|social_security_number"
tag = "pii.ssn"
```
