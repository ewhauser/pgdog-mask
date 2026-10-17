---
title: Troubleshoot
description: Errors masked users and operators see, what they mean, and what to do.
---

## The plugin doesn't load

PgDog logs why it skipped a plugin. With `required = true`, it then refuses to start.

| PgDog says | Cause | Fix |
| --- | --- | --- |
| `it was compiled with a different plugin API version` | PgDog and the plugin were built from different `pgdog-plugin` versions. | Build PgDog from the commit `Cargo.toml` pins. See [compatibility](../../reference/compatibility/). |
| `it was compiled with a different compiler version` | Different Rust toolchains. | Build both with `rust-toolchain.toml`'s toolchain. |
| `shared library could not be opened` | PgDog can't find the library. | Put it in `LD_LIBRARY_PATH` (`DYLD_LIBRARY_PATH` on macOS), or use its full path as `name`. |
| `another plugin already implements the statement hook` | Only one plugin can rewrite statements. | Load one masking plugin: `pgdog_mask` or your own build, not both. |
| `it failed to load its configuration` | The configuration file is invalid. The plugin logs the reason first, prefixed with `[pgdog_mask]`. | Fix the file. |

## Errors masked users get

| SQLSTATE | Message | Meaning |
| --- | --- | --- |
| `57P03` | `masking schema for database "…" is not loaded yet` | PgDog hasn't loaded the catalog for this database yet. It's retried on the next statement. If it persists, check PgDog's log for schema loading errors. |
| `42501` | varies, e.g. `function public.f() is written in plpgsql and can't be analyzed; add it to udf_allowlist if it's safe` | The statement can't be proven safe for this user. See [What masked users can’t do](../../reference/limitations/). |
| `26000` | `prepared statement "…" is out of date, prepare it again` | The configuration, the schema or the session's `search_path` changed, the statement's masked SQL is different now, and PgDog couldn't re-prepare it under its name. Prepare it again. See [Reload configuration](../reload/#prepared-statements). |
| `XX000` (`FATAL`) | `plugin "…" failed to process the query results` | A [proxy mask](../../configure/proxy-masks/) failed. The connection is closed; PgDog's log has the mask's error. |
| `XX000` | `plugin "…" rewrote a prepared statement with different parameters` | A bug in the plugin's rewrite. Please report it with the statement. |

Blocked statements are logged at `warn` with the user, the reason, and the statement with its literals removed. A statement is logged when it's analyzed, so repeats and other users with the same masking profile may not add a message; see [what the logs cover](../logs/#analysis-logs-not-an-audit-trail).

## Results look wrong

- **A column isn't masked.** Check that the user isn't exempt (`[[users]]` roles and the policy's rules), and that the column's assignment matches its database, schema and table. For a [database tag](../../configure/columns/#tags-in-the-database), check that `tag_source` is set, and that PgDog has loaded the schema since the tag was added: tags set directly on Postgres need a reload.
- **A column reads as `NULL` for everyone masked.** Its tags don't resolve to one policy: a tag without a `[[tags]]` entry, or tags or classifiers for different policies. The plugin logs which, at `error`.
- **A query finds nothing.** Conditions on masked columns compare masked values. Use [raw search](../../configure/raw-search/) for roles that need to look rows up.
- **Ordering changed.** `ORDER BY` a masked column sorts by the mask.
