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
| `42501` | `can't place masks on the results: a * of unknown width … precedes or covers columns computed from proxy-masked columns; list the columns` | A `*` over a function, a catalog table, `(expression).*` or a `USING`/`NATURAL` join comes before, or covers, a column carrying proxy-masked values, so the plugin can't tell where it lands. List the columns. See [Positions and `*`](../../configure/proxy-masks/#positions-and-). |
| `42501` | `INSERT would move values of proxy-masked columns (public.users.ssn) where PgDog can't mask them`, or the same for `UPDATE`, `COPY`, `CREATE TABLE AS`, `SELECT INTO`, `DECLARE CURSOR`, `PREPARE` or a function | The statement would write, export or keep proxy-masked values somewhere results masks don't reach. Use the column in conditions only, or select it instead. See [What masked users can’t do](../../reference/limitations/#with-proxy-masks). |
| `42501` | `statements after one that may change name resolution (search_path, role or DDL) can't be checked in the same query; send them separately` | An earlier statement in the query changes `search_path` or the role, or is DDL. Send the later statements as separate queries. |
| `42501` | `EXECUTE of a statement prepared outside this query can't be checked …` | SQL `EXECUTE` only runs statements prepared by a `PREPARE` in the same query. Send both together, or prepare through your driver. See [Statements that run later](../../configure/proxy-masks/#statements-that-run-later). |
| `42501` | `set_config() can only change search_path as a query of its own, SELECT set_config('search_path', '…', false); use SET search_path` | PgDog only tracks `SET search_path` and that exact query, so the plugin would analyze later statements with the wrong path. |
| `42501` | `u.row_to_json calls row_to_json() on the whole row of u, which carries masked columns; write row_to_json(u)` | Attribute notation calls a function on the whole row without the plugin's checks. Write the call explicitly. |
| `42501` | `DDL expressions would store values computed from proxy-masked columns` | A default, generated column, check, `USING` clause or index expression reads proxy-masked columns, directly or through a function. |
| original | `error message removed: the statement reads values this user can't see` | Not an error of the plugin: Postgres raised an error in a statement that computes with proxy-masked columns, and PgDog replaced its message. The SQLSTATE, position and object names are the original ones. See [Per-statement redaction](../../configure/errors/#per-statement-redaction). |
| `26000` | `prepared statement "…" does not exist` | The client bound or described a statement name it didn't prepare through PgDog. Prepare it on this connection first. |
| `26000` | `prepared statement "…" is out of date, prepare it again` | The configuration, the schema or the session's `search_path` changed, the statement's masked SQL is different now, and PgDog couldn't re-prepare it under its name. Prepare it again. See [Reload configuration](../reload/#prepared-statements). |
| `XX000` (`FATAL`) | `plugin "…" failed to process the query results` | A [proxy mask](../../configure/proxy-masks/) failed. The connection is closed; PgDog's log has the mask's error. |
| `XX000` | `plugin "…" rewrote a prepared statement with different parameters` | A bug in the plugin's rewrite. Please report it with the statement. |

Blocked statements are logged at `warn` with the user, the reason, and the statement with its literals removed. A statement is logged when it's analyzed, so repeats and other users with the same masking profile may not add a message; see [what the logs cover](../logs/#analysis-logs-not-an-audit-trail).

## Results look wrong

- **A column isn't masked.** Check that the user isn't exempt (`[[users]]` roles and the policy's rules), and that the column's assignment matches its database, schema and table. For a [database tag](../../configure/columns/#tags-in-the-database), check that `tag_source` is set, and that PgDog has loaded the schema since the tag was added: tags set directly on Postgres need a reload.
- **A column reads as `NULL` for everyone masked.** Its tags don't resolve to one policy: a tag without a `[[tags]]` entry, or tags or classifiers for different policies. The plugin logs which, at `error`.
- **A query finds nothing.** Conditions on SQL-masked columns compare masked values. Use [raw search](../../configure/raw-search/) for roles that need to look rows up. Conditions on proxy-masked columns compare real values.
- **Ordering changed.** `ORDER BY` a SQL-masked column sorts by the mask. Proxy-masked columns sort by their real values.
- **A column is `NULL`.** For users with proxy masks, outputs computed from a proxy-masked column return `NULL`: functions, casts, aggregates, window functions, scalar subqueries, and `UNION` with a branch that returns something else. Select the column itself to get the proxy mask. See [Proxy masks](../../configure/proxy-masks/#how-proxy-masks-apply).
- **An error has no message.** See the `error message removed` row above.
