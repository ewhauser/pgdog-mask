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
| `42501` | `can't place masks on the results: a * of unknown width … precedes or covers columns computed from proxy-masked columns; list the columns` | A `*` over a function, a catalog table, an aliased join of tables, `(expression).*` or a `USING`/`NATURAL` join comes before, or covers, a column carrying proxy-masked values, so the plugin can't tell where it lands. List the columns. See [Positions and `*`](../../configure/proxy-masks/#positions-and-). |
| `42501` | `INSERT would move values of proxy-masked columns (public.users.ssn) where PgDog can't mask them`, or the same for `UPDATE`, `ON CONFLICT DO UPDATE`, `COPY`, `CREATE TABLE AS`, `CREATE MATERIALIZED VIEW`, `SELECT INTO`, `EXECUTE` or a built-in such as `pg_notify()` | The statement would write, export or keep proxy-masked values somewhere results masks don't reach. Use the column in conditions only, or select it instead. See [What masked users can’t do](../../reference/limitations/#with-proxy-masks). |
| `42501` | `function public.f() can pass a parameter to a write or a side effect, so it can't be called with values of proxy-masked columns` | One of the function's parameters can reach an `INSERT`, `pg_notify` or another side effect in its body, and the call passes proxy-masked values, to that parameter or another. Pass other values, or remove the side effect. See [SQL functions](../../configure/views-functions/#sql-functions). |
| `42501` | `DECLARE CURSOR can't use proxy-masked columns: rows read through it later can't be masked; run the statement directly`, or the same for `PREPARE` | The cursor or prepared statement uses a proxy-masked column somewhere, even only in a condition. Rows fetched later through it, with a protocol `Execute` or `Bind`, would get no masks or redaction. Run the statement directly, or prepare it through your driver. See [Statements that run later](../../configure/proxy-masks/#statements-that-run-later). |
| `42501` | `statements after one that may change name resolution (search_path, role or DDL) can't be checked in the same query; send them separately` | An earlier statement in the query is DDL, or calls `set_config` on `role`. Send the later statements as separate queries. |
| `42501` | `changes to search_path or the role must be sent as a query of their own, starting with SET, RESET or DISCARD: PgDog doesn't follow them otherwise` | A `SET` or `RESET` of `search_path` or the role, `RESET ALL` or `DISCARD ALL` is in a query with other statements, or after a comment, a `;` or a lot of whitespace. Send it on its own. |
| `42501` | `"users" may refer to public.users or to backup.users, which read differently for masked users; qualify it with its schema` | Relations of the same name in several schemas have different columns or masks. Postgres may resolve the name with another `search_path` than the plugin, so write `public.users`. |
| `42501` | `EXECUTE of a statement prepared outside this query can't be checked …` | SQL `EXECUTE` only runs statements prepared by a `PREPARE` in the same query. Send both together, or prepare through your driver. See [Statements that run later](../../configure/proxy-masks/#statements-that-run-later). |
| `42501` | `set_config() can't change search_path for masked users: PgDog may not follow the change; use SET search_path` | PgDog doesn't follow a `search_path` set with `set_config` while its query parser is off, so the plugin would analyze later statements with the wrong path. Use `SET search_path`. |
| `42501` | `masked users can't create temporary relations: …`, `creating "…" would shadow …`, `masked users can't drop columns: …`, `masked users can't rename …`, `masked users can't DROP ... CASCADE …` or `masked users can't drop "…", whose name other relations share: …` | The DDL would make a name resolve to a relation or column other than the one in the plugin's catalog, until PgDog reloads it. Choose another name, or run the DDL as an exempt user. See [What masked users can’t do](../../reference/limitations/#statements). |
| `42501` | `u.row_to_json calls row_to_json() on the whole row of u, which carries masked columns; write row_to_json(u)` | Attribute notation calls a function on the whole row without the plugin's checks. Write the call explicitly. |
| `42501` | `s.case may name a column of s without an AS name, or call case() on its whole row, which carries masked columns; name the column with AS` | Postgres doesn't always name such a column the same way, so the plugin can't tell what `s.case` reads. Name the column with `AS` in the subquery. |
| `42501` | `function public.f() reads proxy-masked columns and is IMMUTABLE: the planner can compute the result in advance, and EXPLAIN would show it`, or `… calls an IMMUTABLE function that reads proxy-masked columns …` | `EXPLAIN` of a call to such a function would print its result in the plan. Mark the function `STABLE`, or run the statement without `EXPLAIN`. |
| `42501` | `DDL expressions would store values computed from proxy-masked columns` | A default, generated column, check, `USING` clause or index expression reads proxy-masked columns, directly or through a function. |
| `42501` | `a COPY option is missing its value or has one of the wrong type` | Postgres would reject the option too, e.g. `WITH (delimiter)`. Give it a value. |
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
