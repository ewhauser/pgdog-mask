---
title: Security model
description: What pgdog-mask protects against, and what your deployment must enforce.
---

## What it's designed to protect

The goal: a client connected through PgDog as a masked user, sending arbitrary SQL, can't read the values of masked columns, not directly, and not by inference through filters, ordering, aggregates, errors, side tables, statistics, functions, views, `COPY` or cursors. The plugin rewrites what it can mask and blocks what it can't prove safe.

[Proxy masks](#proxy-masks) are the exception, by design: their conditions, joins and ordering run on real values, so inference through them is allowed. Their values still never reach the client.

That's the intended guarantee, and it holds only:

- in `enforce` mode: `shadow` and `off` change nothing;
- under the deployment assumptions below;
- with the exceptions under [known limits](#known-limits), including raw search and proxy masks, which deliberately allow confirming guesses.

Leaks are tested directly: the canary suite seeds masked columns with unique values, runs an adversarial corpus as a masked user against Postgres, and fails if a canary appears anywhere in rows, errors, notices or `COPY` output. Tests show the absence of the leaks they try, not of every leak: an analyzer bug could still let a statement through. That's why the deployment assumptions include defense in depth.

## What your deployment must enforce

1. **Clients can't reach Postgres directly.** Masking only applies to connections through PgDog. Enforce this with network policy and credentials.
2. **The Postgres role masked users run as doesn't own the masked tables, and can't create functions or views.** This is defense in depth, should the analyzer have a bug: a role that can't create code can't hide a leak in it.
3. **Configuration and keys are protected like credentials.** Whoever can change the configuration can unmask any column. Keep proxy mask keys in environment variables or files readable only by PgDog.
4. **Column comments and security labels are protected like configuration**, with `tag_source = "comment"` or `"security_label"`. Removing a tag unmasks its column. Masked users can't change them through PgDog, but table owners and migrations can.
5. **PgDog runs with `required = true`** for the plugin, so it doesn't serve traffic without masking.
6. **No masked column is a sharding key** or PgDog's tenant column. The plugin doesn't see PgDog's sharding configuration and can't check this. See [Choose masked columns](../../configure/columns/#dont-mask-sharding-keys).
7. **PgDog is built from the commit pgdog-mask pins** (see [compatibility](../compatibility/)). pgdog-mask relies on PgDog's own guarantees there. For example, with a statement plugin loaded, PgDog refuses a `Bind` or `Describe` of a prepared statement the client didn't prepare through it, with `26000`. Server connections hold other clients' statements under PgDog's own names, and binding one directly would run it without the plugin's decision: no rewrite, no masks.

## Identity

Masking decisions use the PgDog user the client authenticated as. `SET ROLE` and client-supplied values such as `application_name` don't change them. See [Users and roles](../../configure/users/#which-identity-counts).

## Proxy masks

[Proxy masks](../../configure/proxy-masks/) trade inference for the real plan:

- **Clients never receive proxy-masked values.** Output columns that pass the column through get the proxy mask, outputs computed from it return `NULL`, statements that would move values where PgDog can't mask them are blocked, and the error messages of statements that compute with them are [redacted](../../configure/errors/#per-statement-redaction).
- **Clients can infer them.** The plugin doesn't rewrite references to proxy-masked columns, so `WHERE`, joins, `GROUP BY` and `ORDER BY` run on real values. A condition confirms a guess, `LIKE` or range conditions recover a value quickly, and ordering ranks rows by it.
- **Use them for trusted roles**, such as engineers who debug production queries or need `EXPLAIN` to show the real plan. Give everyone else a SQL mask.
- **Errors and timing.** Whether a statement fails, and how long it takes, can depend on real values, and are accepted channels. Message contents are redacted.
- **Positions.** PgDog masks result columns by position. The plugin places each mask at a position that depends only on the statement's text, and blocks statements where a `*` of unknown width would make that impossible.

## Known limits

- **Inference from unmasked columns** correlated with masked ones.
- **Timing side channels.**
- **Raw search** deliberately allows confirming guesses, for the roles you give it to. See [Search on masked columns](../../configure/raw-search/#what-youre-allowing).
- **Proxy masks** deliberately allow inference through conditions, joins and ordering, for the roles you give them to. See [Proxy masks](#proxy-masks).
- **Copies of masked data** elsewhere, unmasked: denormalized columns, stored generated columns computed from masked columns, JSON documents, audit tables, or tables exempt users fill. They must carry policies of their own. Classifiers help find columns by name.
- **Messages raised during reads.** With proxy masks, a row security policy, or a function in a view the user reads, that raises an error or notice quoting a proxy-masked value isn't redacted when the statement doesn't compute with proxy-masked columns. Statements that write, maintain, alter or commit are always redacted, which covers triggers, constraints and defaults of every table, and deferred triggers firing at `COMMIT`.
- **A stale catalog.** The plugin resolves names with the catalog PgDog loaded. DDL run directly on Postgres, such as a migration that drops or renames a column, leaves it stale until PgDog reloads its schema, and a column reference may then resolve differently in Postgres. Masked users can't run such DDL through PgDog, nor create temporary relations, which the plugin can't see. Run migrations through PgDog with `reload_schema_on_ddl` on, or reload after them.
- **The server's `search_path`.** PgDog doesn't follow every change to a session's `search_path`, and can leave a change on a pooled server connection for the next client. The plugin blocks the changes PgDog misses, and requires unqualified relation names to read the same in every schema that has them. Unqualified calls of user-defined operators, and of functions named like built-ins, still resolve with the session's `search_path` as PgDog reports it.
- **Allowlisted code** (`udf_allowlist`, `extension_allowlist`, `view_allowlist`) runs without analysis. Only list code that can't return masked data.
- **Auditing.** The plugin's logs record analysis decisions, not every execution, so they can't show every access to a masked column or every raw search. See [Logs and maintenance](../../operate/logs/#analysis-logs-not-an-audit-trail).
