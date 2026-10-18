---
title: Upgrade a deployment
description: Deploy a new version of pgdog-mask, and the PgDog build it needs, to running PgDog instances.
---

Each pgdog-mask commit pins the PgDog commit it's built against. PgDog skips a plugin built against another plugin API version or by another Rust compiler, and with `required = true`, refuses to start. So pgdog-mask and PgDog are always upgraded together.

1. **Build both.** Build PgDog from the commit the new pgdog-mask's `Cargo.toml` pins, and the plugin, with the toolchain in `rust-toolchain.toml`, as in [Install the plugin](../../start/install/). If you build [your own plugin](../../develop/proxy-masks/), rebuild it against the new pgdog-mask.
2. **Read what changed.** The analyzer may block or rewrite statements differently between versions, and configuration keys may change.
3. **Test with your configuration.** Start the new build with your `masking.toml` outside production. The plugin validates the file at startup; with `required = true`, PgDog doesn't start if it's invalid, and logs why. Then run your application's statements against it, ideally in [shadow mode](../../start/shadow-mode/) first, to find statements the new version would block.
4. **Deploy by restarting.** Plugins are loaded at startup, so replacing the library needs a restart; a reload doesn't load the new plugin. Replace PgDog and the plugin on each instance together, and restart them one at a time if your clients can reconnect to another instance.
5. **Check each instance.** Look for `loaded "pgdog_mask" plugin` and the plugin's `loaded … policies` line in the log; see [Logs and maintenance](../logs/#confirm-the-active-configuration).

Keep the previous PgDog binary and plugin library to roll back. Roll them back together, for the same reason.

Moving pgdog-mask itself to a new PgDog commit is a development task: see [Maintain the PgDog dependency](../../develop/pgdog-dependency/).

## Upgrading to results-only proxy masks

This version changes what [proxy masks](../../configure/proxy-masks/) do. Before, a proxy mask covered plain output columns of a single `SELECT`, and every other reference to the column got the policy's SQL `fallback`. Now references to the column are never rewritten, and the mask applies to results only. It needs plugin API 0.8, so build PgDog from the commit `Cargo.toml` pins.

1. **Remove `fallback`**, and the SQL mask keys it used, such as `keep_suffix`, from every proxy rule. The configuration is rejected while they're there: `policy "card": "fallback" was removed: …`. `search = "raw"` and `search_operators` on proxy rules are rejected too: they no longer do anything.
2. **Expect conditions to use real values.** `WHERE`, joins, `GROUP BY` and `ORDER BY` on proxy-masked columns now match and sort real values, so queries return the rows they return for unmasked users, and can use the column's indexes. Users with proxy masks can now confirm guessed values this way: check that only trusted roles get proxy masks, and give everyone else a SQL mask. See [Security model](../../configure/proxy-masks/#security-model).
3. **Expect `NULL` for computed outputs.** Outputs computed from a proxy-masked column, such as `upper(card)`, casts and aggregates, return `NULL` instead of being computed on the fallback. Subqueries, CTEs, views and `UNION`s that pass the column through now get the proxy mask instead of the fallback.
4. **Expect new blocks.** For users with proxy masks, statements that would move proxy-masked values where PgDog can't mask them, such as `INSERT … SELECT`, `UPDATE … SET`, `CREATE TABLE AS` and `COPY … TO`, are blocked instead of writing fallback values. So are SQL `DECLARE` and `PREPARE` of statements that use a proxy-masked column. SQL `EXECUTE` now needs the `PREPARE` in the same query, for every masked user. See [What masked users can’t do](../../reference/limitations/).
5. **Check shadow mode again.** Statements whose only masking is done by proxy masks now log `would mask results`, and statements with `*` in subqueries are rewritten for users with proxy masks, so they log `would rewrite`. Run your application in [shadow mode](../../start/shadow-mode/) with the new version before enforcing it.

Errors of statements that compute with proxy-masked columns are now [redacted](../../configure/errors/#per-statement-redaction), and `scrub_error_detail = false` no longer applies to users with proxy masks.

For users with proxy masks, every statement that writes, maintains, alters or commits now has its errors redacted too, whatever table it writes: triggers, constraints and defaults of any table run on real values.

This version also tightens rules for every masked user. These are blocked now:

- statements after DDL, or a `set_config` of `role`, in the same query;
- a change to `search_path` or the role that isn't a query of its own starting with `SET`, `RESET` or `DISCARD`, such as `BEGIN; SET LOCAL search_path TO app; …` sent as one query: send the `SET` on its own;
- `set_config` of `search_path` in any form, including a query of its own such as `SELECT pg_catalog.set_config('search_path', '', false)`, which `pg_dump` output contains: use `SET search_path`;
- unqualified relation names that refer to relations with different columns or masks in different schemas: qualify them;
- temporary tables and sequences, tables or sequences named like a relation in the catalog, dropping columns, renames, `DROP … CASCADE`, and dropping a relation whose name another schema shares;
- attribute notation on tables with masked columns, column alias lists over masked columns, and SQL functions that change `search_path`.

See [What masked users can’t do](../../reference/limitations/).
