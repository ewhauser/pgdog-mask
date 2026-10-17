---
title: Logs and maintenance
description: What the plugin logs and what it doesn't, how to confirm the active configuration, recover from a rejected reload, and rotate proxy mask keys.
---

The plugin logs through PgDog's logger. Every message starts with `[pgdog_mask]`.

## What's logged

| Event | Level | Example |
| --- | --- | --- |
| Configuration loaded, at startup or by a reload | `info` | `loaded 3 policies, 5 masked columns (mode: Enforce)` |
| Configuration rejected | `error` | `failed to reload masking.toml: policy "card": unknown proxy mask "ff2"` |
| Statement blocked | `warn` | `blocked statement for user "support_app": <reason> [<statement>]` |
| Statement rewritten (`enforce`) | `debug` | `rewrote statement for user "support_app", masked {"public.users.ssn"}: <statement>` |
| Statement would be rewritten (`shadow`) | `info` | `(shadow) would rewrite statement for user "support_app", …` |
| [Raw search](../../configure/raw-search/) | `info` | `user "support_app" searched raw values of {"public.users.ssn"}` |
| A [database tag](../../configure/columns/#tags-in-the-database) was removed | `warn` | `tag "pii.ssn" was removed from column public.users.ssn …` |
| A column's tags don't resolve to one policy | `error` | `column public.users.ssn has tags ["pii.snn"] with no [[tags]] entry; …` |

Statements are logged normalized, with literals replaced by placeholders. Parameter values are never logged.

## Analysis logs, not an audit trail

Statement messages (blocked, rewritten, raw search) are written when the plugin **analyzes** a statement, not each time a statement runs. Analyses are reused without logging:

- **Repeated statements.** Decisions are cached per statement, masking profile, `search_path`, and configuration and catalog version. A repeat is answered from the cache and logs nothing. Statements that differ only in their literal values share one analysis, so `WHERE id = 1` and `WHERE id = 2` produce one message between them.
- **Users with the same profile.** The cache is keyed by profile, not by user (unless the `search_path` contains `$user`). If `alice` and `bob` have the same masking roles, a statement already analyzed for `alice` runs for `bob` without a message. The user a message names is the one whose statement caused the analysis.
- **Prepared statements** are analyzed when they're prepared. Their executions aren't analyzed again unless the configuration, the catalog or the session's `search_path` has changed since.
- **Statements refused with `57P03`**, because the database's catalog hasn't loaded yet, aren't logged.

The cache starts over after a reload or a schema change, and evicts entries beyond `cache_size`, so a statement can be logged again later.

What the logs tell you is which statement shapes were blocked, rewritten or searched by raw value, and one user they were seen for. They don't say how often that happened, or every user who did it. Don't rely on them as a complete access log, or to detect someone probing a raw-search column: pgdog-mask doesn't provide a complete audit log.

### Shadow mode and proxy masks

In [shadow mode](../../start/shadow-mode/), a statement whose only masking would be done by [proxy masks](../../configure/proxy-masks/), in the results, logs no `would rewrite` message: the statement wouldn't change. The columns a `would rewrite` message lists are the ones masked in the statement, including proxy mask fallbacks; output columns a proxy mask would mask aren't listed.

## Confirm the active configuration

The plugin logs `loaded N policies, M masked columns (mode: …)` at startup and after every reload it accepts. The most recent such line describes the configuration in use. A rejected reload logs an error instead, and no `loaded` line.

The plugin has no command that prints its configuration. To check behavior, connect through PgDog as a masked user and as an exempt user and select a masked column.

## Recover from a rejected reload

When the new file doesn't parse or validate, the plugin logs why and **keeps its previous configuration** unchanged: masking continues as before the reload.

1. Read the `failed to reload` error.
2. Fix the file and reload again.
3. Check for the `loaded` line.

Fix the file before PgDog next restarts: at startup, an invalid file makes PgDog refuse to start, with `required = true`.

The plugin has no separate command to validate a file without loading it. To check a change before production, load it into a PgDog instance in a test environment.

## Rotate proxy mask keys

Proxy masks read their keys, from `key_env` or `key_file`, each time the configuration loads: at startup and at every reload.

- **`key_file`:** write the new key to the file, then reload.
- **`key_env`:** a running process's environment can't change, so a new value takes effect at the next restart. Use `key_file` for keys you want to rotate without restarting.

If the new key is missing or invalid, the reload is rejected and the old key stays in use.

A new key changes every value the mask produces: `hmac_sha256` tokens and `ff1` ciphertexts differ from before. Clients that stored masked values, or join them with older data, see the change. Statements already running finish with the old key.
