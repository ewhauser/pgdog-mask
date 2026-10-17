---
title: Reload configuration
description: Change policies without restarting PgDog, and what happens to sessions and prepared statements.
---

The plugin reloads its configuration file whenever PgDog reloads its own: on `SIGHUP`, or the admin database's `RELOAD` command.

```bash
kill -HUP $(pidof pgdog)
```

- **Invalid configuration is ignored.** If the new file doesn't parse or validate, the plugin logs the error and keeps its current configuration:

  ```text
  [pgdog_mask] failed to reload masking.toml: policy "card": unknown proxy mask "ff2"
  ```

- **New decisions apply to the next statement**, including in open sessions: the next statement each client sends is analyzed with the new policies.
- **Prepared statements are checked again** at their next execution. Some must be prepared again by the client; see [below](#prepared-statements).
- **Statements already running** finish with the masks they started with.

Plugins can't be added or removed by a reload; that needs a restart. To check which configuration is active, and what to do after a rejected reload, see [Logs and maintenance](../logs/).

## Prepared statements

A prepared statement is analyzed when it's prepared. At its next execution (`Bind`), PgDog asks the plugin again if any of these changed since:

- the plugin's configuration, by a reload;
- the catalog, after a schema load;
- the session's `search_path`.

If the statement's masked SQL is the same, it runs as before. If it's different, what happens depends on the statement:

| Statement | What happens |
| --- | --- |
| A named statement PgDog tracks, with `prepared_statements` set to `extended` (the default), `extended_anonymous` or `full` | PgDog prepares the new SQL on the server under the client's statement name. The client notices nothing. |
| The unnamed statement | The `Bind` fails with SQLSTATE `26000`. |
| Any statement with `prepared_statements = "disabled"` | The `Bind` fails with `26000`. |
| A named statement PgDog hasn't registered | The `Bind` fails with `26000`. |

`26000` says `prepared statement "…" is out of date, prepare it again`. The client must send `Parse` again, then retry. Many drivers don't do that on their own: a driver that caches prepared statements may keep failing until its cache, or the connection, is reset. If your clients use the unnamed statement or run with prepared statements disabled in PgDog, expect these errors after reloads and schema changes, and test how your driver handles them before relying on live reloads.

## Schema changes

The plugin works from the catalog PgDog loads: at startup, on reload, and after DDL sent through PgDog when its `reload_schema_on_ddl` is on (the default). DDL includes `CREATE`, `ALTER` and `DROP`, and `COMMENT ON COLUMN` and `SECURITY LABEL … ON COLUMN`, so [database tags](../../configure/columns/#when-tag-changes-apply) set through PgDog apply right away.

Changes made directly on Postgres, such as migrations that don't go through PgDog, apply at the next reload or restart. Until then, statements on relations the plugin hasn't seen are blocked for masked users, unless `on_unresolved = "allow"`, and new tags don't mask anything yet.
