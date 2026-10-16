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

- **New decisions apply immediately**, including to open sessions: the next statement each client sends is analyzed with the new policies.
- **Prepared statements are checked again** at their next execution, and PgDog re-prepares them transparently if their masked SQL changed.
- **Statements already running** finish with the masks they started with.

Plugins can't be added or removed by a reload; that needs a restart.

## Schema changes

The plugin works from the catalog PgDog loads: at startup, on reload, and after DDL sent through PgDog when its `reload_schema_on_ddl` is on (the default). DDL includes `CREATE`, `ALTER` and `DROP`, and `COMMENT ON COLUMN` and `SECURITY LABEL … ON COLUMN`, so [database tags](../../configure/columns/#when-tag-changes-apply) set through PgDog apply right away.

Changes made directly on Postgres, such as migrations that don't go through PgDog, apply at the next reload or restart. Until then, statements on relations the plugin hasn't seen are blocked for masked users, unless `on_unresolved = "allow"`, and new tags don't mask anything yet.
