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

The plugin works from the catalog PgDog loads at startup and on reload, or after DDL when PgDog's `reload_schema_on_ddl` is on. New tables and columns, view definitions, functions, and [database tags](../../configure/columns/#tags-in-the-database) take effect when PgDog next loads the schema. Statements on relations the plugin hasn't seen yet are blocked for masked users, unless `on_unresolved = "allow"`.
