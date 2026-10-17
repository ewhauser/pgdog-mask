---
title: Mask your first column
description: Write a policy, assign it to a column, and check the result as a masked and an exempt user.
---

This walkthrough masks the `ssn` column of the sample database from [Install the plugin](../install/) for every PgDog user except `admin`. Run the commands from the same working directory, with PgDog running.

## 1. Write the configuration

Replace `masking.toml` with:

```toml
[general]
mode = "enforce"

[[users]]
name = "admin"            # a PgDog user from users.toml
roles = ["pii_admin"]

[[policies]]
name = "ssn"
data_type = "text"
mask = "partial"          # the default mask
keep_suffix = 4

[[policies.rules]]
roles = ["pii_admin"]
mask = "none"             # admins see real values

[[masked_columns]]
schema = "public"
name = "users"
column = "ssn"
policy = "ssn"
```

- `[[users]]` grants masking roles to PgDog users. Users not listed, like `support`, have no roles, so every policy's default mask applies to them.
- `[[policies]]` defines a mask. Its top-level `mask` is the default; `[[policies.rules]]` override it for some roles. The first rule whose roles match wins.
- `[[masked_columns]]` assigns the policy to a column.

## 2. Reload

Tell PgDog to reload its configuration; the plugin reloads its file with it:

```bash
kill -HUP $(pgrep -x pgdog)
```

PgDog's log should show the new configuration:

```text
[pgdog_mask] loaded 1 policies, 1 masked columns (mode: Enforce)
```

If the file is invalid, the plugin logs why and keeps its previous configuration. See [Reload configuration](../../operate/reload/).

## 3. Check as a masked user

Connect as `support`:

```bash
psql "postgres://support:support@127.0.0.1:6432/masking_demo"
```

```sql
SELECT id, ssn FROM users ORDER BY id;
```

```text
 id |     ssn
----+-------------
  1 | *******6789
  2 | *******1234
```

The mask applies wherever the column appears in the statement:

```sql
SELECT count(*) FROM users WHERE ssn = '123-45-6789';   -- 0: compares masked values
SELECT max(ssn) FROM users;                             -- the maximum masked value
SELECT * FROM users;                                    -- ssn is masked
```

## 4. Check as the administrator

```bash
psql "postgres://admin:admin@127.0.0.1:6432/masking_demo" -c "SELECT id, ssn FROM users ORDER BY id"
```

`admin`'s profile masks nothing, so their statements reach Postgres unchanged and they see real values.

## Next steps

- Read the [prerequisites](../prerequisites/) for production, then roll out with [shadow mode](../shadow-mode/).
- Choose columns by [tag, classifier or database comment](../../configure/columns/) instead of listing each one.
- See every mask in the [mask reference](../../reference/masks/).
