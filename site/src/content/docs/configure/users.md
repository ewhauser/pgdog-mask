---
title: Users and roles
description: Grant masking roles to PgDog users, and how the masking identity is determined.
---

Masking roles are a pgdog-mask concept, like Snowflake roles: they're not Postgres roles. `[[users]]` grants them to PgDog users.

```toml
[[users]]
name = "support_app"      # a PgDog user from users.toml
database = "prod"         # optional: only for this PgDog database
roles = ["support"]

[[users]]
name = "analyst"
roles = ["analytics", "eu"]
```

A user can appear several times, for example once per database; their roles are combined. Users not listed have no roles, so every policy's default mask applies to them.

## Which identity counts

The masking identity is the **PgDog user the client authenticated as**, and the PgDog database it connected to. It's fixed for the session:

- `SET ROLE` and `SET SESSION AUTHORIZATION` don't change it. PgDog acknowledges `SET` before Postgres validates it, so a client could otherwise claim any role.
- Client-supplied values such as `application_name` are never used for masking decisions.

A workload that needs different masking connects as a different PgDog user. Several PgDog users can share one Postgres user (`server_user` in `users.toml`), so this costs no extra Postgres roles.

## Exempt users

A user whose roles make every policy resolve to `mask = "none"` is exempt: their statements aren't analyzed at all. This is how administrators and trusted services see real values. It costs one profile lookup per statement, about 30 ns (see [Performance](../../operate/performance/#per-statement)).

Exemption is per policy: a rule with `mask = "none"` only exempts the user from that policy. To exempt a role from everything, give it such a rule in every policy.

## Admin connections

Connections to PgDog's admin database are never masked: they run PgDog's own commands and don't reach Postgres.
