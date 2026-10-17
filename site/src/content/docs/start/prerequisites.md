---
title: Prerequisites
description: The versions pgdog-mask needs, and what your deployment must enforce for masking to protect anything.
---

Check these before you install, and again before you put masked users on production traffic.

## Versions

- **PgDog**, built from the commit pgdog-mask's `Cargo.toml` pins, on the [`ewhauser/pgdog`](https://github.com/ewhauser/pgdog/tree/masking/plugin-api) fork. Upstream PgDog doesn't have the plugin API pgdog-mask needs.
- **Rust**, the toolchain in `rust-toolchain.toml`, for both PgDog and the plugin.
- **Postgres** 14 or later. CI tests Postgres 16.
- **Linux or macOS.**

Details are in [compatibility](../../reference/compatibility/).

## What your deployment must enforce

The plugin only sees statements that go through PgDog, and only masks what its configuration says. Masking protects data only if:

1. **Clients can't reach Postgres directly.** Enforce it with network policy and credentials.
2. **The Postgres role masked users run as doesn't own the masked tables, and can't create functions or views.** This limits the damage if the analyzer has a bug.
3. **The configuration file and proxy mask keys are protected like credentials.** Whoever can change them can unmask any column.
4. **Column comments and security labels are protected like configuration**, if you take tags from the database (`tag_source`). Removing a tag unmasks its column.
5. **PgDog loads the plugin with `required = true`**, so it doesn't serve traffic without masking.
6. **No masked column is a sharding key** or PgDog's tenant column. The plugin can't check this. See [Choose masked columns](../../configure/columns/#dont-mask-sharding-keys).

The [security model](../../reference/security/) explains each assumption, and what masking doesn't cover even when they hold.

Next: [install the plugin](../install/).
