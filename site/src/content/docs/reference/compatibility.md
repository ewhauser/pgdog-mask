---
title: Compatibility
description: The PgDog, Rust and Postgres versions pgdog-mask works with.
---

## PgDog

pgdog-mask needs PgDog's plugin API **0.8**: statement verdicts, column masks (including `NULL` masks), error redaction (for every error, and per statement) and the typed catalog. It's only on the [`masking/plugin-api`](https://github.com/ewhauser/pgdog/tree/masking/plugin-api) branch of the `ewhauser/pgdog` fork. It has been proposed upstream in [pgdogdev/pgdog#1835](https://github.com/pgdogdev/pgdog/issues/1835), but there's no guarantee it will be accepted, or accepted in this form: the API, and pgdog-mask with it, may have to change.

`Cargo.toml` pins the exact commit: the `rev` of `pgdog-plugin`. Build PgDog from that commit. PgDog checks the plugin API version (major and minor) when it loads a plugin, and skips plugins built for another one.

Besides the API, pgdog-mask relies on PgDog behavior at that commit:

- results of a query with several statements are numbered by statement, including statements PgDog answers itself, such as `SET`;
- with a statement plugin loaded, a `Bind` or `Describe` of a prepared statement the client didn't prepare through PgDog is refused with `26000`, so a client can't run another client's server-side statement without the plugin's decision;
- `SET search_path`, sent as a query of its own, updates the session's `search_path`, which the plugin analyzes statements with. PgDog doesn't follow every other change to it, and can leave one on a pooled server connection: the plugin blocks the changes it misses, and resolves unqualified relation names only when they read the same in every schema (see [Security model](../security/#known-limits)).

## Rust

PgDog only loads plugins built by the same Rust compiler, because plugins share Rust types with it. Build PgDog and the plugin, or [your own plugin](../../develop/proxy-masks/), with the toolchain in `rust-toolchain.toml`: currently Rust **1.96**.

## Postgres

| | |
| --- | --- |
| Tested | Postgres 16, in CI and in the [benchmark](../../operate/performance/). |
| Supported | Postgres 14 and later. Earlier versions aren't tested. |
| `BEGIN ATOMIC` functions | SQL functions with `BEGIN ATOMIC` bodies, which Postgres 14 introduced, are analyzed from the body Postgres stores. |
| Security labels | `tag_source = "security_label"` needs a label provider loaded in Postgres. |

## Clients

The end-to-end suite runs through PgDog with tokio-postgres, in text and binary formats. The compatibility suite runs PgDog's Go integration tests (pgx, lib/pq and GORM) with every user masked; their results match a run without the plugin.

## Platforms

Linux and macOS, wherever PgDog builds.
