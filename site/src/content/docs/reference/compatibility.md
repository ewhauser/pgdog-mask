---
title: Compatibility
description: The PgDog, Rust and Postgres versions pgdog-mask works with.
---

## PgDog

pgdog-mask needs PgDog's plugin API **0.7**: statement verdicts, column masks, error redaction and the typed catalog. It's on the [`masking/plugin-api`](https://github.com/ewhauser/pgdog/tree/masking/plugin-api) branch of the `ewhauser/pgdog` fork until it's merged upstream.

`Cargo.toml` pins the exact commit, currently [`40a3d1b5`](https://github.com/ewhauser/pgdog/commit/40a3d1b516d6072406f0286bab7d722bdb80f82a). Build PgDog from that commit. PgDog checks the plugin API version (major and minor) when it loads a plugin, and skips plugins built for another one.

## Rust

PgDog only loads plugins built by the same Rust compiler, because plugins share Rust types with it. Build PgDog and the plugin, or [your own plugin](../../develop/proxy-masks/), with the toolchain in `rust-toolchain.toml`: currently Rust **1.96**.

## Postgres

| | |
| --- | --- |
| Tested | Postgres 16, in CI. |
| Required | Postgres 14 or later, to analyze SQL functions with `BEGIN ATOMIC` bodies. Older versions work, but those functions can't be analyzed. |
| Security labels | `tag_source = "security_label"` needs a label provider loaded in Postgres. |

## Clients

The end-to-end suite runs through PgDog with tokio-postgres, in text and binary formats. The compatibility suite runs PgDog's Go integration tests (pgx, lib/pq and GORM) with every user masked; their results match a run without the plugin.

## Platforms

Linux and macOS, wherever PgDog builds.
