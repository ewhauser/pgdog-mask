---
title: Maintain the PgDog dependency
description: Move pgdog-mask to a new PgDog commit and check it still works.
---

PgDog only loads plugins built against the same plugin API version and with the same Rust compiler, so pgdog-mask pins the PgDog commit it's built against, in `Cargo.toml`. This page is for moving that pin. To deploy a new version, see [Upgrade a deployment](../../operate/upgrade/).

1. Point `pgdog-plugin` and `pgdog-stats` in `Cargo.toml` at the new commit, then run `cargo update -p pgdog-plugin -p pgdog-stats`. Run it in `example/custom-mask` and `fuzz` too: each is its own workspace, with its own `Cargo.lock`.
2. If the new commit uses another `pg_raw_parse` revision, pin it in both `Cargo.toml` and `fuzz/Cargo.toml`.
3. Check that `rust-toolchain.toml` matches the new commit's toolchain, and update it if it doesn't.
4. Copy PgDog's catalog queries, `pgdog/src/backend/schema/{relations,columns_catalog,views,functions,operators}.sql`, into `src/schema/`. `src/schema.rs` includes them, so `pgdog-mask validate` and the tests load catalogs as PgDog does.
5. Run `cargo test`, `bash integration/run.sh`, `bash integration/sharded/run.sh` and `bash integration/compat.sh`. The integration scripts build PgDog from the pinned commit.
6. Run the [benchmark](../../operate/performance/#run-the-benchmark) and compare it with the last run.

If you build your own plugin with [custom proxy masks](../proxy-masks/), rebuild it against the new pgdog-mask too.
