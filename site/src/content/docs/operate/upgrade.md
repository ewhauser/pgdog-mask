---
title: Upgrade PgDog
description: Move pgdog-mask to a new PgDog commit.
---

PgDog only loads plugins built against the same plugin API version and with the same Rust compiler, so pgdog-mask and PgDog are upgraded together. `Cargo.toml` pins the PgDog commit.

1. Point `pgdog-plugin` and `pgdog-stats` in `Cargo.toml` at the new commit, then run `cargo update -p pgdog-plugin -p pgdog-stats`.
2. Copy PgDog's catalog queries, `pgdog/src/backend/schema/{relations,columns_catalog,views,functions,operators}.sql`, into `tests/support/sql`. The tests load catalogs with them, exactly as PgDog does.
3. Run `cargo test` and `bash integration/run.sh`. The integration script builds PgDog from the pinned commit.
4. Build PgDog from the same commit, with the same toolchain, for production.

If you build your own plugin with [custom proxy masks](../../develop/proxy-masks/), rebuild it against the new pgdog-mask too.
