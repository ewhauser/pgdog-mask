---
title: Maintain the PgDog dependency
description: Move pgdog-mask to a new PgDog commit and check it still works.
---

PgDog only loads plugins built against the same plugin API version and with the same Rust compiler, so pgdog-mask pins the PgDog commit it's built against, in `Cargo.toml`. This page is for moving that pin. To deploy a new version, see [Upgrade a deployment](../../operate/upgrade/).

1. Point `pgdog-plugin` and `pgdog-stats` in `Cargo.toml` at the new commit, then run `cargo update -p pgdog-plugin -p pgdog-stats`.
2. Check that `rust-toolchain.toml` matches the new commit's toolchain, and update it if it doesn't.
3. Copy PgDog's catalog queries, `pgdog/src/backend/schema/{relations,columns_catalog,views,functions,operators}.sql`, into `tests/support/sql`. The tests load catalogs with them, as PgDog does.
4. Run `cargo test`, `bash integration/run.sh` and `bash integration/compat.sh`. The integration scripts build PgDog from the pinned commit.
5. Run the [benchmark](../../operate/performance/#run-the-benchmark) and compare it with the last run.
6. Update the commit in [compatibility](../../reference/compatibility/).

If you build your own plugin with [custom proxy masks](../proxy-masks/), rebuild it against the new pgdog-mask too.
