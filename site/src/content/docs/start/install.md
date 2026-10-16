---
title: Install the plugin
description: Build pgdog-mask and a compatible PgDog, and load the plugin.
---

pgdog-mask is a shared library that PgDog loads at startup. PgDog only loads plugins built against the same plugin API version and with the same Rust compiler as itself, so you build both.

## Build a compatible PgDog

pgdog-mask needs PgDog's plugin API 0.7, which is on the [`ewhauser/pgdog`](https://github.com/ewhauser/pgdog/tree/masking/plugin-api) fork. `Cargo.toml` pins the exact commit: build PgDog from that commit.

```bash
git clone https://github.com/ewhauser/pgdog
cd pgdog
git checkout $(sed -nE 's/^pgdog-plugin = \{ git = "[^"]+", rev = "([^"]+)".*/\1/p' ../pgdog-mask/Cargo.toml)
cargo build --release
```

Use the toolchain in pgdog-mask's `rust-toolchain.toml` for both builds. See [compatibility](../../reference/compatibility/).

## Build the plugin

```bash
cd pgdog-mask
cargo build --release
# target/release/libpgdog_mask.so (Linux) or libpgdog_mask.dylib (macOS)
```

Put the library where PgDog can load it: a directory in `LD_LIBRARY_PATH` (`DYLD_LIBRARY_PATH` on macOS), a system library path, or give its full path as the plugin `name`.

## Load it in PgDog

Add the plugin to `pgdog.toml`:

```toml
[[plugins]]
name = "pgdog_mask"
config = "masking.toml"
required = true
```

- `config` is the plugin's [configuration file](../../reference/configuration/), relative to PgDog's working directory.
- `required = true` makes PgDog refuse to start if the plugin fails to load, or rejects its configuration. Set it: without it, PgDog starts without masking.

PgDog loads the database catalog for the plugin, even if `load_schema` is off. Until a database's catalog has loaded, masked users get SQLSTATE `57P03` (`cannot_connect_now`), so they never run unanalyzed statements.

## Check that it loaded

PgDog logs each plugin it loads. Look for:

```text
loaded "pgdog_mask" plugin (v0.1.0)
[pgdog_mask] loaded 3 policies, 5 masked columns (mode: Enforce)
```

If PgDog doesn't start, or skips the plugin, see [Troubleshoot](../../operate/troubleshoot/#the-plugin-doesnt-load).

Next: [mask your first column](../first-policy/).
