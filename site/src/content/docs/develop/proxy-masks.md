---
title: Write a proxy mask
description: Implement a mask in Rust, register it, and build your own plugin with it.
---

pgdog-mask is a library as well as a plugin. To add your own [proxy masks](../../configure/proxy-masks/), you build your own plugin: a small crate that depends on pgdog-mask, registers your masks, and produces the shared library PgDog loads in place of `libpgdog_mask`.

The repository has a complete example: [`example/custom-mask`](https://github.com/ewhauser/pgdog-mask/tree/main/example/custom-mask), a vault-tokenization mask.

## 1. Create the crate

```toml
# Cargo.toml
[package]
name = "acme-mask"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["cdylib"]

[dependencies]
# Default features off: your crate builds the plugin, not pgdog-mask.
pgdog-mask = { git = "https://github.com/ewhauser/pgdog-mask", default-features = false }
```

With default features on, pgdog-mask's own plugin would be linked into yours as well.

Use the same Rust toolchain as PgDog, as for any PgDog plugin ([compatibility](../../reference/compatibility/)). Use the plugin API through `pgdog_mask::pgdog_plugin` rather than depending on `pgdog-plugin` yourself, so the versions always match.

## 2. Implement `ProxyMask`

```rust
use pgdog_mask::proxy::{Datum, MaskError, Options, ProxyMask};

/// Adds a fixed offset to balances.
struct Offset(i64);

impl ProxyMask for Offset {
    // Checked against the policy's data_type when the configuration loads.
    fn accepts(&self, data_type: &str) -> bool {
        data_type == "bigint"
    }

    fn mask(&self, value: Datum) -> Result<Datum, MaskError> {
        match value {
            Datum::Bigint(n) => Ok(Datum::Bigint(n + self.0)),
            other => Err(MaskError::new(format!("expected bigint, got {}", other.data_type()))),
        }
    }
}
```

- `accepts` receives the policy's `data_type`, as `information_schema` spells it. Return `false` for types the mask can't handle; the configuration is then rejected.
- `mask` receives one non-NULL value and returns a value of the **same type**, or `Datum::Null`. Values are already decoded from the client's format (text or binary) and are encoded back after masking; a value of another type is an error.
- `Datum` is PgDog's value type (re-exported from `pgdog_plugin::types`). It covers `smallint`, `integer`, `bigint`, `numeric`, `real`, `double precision`, `boolean`, `uuid`, `timestamp`, `timestamptz`, `interval`, `oid`, arrays of those, and text types. Other types arrive as `Datum::Unknown` with raw bytes in the client's format, so prefer masks over the supported types.
- An error fails the query and closes the client's connection, since earlier rows may already have been sent. Return one only when the value can't be masked safely.

Masks are shared by every client and called from many threads at once (`ProxyMask: Send + Sync`).

## 3. Batches and blocking calls

Two optional methods help masks that call other services:

```rust
impl ProxyMask for Tokenize {
    fn accepts(&self, data_type: &str) -> bool {
        matches!(data_type, "text" | "character varying")
    }

    // The mask makes network calls: PgDog runs it on its blocking thread pool.
    fn blocking(&self) -> bool {
        true
    }

    fn mask(&self, value: Datum) -> Result<Datum, MaskError> {
        Ok(self.mask_batch(vec![value])?.remove(0))
    }

    // One vault round trip per batch of rows, instead of one per value.
    // `values` are one column's values in row order, NULLs as Datum::Null.
    // Return exactly one value per input value.
    fn mask_batch(&self, values: Vec<Datum>) -> Result<Vec<Datum>, MaskError> {
        let tokens = self.vault.tokenize(&values)?;
        Ok(tokens)
    }
}
```

The default `mask_batch` keeps NULLs and calls `mask` for every other value. Don't block in a mask that isn't declared `blocking`: it would stall one of PgDog's async workers.

## 4. Register and build the plugin

A factory builds the mask from the policy's `options` when the configuration loads:

```rust
use pgdog_mask::proxy::{Options, Registry};

pgdog_mask::masking_plugin!(register);

fn register(registry: &mut Registry) {
    registry.register("acme.offset", |options: &Options| {
        Ok(Offset(options.integer("offset")?.unwrap_or(1000)))
    });
}
```

`masking_plugin!` defines the whole plugin: the built-in masks plus yours. `Options` reads the policy's `options` table with `string`, `integer`, and `secret`, which reads `key_env` or `key_file` so keys stay out of the configuration file.

```bash
cargo build --release
# target/release/libacme_mask.so — load it in PgDog instead of libpgdog_mask
```

```toml
# pgdog.toml
[[plugins]]
name = "acme_mask"
config = "masking.toml"
required = true
```

## 5. Use it in a policy

```toml
[[policies]]
name = "balance"
data_type = "bigint"
mask = "proxy"
proxy = "acme.offset"
options = { offset = 5000 }
fallback = "null"
```

Prefix your masks' names, like `acme.`, so they can't collide with built-in masks added later.

## Test your mask

Unit-test masks directly, like the example does. To test them through PgDog, pgdog-mask's own end-to-end suite (`integration/run.sh`) shows how to start PgDog with a plugin and check masked values in text and binary formats.
