---
title: Install the plugin
description: Build pgdog-mask and a compatible PgDog from a fresh checkout, load the plugin, and connect through it.
---

pgdog-mask is a shared library that PgDog loads at startup. PgDog only loads plugins built against the same plugin API version and with the same Rust compiler as itself, so you build both.

This page goes from nothing to PgDog running with the plugin, in front of a sample database. If you already run PgDog, skip to [Add it to an existing PgDog](#add-it-to-an-existing-pgdog).

## Before you start

You need:

- **git** and **Rust**, through [rustup](https://rustup.rs). Each repository's `rust-toolchain.toml` selects the toolchain, and rustup installs it on the first build.
- **Postgres 14 or later**, running on `127.0.0.1:5432`, and `psql`.
- A Postgres role that can create a database. The commands below use the `postgres` role with password `postgres`; substitute your own.

See [prerequisites](../prerequisites/) for the versions pgdog-mask supports and what a production deployment must enforce.

## 1. Clone both repositories

Work in a new directory. Every later command runs from it.

```bash
mkdir pgdog-masking
cd pgdog-masking
git clone https://github.com/ewhauser/pgdog-mask
git clone https://github.com/ewhauser/pgdog
```

pgdog-mask needs PgDog's plugin API 0.8, which is on the [`ewhauser/pgdog`](https://github.com/ewhauser/pgdog/tree/masking/plugin-api) fork. pgdog-mask's `Cargo.toml` pins the exact commit.

## 2. Build PgDog at the pinned commit

```bash
git -C pgdog checkout "$(sed -nE 's/^pgdog-plugin = \{ git = "[^"]+", rev = "([^"]+)".*/\1/p' pgdog-mask/Cargo.toml)"
(cd pgdog && cargo build --release -p pgdog)
```

The binary is `pgdog/target/release/pgdog`. Building in PgDog's own checkout uses its `rust-toolchain.toml` and `.cargo/config.toml`; at the pinned commit, its toolchain matches pgdog-mask's.

## 3. Build the plugin

```bash
(cd pgdog-mask && cargo build --release)
```

The library is `pgdog-mask/target/release/libpgdog_mask.so` on Linux, or `libpgdog_mask.dylib` on macOS. The build also writes `pgdog-mask/target/release/pgdog-mask`, the command that [validates a configuration](../../operate/validate/) against a database.

## 4. Create a sample database

```bash
psql "postgres://postgres:postgres@127.0.0.1:5432/postgres" -c "CREATE DATABASE masking_demo"
psql "postgres://postgres:postgres@127.0.0.1:5432/masking_demo" <<'SQL'
CREATE TABLE users (id bigint PRIMARY KEY, name text NOT NULL, ssn text);
INSERT INTO users VALUES
    (1, 'alice', '123-45-6789'),
    (2, 'bob', '987-65-1234');
SQL
```

Create tables before PgDog starts, or [reload](../../operate/reload/) after: the plugin works from the catalog PgDog loads, and blocks masked users' statements on tables it hasn't seen.

## 5. Configure PgDog

Create three files in the working directory.

`pgdog.toml` points PgDog at the database and loads the plugin:

```toml
[[databases]]
name = "masking_demo"     # also the Postgres database name
host = "127.0.0.1"
port = 5432

[[plugins]]
name = "pgdog_mask"
config = "masking.toml"
required = true
```

`users.toml` defines the users clients connect as. Both share one Postgres role: masking depends on the PgDog user, not the Postgres one.

```toml
[[users]]
name = "support"
database = "masking_demo"
password = "support"
server_user = "postgres"
server_password = "postgres"

[[users]]
name = "admin"
database = "masking_demo"
password = "admin"
server_user = "postgres"
server_password = "postgres"
```

`masking.toml` is the plugin's configuration. Start with no policies; you'll add one in the [next step](../first-policy/):

```toml
[general]
mode = "enforce"
```

- `config` is the plugin's [configuration file](../../reference/configuration/), relative to PgDog's working directory.
- `required = true` makes PgDog refuse to start if the plugin fails to load, or rejects its configuration. Set it: without it, PgDog starts without masking.

## 6. Start PgDog

PgDog finds the plugin by its name, `pgdog_mask`, in the library search path:

```bash
export LD_LIBRARY_PATH="$PWD/pgdog-mask/target/release"   # Linux
export DYLD_LIBRARY_PATH="$PWD/pgdog-mask/target/release" # macOS
./pgdog/target/release/pgdog --config pgdog.toml --users users.toml
```

Leave it running, and use another terminal, in the same directory, for the next steps. Instead of setting the search path, you can copy the library to a system library directory, or set the plugin's `name` to the library's full path, including its extension.

PgDog loads the database catalog for the plugin, even if `load_schema` is off. Until a database's catalog has loaded, masked users get SQLSTATE `57P03` (`cannot_connect_now`) instead of running statements the plugin couldn't analyze.

## 7. Check that it loaded

PgDog logs each plugin it loads, after the plugin has loaded its configuration. Look for:

```text
[pgdog_mask] loaded 0 policies, 0 masked columns (mode: Enforce)
loaded "pgdog_mask" plugin (v0.1.0)
```

Then connect through PgDog, on port 6432:

```bash
psql "postgres://support:support@127.0.0.1:6432/masking_demo" -c "SELECT * FROM users"
```

Nothing is masked yet. If PgDog doesn't start, or skips the plugin, see [Troubleshoot](../../operate/troubleshoot/#the-plugin-doesnt-load).

Next: [mask your first column](../first-policy/).

## Add it to an existing PgDog

If you already run PgDog:

1. Build PgDog from the commit pgdog-mask's `Cargo.toml` pins (step 2), and the plugin (step 3), with the toolchain in `rust-toolchain.toml`. A PgDog built from another commit skips the plugin.
2. Put the library where PgDog can load it: a directory in `LD_LIBRARY_PATH` (`DYLD_LIBRARY_PATH` on macOS), a system library directory, or give its full path as the plugin `name`.
3. Add the `[[plugins]]` entry above to your `pgdog.toml`, and create `masking.toml`.
4. Restart PgDog. Plugins are loaded at startup only, not by a reload.
