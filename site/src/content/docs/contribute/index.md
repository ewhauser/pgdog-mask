---
title: Development and tests
description: Build pgdog-mask, run its test suites, and work on this documentation.
---

## Layout

| Path | Contents |
| --- | --- |
| `src/analyzer` | Resolves statements against policies and rewrites them. |
| `src/engine.rs` | Plugin state: configuration, catalogs, caches, decisions. |
| `src/proxy` | Proxy masks: the `ProxyMask` API, the registry, built-in masks. |
| `src/plugin.rs` | The plugin's hooks and the `masking_plugin!` macro. |
| `tests` | Canary leak tests and end-to-end tests. |
| `integration` | Scripts that build PgDog and run the plugin in it. |
| `example/custom-mask` | A plugin with a custom proxy mask. |
| `docs/DESIGN.md` | The [design](design/). |
| `site` | This documentation. |

## Tests

Tests need Postgres on `127.0.0.1:5432` with a `pgdog` superuser (password `pgdog`) and a `pgdog` database. Override these with the usual `PG*` variables.

```bash
cargo test                       # unit tests and canary leak tests
bash integration/run.sh          # end-to-end, through PgDog
bash integration/compat.sh       # Go drivers and ORMs (pgx, pq, GORM) with every user masked
bash integration/bench/bench.sh  # pgbench: Postgres, PgDog, PgDog with the plugin
```

The integration scripts build PgDog from the commit `Cargo.toml` pins, in `.pgdog/<commit>`. Set `PGDOG_BIN` to use your own build.

- **Canary tests** seed masked columns with unique values, run an adversarial corpus through the analyzer as a masked user, execute the result in Postgres, and fail if a canary appears anywhere in rows, errors, notices or `COPY` output. They load the schema with PgDog's own catalog queries.
- **End-to-end tests** run PgDog with the plugin, built with the `test-masks` feature, and check masked and exempt users over the simple and extended protocols.
- **`compat.sh`** needs PgDog's integration databases (`integration/setup.sh` in PgDog's repository). Its results should match `integration/go/run.sh` there, which runs without the plugin.
- **`bench.sh`** needs `pgbench -i -s 20 masking_bench` and `integration/bench/setup.sql`.

CI runs formatting, clippy, the tests, the custom-mask example and the end-to-end suite on every push.

## Documentation

This site is [Astro](https://docs.astro.build) with [Starlight](https://starlight.astro.build), in `site/`.

```bash
cd site
pnpm install --frozen-lockfile
pnpm dev     # http://localhost:4321/pgdog-mask/
pnpm build   # also checks every internal link
```

Pages are Markdown in `site/src/content/docs`; the sidebar is in `site/astro.config.mjs`. `pnpm sync`, run before `dev` and `build`, publishes `docs/DESIGN.md` as the [design](design/) page: edit it there.

The site deploys to GitHub Pages from `main`, through `.github/workflows/site.yml`.
