# Fuzzing

Coverage-guided fuzzing of the plugin's hooks with
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) and libFuzzer.

This crate is a masking plugin, built with `masking_plugin!` the way custom
mask plugins are. The targets call it through its vtable, as PgDog does. Hook
inputs cross the plugin boundary, and their outputs are decoded and freed by
`pgdog-plugin`'s host side. Hooks catch panics and fail closed, so a panicking
hook would otherwise go unnoticed. Here every hook error fails the target, and
libFuzzer's panic hook aborts on the panic with its backtrace.

The plugin runs with a fixed configuration and catalog: [`src/fixture.rs`](src/fixture.rs).
The fixture has SQL, partial, round and proxy masks (the built-in `hmac_sha256`
and `ff1`, plus the fuzzer's own integer and blocking masks), comment tags, a
partition, inlinable, security-barrier and materialized views, SQL functions
and operators.

| Target | Hook | Checks |
| --- | --- | --- |
| `statement` | `statement` | Raw SQL in every standard session, seeded with the analyzer's test statements. Exempt users are allowed. Databases without a catalog fail closed with `57P03`. Rewrites parse. Verdicts are deterministic. |
| `statement_grammar` | `statement`, `function_call` | SQL generated over the fixture schema ([`src/grammar.rs`](src/grammar.rs)). Same checks, plus a leak oracle: a statement that reads a masked column is never allowed as is for the masked user. Only exempt users may make fast-path calls. |
| `mask_rows` | `mask_rows` | Batches with valid and unknown mask IDs, declared and mismatched types, both formats, and arbitrary values. Unknown masks fail. NULL stays NULL. Masked values decode as the column's type. |
| `redact_error` | `redact_error` | Errors and notices with arbitrary fields. Masked users lose `DETAIL` and nothing else. Exempt users keep everything. |
| `catalog` | `catalog`, `statement` | Arbitrary relations, columns, tags, view definitions, functions and operators. The generation changes on every catalog, and statements against the catalog pass the `statement` checks. |
| `config` | `config` and all others | Arbitrary TOML, loaded like the config file, then every hook run with it. |

## Running

You need a nightly toolchain and cargo-fuzz:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

Run one target, or all of them in turn, for a number of seconds each:

```sh
bash fuzz/run.sh statement_grammar 300
bash fuzz/run.sh all 60
```

New inputs go to `fuzz/corpus/<target>`. The seeds committed in
`fuzz/seeds/<target>` are read too. Crashes land in `fuzz/artifacts/<target>`.
To reproduce or minimize one:

```sh
cargo +nightly fuzz run statement fuzz/artifacts/statement/crash-...
cargo +nightly fuzz tmin statement fuzz/artifacts/statement/crash-...
```

Regenerate the seeds after adding analyzer tests:

```sh
python3 fuzz/scripts/seeds.py
```

## CI

[`.github/workflows/fuzz.yml`](../.github/workflows/fuzz.yml) runs every
target for 30 minutes each night, and on demand with a custom duration. The
corpus is cached between runs and minimized after each one. When a target
fails, its crashes are uploaded as the `fuzz-artifacts-<target>` artifact, and
the job summary says how to reproduce them.

## Known issues

These are skipped so they don't hide new findings, in
[`src/session.rs`](src/session.rs) and
[`fuzz_targets/mask_rows.rs`](fuzz_targets/mask_rows.rs). Each one fails closed.
Remove its check once it's fixed.

- Parameter `$0` deparses as `?` (pg_raw_parse), so its rewrites don't parse.
  Postgres rejects `$0` anyway.
- A masked column in a type's modifiers (`foo(ssn) ''`) is masked, and the
  masked modifier deparses as nothing (`''::foo()`). Postgres only accepts
  constants there.
- `RETURNING *` of a relation with no columns rewrites to an empty
  `RETURNING`.
- Binary timestamps near the end of Postgres's range (294276 AD) overflow
  converting to the Unix epoch (pgdog-postgres-types). With overflow checks
  on, that's a panic.
