---
title: Performance
description: What masking costs, measured with pgbench, and how to run the benchmark yourself.
---

## Results

Median transactions per second from `integration/bench/bench.sh`: 3 runs of 10 seconds per row, 16 clients, scale 20, on an Apple M3 Max with Postgres 16, PgDog and pgbench on the same machine. *vs PgDog* compares each pgdog-mask user with PgDog without the plugin. Differences of a few percent are within run-to-run variation; each report gives the spread.

| Workload | Protocol | Postgres direct | PgDog | exempt | masked | vs PgDog |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| point: masked column by key | simple | 156,930 | 79,623 | 79,198 | 77,946 | −2.1% |
| | prepared | 162,064 | 79,484 | 78,353 | 77,704 | −2.2% |
| point_unmasked: analysis only | simple | 150,143 | 78,752 | 78,471 | 76,660 | −2.7% |
| | prepared | 172,570 | 83,504 | 83,528 | 83,820 | +0.4% |
| join | simple | 119,229 | 68,453 | 67,618 | 65,464 | −4.4% |
| | prepared | 153,727 | 78,032 | 77,930 | 77,357 | −0.9% |
| orm: `SELECT *` over 34 columns | simple | 62,212 | 41,573 | 41,296 | 31,535 | −24.1% |
| | extended | 57,588 | 39,034 | 39,382 | 29,026 | −25.6% |
| | prepared | 119,927 | 56,223 | 56,297 | 53,343 | −5.1% |
| proxy: 20 rows, `hmac_sha256` | simple | 151,432 | 75,648 | 75,701 | 75,284 | −0.5% |
| | prepared | 148,489 | 75,367 | 76,224 | 75,451 | +0.1% |
| proxy_batch: 500 rows, `hmac_sha256` | simple | 49,459 | 24,047 | 21,966 | 12,482 | −48.1% |
| | prepared | 54,106 | 24,792 | 24,295 | 14,070 | −43.2% |

Lookups by an indexed, masked column, with and without [raw search](../../configure/raw-search/):

| Protocol | Postgres direct | PgDog | exempt | masked | vs PgDog | masked, raw search | vs PgDog |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| simple | 140,941 | 75,742 | 75,292 | 318 | −99.6% | 73,849 | −2.5% |
| extended | 136,125 | 73,325 | 72,581 | 320 | −99.6% | 73,915 | +0.8% |
| prepared | 168,625 | 82,545 | 82,000 | 325 | −99.6% | 81,943 | −0.7% |

Sources, with every protocol, latency percentiles and spread:

- [`published/20261016-204855.md`](https://github.com/ewhauser/pgdog-mask/blob/main/integration/bench/published/20261016-204855.md): every row except `proxy` and `proxy_batch`. PgDog `b90f1926`. The report records pgdog-mask `484fd75-dirty`: it was run before the benchmark itself was committed, in `7476ab1`.
- [`published/20261017-005209.md`](https://github.com/ewhauser/pgdog-mask/blob/main/integration/bench/published/20261017-005209.md): `proxy` and `proxy_batch`, after proxy masks were optimized in `615d8ab`. PgDog `b90f1926`. The report records pgdog-mask `6949462`, an earlier commit with the same tree as `615d8ab`.

The two runs were made on the same machine with the same settings, a few hours apart; compare rows within a run.

What they show:

- **PgDog itself** roughly halves the throughput of these sub-millisecond queries compared with Postgres directly, with or without the plugin: that's the proxy hop. Masking costs are measured against PgDog.
- **Exempt users** are within run-to-run variation of PgDog.
- **SQL masks** cost 1–4% on point queries and joins.
- **Wide `SELECT *`** costs about 25% over the simple and extended protocols, but 5% with prepared statements. The plugin's analysis is cached in all three, so the difference comes from Postgres executing the expanded, masked statement. Planning is a likely part of it: a prepared statement can reuse a plan, while the simple and extended runs plan every execution. The masked expressions are still evaluated on every execution, prepared or not, and Postgres may plan a prepared statement again for its parameters (see [`PREPARE`](https://www.postgresql.org/docs/current/sql-prepare.html)). The benchmark measures the difference; it doesn't isolate the cause.
- **Lookups by a masked column** can't use its index, and scan the table: 99.6% lower throughput here, with 100,000 rows. With `search = "raw"`, the condition compares real values and ran within a few percent of PgDog, while results stay masked. Choose raw search for columns users look rows up by, if your security model allows it.
- **Proxy masks** cost per value: within variation for 20 rows, and 39–48% lower throughput for 500 rows, where every row's value goes through the plugin's HMAC. Use SQL masks unless you need a key or code.

## Per statement

Decisions are cached per statement and masking profile. Statements that differ only in their literal values share one analysis (their **shape**), so simple-protocol clients that inline values don't cause a new analysis per statement. Prepared statements are analyzed when they're prepared, and again only after a reload, a schema change or a change of the session's `search_path`.

`cargo bench --bench overhead` measures the plugin alone, without the network or Postgres:

| Case | Cost per statement |
| --- | --- |
| Exempt user | ~30 ns |
| Masked user, cached statement | 120–320 ns |
| Masked user, new literals (simple protocol) | 2–6 µs |
| Masked user, new statement shape | 3–35 µs, once per shape |

`cache_size` sets how many analyzed statements are kept (default 100,000).

## Indexes

A masked column in a condition is compared through its mask: `WHERE mask(login) = $1` can't use an index on `login`. This is inherent to masking conditions (Snowflake behaves the same way) and only affects masked users filtering, joining or sorting on masked columns.

- Rules with [`search = "raw"`](../../configure/raw-search/) keep their lookups on the real column, so they use its index, as the lookup results above show.
- An expression index on the exact mask expression can serve hot queries, but it must match the rewritten expression exactly, including its cast, and breaks when the policy changes.
- [Shadow mode](../../start/shadow-mode/) shows which statements would be affected before you enforce.

## Run the benchmark

The benchmark is a repeatable manual test. Run it before and after changes that could affect performance, and when you upgrade PgDog.

```bash
bash integration/bench/bench.sh            # full run: about 55 minutes
QUICK=1 bash integration/bench/bench.sh    # one short pass: about 12 minutes
```

It loads its own data into a `masking_bench` database, builds the plugin and PgDog, starts PgDog with and without the plugin, checks that masking works, and runs every workload against every target, interleaved, several times. Reports go to `integration/bench/results/`. To compare two runs:

```bash
python3 integration/bench/report.py compare results/<before>.csv results/<after>.csv
```

Settings, workloads, targets and how to read the report are in [`integration/bench/README.md`](https://github.com/ewhauser/pgdog-mask/blob/main/integration/bench/README.md).
