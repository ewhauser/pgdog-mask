---
title: Performance
description: What masking costs, measured with pgbench, and how to run the benchmark yourself.
---

## Results

Median transactions per second from `integration/bench/bench.sh`: 3 runs of 10 seconds per row, 16 clients, scale 20, on an Apple M3 Max with Postgres 16, PgDog and pgbench on the same machine. *vs PgDog* compares each pgdog-mask user with PgDog without the plugin.

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
| proxy: 20 rows, `hmac_sha256` | simple | 132,130 | 71,633 | 71,589 | 57,795 | −19.3% |
| | prepared | 135,392 | 71,937 | 71,841 | 62,278 | −13.4% |
| proxy_batch: 500 rows, `hmac_sha256` | simple | 48,235 | 24,469 | 23,840 | 6,650 | −72.8% |
| | prepared | 52,827 | 26,007 | 25,441 | 6,722 | −74.2% |

Lookups by an indexed, masked column, with and without [raw search](../../configure/raw-search/):

| Protocol | Postgres direct | PgDog | exempt | masked | vs PgDog | masked, raw search | vs PgDog |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| simple | 140,941 | 75,742 | 75,292 | 318 | −99.6% | 73,849 | −2.5% |
| extended | 136,125 | 73,325 | 72,581 | 320 | −99.6% | 73,915 | +0.8% |
| prepared | 168,625 | 82,545 | 82,000 | 325 | −99.6% | 81,943 | −0.7% |

What they show:

- **PgDog itself** roughly halves the throughput of these sub-millisecond queries compared with Postgres directly, with or without the plugin: that's the proxy hop. Masking costs are measured against PgDog.
- **Exempt users** are within noise of PgDog everywhere.
- **SQL masks** cost 1–4% on point queries and joins.
- **Wide `SELECT *`** costs about 25% over the simple and extended protocols, but 5% with prepared statements. The plugin's analysis is cached in all three; the difference is Postgres planning and evaluating the expanded, masked select list on every execution, which prepared statements avoid.
- **Lookups by a masked column** can't use its index, and scan the table: 99.6% slower here, with 100,000 rows. With `search = "raw"`, the condition compares real values and runs as fast as without masking, while results stay masked. Choose raw search for columns users look rows up by, if your security model allows it.
- **Proxy masks** cost per value: 13–19% for 20 rows, and about 73% for 500 rows, where every row's value goes through the plugin's HMAC. Use SQL masks unless you need a key or code.

## Per statement

Decisions are cached per statement and masking profile. Statements that differ only in their literal values share one analysis (their **shape**), so simple-protocol clients that inline values don't cause a new analysis per statement. Prepared statements are only analyzed when they're prepared.

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
