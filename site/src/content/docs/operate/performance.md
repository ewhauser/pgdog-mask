---
title: Performance
description: What masking costs per statement and in Postgres, and how caching keeps it low.
---

## Per statement

Decisions are cached per statement and masking profile. Statements that differ only in their literal values share one analysis (their **shape**), so simple-protocol clients that inline values don't cause a new analysis per statement. Prepared statements are only analyzed when they're prepared.

Measured with `cargo bench --bench overhead`:

| Case | Cost per statement |
| --- | --- |
| Exempt user | ~30 ns |
| Masked user, cached statement | 120–320 ns |
| Masked user, new literals (simple protocol) | 2–6 µs |
| Masked user, new statement shape | 3–35 µs, once per shape |

`cache_size` sets how many analyzed statements are kept (default 100,000).

End to end, `integration/bench/bench.sh` runs pgbench against Postgres, PgDog, and PgDog with the plugin. Prepared statements and point queries show no measurable overhead. A 34-column `SELECT table.*` with masked columns over the simple protocol runs about 16% slower for masked users, mostly because Postgres plans and evaluates the expanded, masked select list.

## Indexes

A masked column in a condition is compared through its mask: `WHERE mask(ssn) = $1` can't use an index on `ssn`. This is inherent to masking predicates (Snowflake behaves the same way) and only affects masked users filtering, joining or sorting on masked columns.

- Rules with [`search = "raw"`](../../configure/raw-search/) keep their searches on the real column, so they use its index.
- An expression index on the exact mask expression can serve hot queries, but it must match the rewritten expression exactly, including its cast, and breaks when the policy changes.
- [Shadow mode](../../start/shadow-mode/) shows which statements would be affected before you enforce.

## Proxy masks

[Proxy masks](../../configure/proxy-masks/) run in the plugin for every value of the masked columns, in batches of rows already received. Their cost is the mask's own: an HMAC is cheap, a vault call isn't. Use SQL masks unless you need a key or code.
