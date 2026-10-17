# Masking benchmark

A repeatable, manual pgbench comparison of what masking costs. It runs each
workload against Postgres, PgDog without the plugin, and PgDog with the plugin
for exempt and masked users, and reports medians over several runs.

Run it before and after a change that could affect performance, and when you
upgrade PgDog, and compare the results.

## Run

Needs Postgres on `127.0.0.1:5432` with a `pgdog` superuser (password `pgdog`),
`pgbench` and `psql` from the same Postgres version, Python 3, and Rust.

```bash
bash integration/bench/bench.sh            # full run: about 55 minutes
QUICK=1 bash integration/bench/bench.sh    # one 5s pass: about 12 minutes
```

The script:

1. creates the `masking_bench` database and loads the data (`pgbench -i` at
   scale 20, then `setup.sql`), unless it's already there at the current version;
2. builds the plugin and PgDog (release), at the commit `Cargo.toml` pins;
3. starts two PgDogs: without the plugin on port 6433, with it on port 6432;
4. checks that masking works (masked, exempt and raw-search results), and stops
   if it doesn't;
5. runs every workload, protocol and target, with a short warmup, `REPEAT` times.
   Targets are interleaved within each repetition, so drift on the machine
   affects them alike;
6. writes `results/<timestamp>.csv` (every run), `.env` (the environment) and
   `.md` (the report), and prints the report.

### Settings

| Variable | Default | |
| --- | --- | --- |
| `DURATION` | `10` | Seconds per run. |
| `REPEAT` | `3` | Runs per workload, protocol and target. The report shows medians. |
| `WARMUP` | `3` | Seconds of warmup per workload and protocol, not recorded. |
| `CLIENTS` / `THREADS` | `16` / `4` | pgbench `-c` and `-j`. |
| `PGDOG_WORKERS` | `4` | PgDog's `workers`. |
| `SCALE` | `20` | pgbench scale. Changing it reloads the data. |
| `WORKLOADS` | all | Space-separated names from `workloads/`. |
| `PROTOCOLS` | `simple extended prepared` | pgbench `-M`. |
| `TARGETS` | `postgres pgdog exempt masked` | `raw_search` is added for `lookup` when `masked` runs. |
| `SAMPLING` | `0.1` | Share of transactions logged for latency percentiles. |
| `QUICK` | | `1`: `DURATION=5 REPEAT=1 WARMUP=1`. |

For example, only the proxy workloads over the extended protocol:

```bash
WORKLOADS="proxy proxy_batch" PROTOCOLS=extended bash integration/bench/bench.sh
```

## Targets

| Target | Connects to | As | Measures |
| --- | --- | --- | --- |
| `postgres` | Postgres | `pgdog` | The database alone. |
| `pgdog` | PgDog without the plugin | `bench_masked` | The baseline every masking number is compared to. |
| `exempt` | PgDog with the plugin | `bench_admin`, no masks apply | The plugin's cost for users it doesn't mask: a lookup per statement. |
| `masked` | PgDog with the plugin | `bench_masked` | The cost of masking: analysis, rewritten statements, proxy masks. |
| `raw_search` | PgDog with the plugin | `bench_support`, masked, with `search = "raw"` on `login` | A masked user's lookups when raw search is allowed. `lookup` only. |

`lookup` always measures masked users both ways: `masked`, whose condition is
masked and can't use the index, and `raw_search`, whose condition compares real
values and uses it. Results stay masked for both. Read them side by side: they're
the two configurations you choose between for columns users search on.

## Workloads

| Workload | Query | What it shows for masked users |
| --- | --- | --- |
| `point` | `abalance` by primary key | An SQL mask (`round`) on a point query. |
| `point_unmasked` | `bid` by primary key, same table | Analysis only: the statement isn't changed. |
| `join` | Accounts joined with branches, `abalance` masked | An SQL mask in a join. |
| `orm` | `SELECT "customers".*` over 34 columns, 3 rows | `*` expanded and masked: the largest rewrite. |
| `lookup` | `WHERE login = $1`, indexed | `masked`: the condition is masked, so the index can't be used. `raw_search`: the condition is left raw and uses the index. |
| `proxy` | 20 rows with `tax_id` | A proxy mask (`hmac_sha256`), computed by the plugin. |
| `proxy_batch` | 500 rows with `tax_id` | The proxy mask's per-row cost. |

To add a workload, put a pgbench script in `workloads/`, add any tables it needs
to `setup.sql` (and bump the version in its last line and in `bench.sh`), and
its masking to `masking.toml`.

## Read the report

The report starts with a summary of every workload and target, then a section
per workload with latency percentiles. *vs PgDog* is the change in throughput
against PgDog without the plugin: that's the cost of masking. *spread* is the
range of throughput across runs, relative to the median: a difference smaller
than the spread is noise. Any failed transaction is flagged at the end, and the
run is invalid.

What to expect:

- `exempt` within noise of `pgdog` on every workload.
- `masked` within a few percent of `pgdog` on `point`, `point_unmasked` and
  `join`, and further behind on `orm`, where Postgres evaluates 34 masked and
  unmasked expressions.
- On `lookup`, `masked` far behind, by design: it scans the table. `raw_search`
  within noise of `pgdog`.
- `masked` behind on `proxy` and more on `proxy_batch`: every value goes through
  the plugin.

## Compare runs

```bash
python3 integration/bench/report.py compare results/<before>.csv results/<after>.csv
```

prints the change in median throughput and p95 latency for every workload,
protocol and target the two runs share. Compare runs from the same machine with
the same settings.

## Getting stable numbers

- Run on an otherwise idle machine, on AC power, and with the same settings
  each time.
- Postgres, PgDog and pgbench share the machine, so they compete for CPU. Keep
  `CLIENTS` and `PGDOG_WORKERS` the same across runs you compare.
- Use the full run for decisions; `QUICK=1` is for checking the harness.
- `cargo bench --bench overhead` measures the plugin's per-statement cost alone,
  without the network or Postgres.
