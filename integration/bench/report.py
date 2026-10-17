#!/usr/bin/env python3
"""Reports for bench.sh results.

    python3 report.py report results/<stamp>.csv results/<stamp>.env
    python3 report.py compare results/<old>.csv results/<new>.csv
"""
import csv
import statistics
import sys
from collections import defaultdict

# Targets, in report order, with what they measure.
TARGETS = {
    "postgres": "Postgres direct",
    "pgdog": "PgDog, no plugin",
    "exempt": "pgdog-mask, exempt user",
    "masked": "pgdog-mask, masked user",
    "raw_search": "pgdog-mask, masked user with raw search",
}
# Earlier runs called raw_search "support".
ALIASES = {"support": "raw_search"}

WORKLOADS = {
    "point": "`abalance` by primary key, masked with an SQL mask (`round`).",
    "point_unmasked": "An unmasked column of a table with masked columns: the plugin "
    "analyzes the statement but doesn't change it.",
    "join": "Accounts joined with branches, returning masked `abalance`.",
    "orm": 'An ORM-style `SELECT "customers".*` over 34 columns, 3 of them masked: '
    "the largest rewrite.",
    "lookup": "`WHERE login = $1` on an indexed, masked column. The masked user's "
    "condition compares masked values, so Postgres can't use the index. With "
    '`search = "raw"`, the condition compares real values and uses the index; '
    "results are still masked.",
    "proxy": "20 rows with `tax_id`, masked in the results by a proxy mask "
    "(`hmac_sha256`).",
    "proxy_batch": "500 rows with `tax_id`: the proxy mask's per-row cost.",
}

METRICS = ["tps", "latency_ms", "p50_ms", "p95_ms", "p99_ms"]


def load(path):
    """Median of every metric per (workload, protocol, target), and failures."""
    runs = defaultdict(list)
    with open(path) as f:
        for row in csv.DictReader(f):
            target = ALIASES.get(row["target"], row["target"])
            runs[(row["workload"], row["protocol"], target)].append(row)
    medians = {}
    for key, rows in runs.items():
        medians[key] = {m: statistics.median(float(r[m]) for r in rows) for m in METRICS}
        medians[key]["failed"] = sum(int(r["failed"]) for r in rows)
        medians[key]["runs"] = len(rows)
        tps = [float(r["tps"]) for r in rows]
        # Spread between runs, to tell real differences from noise.
        median = statistics.median(tps)
        medians[key]["spread"] = (max(tps) - min(tps)) / median * 100 if median else 0
    return medians


def groups(medians):
    seen = []
    for workload, protocol, _ in medians:
        if (workload, protocol) not in seen:
            seen.append((workload, protocol))
    return seen


def pct(value, base):
    if not base:
        return ""
    return f"{(value - base) / base * 100:+.1f}%"


def summary(medians):
    """Throughput of every target side by side."""
    print()
    print("## Summary")
    print()
    print(
        "Median transactions per second. *vs PgDog* compares each pgdog-mask user "
        "with PgDog without the plugin."
    )
    print()
    print(
        "| workload | protocol | Postgres direct | PgDog | exempt | masked | vs PgDog "
        "| masked, raw search | vs PgDog |"
    )
    print("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for workload, protocol in groups(medians):
        tps = {
            target: medians[(workload, protocol, target)]["tps"]
            for target in TARGETS
            if (workload, protocol, target) in medians
        }
        base = tps.get("pgdog")

        def cell(target):
            return f"{tps[target]:,.0f}" if target in tps else "–"

        def vs(target):
            return pct(tps[target], base) if target in tps else "–"

        print(
            f"| {workload} | {protocol} | {cell('postgres')} | {cell('pgdog')} | "
            f"{cell('exempt')} | {cell('masked')} | {vs('masked')} | "
            f"{cell('raw_search')} | {vs('raw_search')} |"
        )


def report(csv_path, env_path):
    env = dict(line.strip().split("=", 1) for line in open(env_path) if "=" in line)
    medians = load(csv_path)

    print("# pgdog-mask benchmark")
    print()
    print(
        f"{env['date']} on {env['host']}: {env['cpu']}, {env['cores']} cores, {env['os']}. "
        f"Postgres {env['postgres']}, pgbench {env['pgbench']}, PgDog `{env['pgdog'][:8]}`, "
        f"pgdog-mask `{env['pgdog_mask']}`."
    )
    print()
    print(
        f"{env['repeat']} runs of {env['duration']}s per row, {env['clients']} clients, "
        f"{env['threads']} threads, scale {env['scale']}, {env['pgdog_workers']} PgDog workers. "
        "Values are medians across runs."
    )
    print()
    print("Targets:")
    print()
    print("- **Postgres direct**: pgbench connects to Postgres.")
    print("- **PgDog**: PgDog without the plugin, the baseline for masking.")
    print("- **exempt**: PgDog with the plugin, as a user no policy masks.")
    print("- **masked**: PgDog with the plugin, as a masked user.")
    print(
        '- **masked, raw search**: PgDog with the plugin, as a masked user whose rule '
        'has `search = "raw"`. Only measured for `lookup`.'
    )

    summary(medians)

    by_workload = defaultdict(list)
    for workload, protocol in groups(medians):
        by_workload[workload].append(protocol)

    for workload, protocols in by_workload.items():
        print()
        print(f"## {workload}")
        print()
        if workload in WORKLOADS:
            print(WORKLOADS[workload])
            print()
        print(
            "| protocol | target | tps | vs PgDog | latency ms | p50 | p95 | p99 | spread "
            "| failed |"
        )
        print("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        for protocol in protocols:
            base = medians.get((workload, protocol, "pgdog"), {}).get("tps")
            for target, label in TARGETS.items():
                m = medians.get((workload, protocol, target))
                if not m:
                    continue
                vs = "" if target in ("pgdog", "postgres") else pct(m["tps"], base)
                failed = m["failed"] if m["failed"] >= 0 else "error"
                print(
                    f"| {protocol} | {label} | {m['tps']:,.0f} | {vs} | "
                    f"{m['latency_ms']:.3f} | {m['p50_ms']:.3f} | {m['p95_ms']:.3f} | "
                    f"{m['p99_ms']:.3f} | {m['spread']:.1f}% | {failed} |"
                )

    print()
    print(
        "*spread* is the range of throughput across runs, relative to the median: "
        "a difference smaller than the spread is noise."
    )
    failures = [k for k, m in medians.items() if m["failed"] != 0]
    if failures:
        print()
        print("**Failed transactions or runs:** " + ", ".join("/".join(k) for k in failures))


def compare(old_path, new_path):
    old, new = load(old_path), load(new_path)
    order = list(TARGETS)
    print(f"# Comparison\n\nThroughput medians, {old_path} → {new_path}.\n")
    print("| workload | protocol | target | old tps | new tps | change | old p95 | new p95 |")
    print("| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |")
    for key in sorted(set(old) & set(new), key=lambda k: (k[0], k[1], order.index(k[2]))):
        o, n = old[key], new[key]
        print(
            f"| {key[0]} | {key[1]} | {TARGETS[key[2]]} | {o['tps']:,.0f} | {n['tps']:,.0f} | "
            f"{pct(n['tps'], o['tps'])} | {o['p95_ms']:.3f} | {n['p95_ms']:.3f} |"
        )


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "report":
        report(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 4 and sys.argv[1] == "compare":
        compare(sys.argv[2], sys.argv[3])
    else:
        sys.exit(__doc__)
