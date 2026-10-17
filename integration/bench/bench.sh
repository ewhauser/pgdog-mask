#!/bin/bash
# pgbench comparison of masking overhead. See README.md in this directory.
#
#   bash integration/bench/bench.sh            # full run, ~55 minutes
#   QUICK=1 bash integration/bench/bench.sh    # one short pass, ~12 minutes
#
# Each workload runs against every target, interleaved, REPEAT times:
#
#   postgres     Postgres directly
#   pgdog        PgDog without the plugin
#   exempt       PgDog with the plugin, as a user it masks nothing for
#   masked       PgDog with the plugin, as a masked user
#   raw_search   PgDog with the plugin, as a masked user whose rule has
#                search = "raw" (lookup only: masked lookups with and without
#                raw search are both measured)
#
# Results go to integration/bench/results/: a CSV with every run, and a
# Markdown report with medians and the environment.
set -euo pipefail
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source "${SCRIPT_DIR}/../common.sh"

if [ "${QUICK:-0}" = "1" ]; then
    DURATION=${DURATION:-5}
    REPEAT=${REPEAT:-1}
    WARMUP=${WARMUP:-1}
fi
DURATION=${DURATION:-10}
REPEAT=${REPEAT:-3}
WARMUP=${WARMUP:-3}
CLIENTS=${CLIENTS:-16}
THREADS=${THREADS:-4}
SCALE=${SCALE:-20}
WORKLOADS=${WORKLOADS:-point point_unmasked join orm lookup proxy proxy_batch}
PROTOCOLS=${PROTOCOLS:-simple extended prepared}
TARGETS=${TARGETS:-postgres pgdog exempt masked}
# Share of transactions whose latency is logged, for percentiles.
SAMPLING=${SAMPLING:-0.1}

DATABASE=masking_bench
DATA_VERSION=3
MASKING_PORT=6432
BASELINE_PORT=6433
RESULTS="${SCRIPT_DIR}/results"
STAMP=$(date +%Y%m%d-%H%M%S)
CSV="${RESULTS}/${STAMP}.csv"
META="${RESULTS}/${STAMP}.env"
REPORT="${RESULTS}/${STAMP}.md"
export PGDOG_MASK_BENCH_HMAC_KEY=bench-hmac-key

targets_for() {
    local workload=$1
    echo "${TARGETS}"
    # Lookups by a masked column, with search = "raw": the condition keeps
    # using the index. Measured next to masked, which can't.
    if [ "${workload}" = "lookup" ] && [[ " ${TARGETS} " == *" masked "* ]]; then
        echo "raw_search"
    fi
}

port_of() {
    case $1 in
        postgres) echo "${PGPORT}" ;;
        pgdog) echo "${BASELINE_PORT}" ;;
        *) echo "${MASKING_PORT}" ;;
    esac
}

user_of() {
    case $1 in
        postgres) echo "${PGUSER}" ;;
        pgdog | masked) echo bench_masked ;;
        exempt) echo bench_admin ;;
        raw_search) echo bench_support ;;
    esac
}

# Load the data if it's missing or out of date.
setup_data() {
    if ! psql -d postgres -Atqc "SELECT 1 FROM pg_database WHERE datname = '${DATABASE}'" | grep -q 1; then
        createdb "${DATABASE}"
    fi
    local version
    version=$(psql -d "${DATABASE}" -Atqc "SELECT version FROM bench_meta" 2>/dev/null || true)
    local scale
    scale=$(psql -d "${DATABASE}" -Atqc "SELECT count(*) FROM pgbench_branches" 2>/dev/null || true)
    if [ "${version}" != "${DATA_VERSION}" ] || [ "${scale}" != "${SCALE}" ]; then
        echo "Loading benchmark data (scale ${SCALE})..."
        pgbench -i -q -s "${SCALE}" "${DATABASE}"
        psql -v ON_ERROR_STOP=1 -q -d "${DATABASE}" -f "${SCRIPT_DIR}/setup.sql"
    fi
}

PIDS=()
stop_all() {
    for pid in "${PIDS[@]:-}"; do
        [ -n "${pid}" ] && kill "${pid}" 2> /dev/null || true
    done
    wait 2> /dev/null || true
}

# Start PgDog. $1: config directory, $2: port.
start_instance() {
    local dir=$1 port=$2 bin
    bin=$(pgdog_bin release)
    export LD_LIBRARY_PATH="${ROOT}/target/release"
    export DYLD_LIBRARY_PATH="${LD_LIBRARY_PATH}"
    "${bin}" --config "${dir}/pgdog.toml" --users "${dir}/users.toml" > "${dir}/pgdog.log" 2>&1 &
    local pid=$!
    PIDS+=("${pid}")
    until pg_isready -h 127.0.0.1 -p "${port}" -q; do
        if ! kill -0 "${pid}" 2> /dev/null; then
            echo "PgDog on port ${port} exited:"
            tail -20 "${dir}/pgdog.log"
            exit 1
        fi
        sleep 0.1
    done
}

# Write a PgDog config. $1: directory, $2: port, $3: "plugin" to load masking.
write_config() {
    local dir=$1 port=$2 plugin=${3:-}
    mkdir -p "${dir}"
    cp "${SCRIPT_DIR}/users.toml" "${dir}/users.toml"
    {
        echo "[general]"
        echo "port = ${port}"
        echo "workers = ${PGDOG_WORKERS:-4}"
        if [ "${plugin}" = "plugin" ]; then
            echo
            echo "[[plugins]]"
            echo "name = \"pgdog_mask\""
            echo "config = \"${SCRIPT_DIR}/masking.toml\""
            echo "required = true"
        fi
        echo
        echo "[[databases]]"
        echo "name = \"${DATABASE}\""
        echo "host = \"127.0.0.1\""
    } > "${dir}/pgdog.toml"
}

# Fail fast if masking isn't doing what the numbers are meant to measure.
check_masking() {
    local q="SELECT email, tax_id FROM customers WHERE id = 1"
    local masked exempt
    masked=$(psql -h 127.0.0.1 -p "${MASKING_PORT}" -U bench_masked -d "${DATABASE}" -Atqc "${q}")
    exempt=$(psql -h 127.0.0.1 -p "${MASKING_PORT}" -U bench_admin -d "${DATABASE}" -Atqc "${q}")
    if [[ "${masked}" != "****@example.com|"* ]] || [[ "${masked}" == *"TAX-"* ]]; then
        echo "masking check failed: bench_masked got '${masked}'"
        exit 1
    fi
    if [ "${exempt}" != "user1@example.com|TAX-00000001" ]; then
        echo "masking check failed: bench_admin got '${exempt}'"
        exit 1
    fi
    local found
    found=$(psql -h 127.0.0.1 -p "${MASKING_PORT}" -U bench_support -d "${DATABASE}" -Atqc \
        "SELECT count(*) FROM customers WHERE login = '1'")
    if [ "${found}" != "1" ]; then
        echo "masking check failed: raw search found '${found}' rows for bench_support (raw_search)"
        exit 1
    fi
}

# One pgbench run. Prints: tps,latency_avg_ms,p50_ms,p95_ms,p99_ms,failed
run_pgbench() {
    local target=$1 workload=$2 protocol=$3 duration=$4
    local logs
    logs=$(mktemp -d)
    local out
    out=$(cd "${logs}" && pgbench -h 127.0.0.1 -p "$(port_of "${target}")" -U "$(user_of "${target}")" \
        -n -M "${protocol}" -c "${CLIENTS}" -j "${THREADS}" -T "${duration}" \
        -l --sampling-rate="${SAMPLING}" --log-prefix=lat \
        -f "${SCRIPT_DIR}/workloads/${workload}.sql" "${DATABASE}" 2>&1) || true
    local tps lat failed
    tps=$(echo "${out}" | sed -nE 's/^tps = ([0-9.]+).*/\1/p')
    lat=$(echo "${out}" | sed -nE 's/^latency average = ([0-9.]+) ms/\1/p')
    failed=$(echo "${out}" | sed -nE 's/^number of failed transactions: ([0-9]+).*/\1/p')
    if [ -z "${tps}" ]; then
        echo "pgbench failed for ${target}/${workload}/${protocol}:" >&2
        echo "${out}" | tail -5 >&2
        rm -rf "${logs}"
        echo "0,0,0,0,0,-1"
        return
    fi
    # Column 3 of pgbench's transaction log is the latency in microseconds.
    local percentiles
    percentiles=$(cat "${logs}"/lat.* 2> /dev/null | awk '{print $3}' | sort -n | awk '
        { v[NR] = $1 }
        END {
            if (NR == 0) { print "0,0,0"; exit }
            p50 = v[int(NR * 0.50) > 0 ? int(NR * 0.50) : 1]
            p95 = v[int(NR * 0.95) > 0 ? int(NR * 0.95) : 1]
            p99 = v[int(NR * 0.99) > 0 ? int(NR * 0.99) : 1]
            printf "%.3f,%.3f,%.3f", p50 / 1000, p95 / 1000, p99 / 1000
        }')
    rm -rf "${logs}"
    echo "${tps},${lat:-0},${percentiles},${failed:-0}"
}

main() {
    mkdir -p "${RESULTS}"
    local workload_count target_count protocol_count runs
    workload_count=$(echo ${WORKLOADS} | wc -w | tr -d ' ')
    target_count=$(( $(echo ${TARGETS} | wc -w | tr -d ' ') ))
    protocol_count=$(echo ${PROTOCOLS} | wc -w | tr -d ' ')
    runs=$(( workload_count * protocol_count * target_count * REPEAT ))
    echo "${runs} runs of ${DURATION}s (plus warmup and raw_search on lookup): about $(( runs * (DURATION + 1) / 60 + 1 )) minutes."

    setup_data
    (cd "${ROOT}" && cargo build --release --quiet)

    local tmp
    tmp=$(mktemp -d)
    write_config "${tmp}/baseline" "${BASELINE_PORT}"
    write_config "${tmp}/masking" "${MASKING_PORT}" plugin
    trap stop_all EXIT
    start_instance "${tmp}/baseline" "${BASELINE_PORT}"
    start_instance "${tmp}/masking" "${MASKING_PORT}"
    # Let the catalog reach the plugin.
    sleep 2
    check_masking

    {
        echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "host=$(hostname -s)"
        echo "os=$(uname -sr)"
        echo "cpu=$( (sysctl -n machdep.cpu.brand_string 2> /dev/null || grep -m1 'model name' /proc/cpuinfo | cut -d: -f2) | sed 's/^ *//')"
        echo "cores=$(getconf _NPROCESSORS_ONLN)"
        echo "postgres=$(psql -d "${DATABASE}" -Atqc 'SHOW server_version')"
        echo "pgbench=$(pgbench --version | awk '{print $3}')"
        echo "pgdog=${PGDOG_REV}"
        echo "pgdog_mask=$(git -C "${ROOT}" rev-parse --short HEAD)$(git -C "${ROOT}" diff --quiet || echo '-dirty')"
        echo "duration=${DURATION}"
        echo "repeat=${REPEAT}"
        echo "clients=${CLIENTS}"
        echo "threads=${THREADS}"
        echo "scale=${SCALE}"
        echo "pgdog_workers=${PGDOG_WORKERS:-4}"
    } > "${META}"

    echo "rep,workload,protocol,target,tps,latency_ms,p50_ms,p95_ms,p99_ms,failed" > "${CSV}"
    for workload in ${WORKLOADS}; do
        for protocol in ${PROTOCOLS}; do
            if [ "${WARMUP}" -gt 0 ]; then
                for target in $(targets_for "${workload}"); do
                    run_pgbench "${target}" "${workload}" "${protocol}" "${WARMUP}" > /dev/null
                done
            fi
            for rep in $(seq 1 "${REPEAT}"); do
                # Interleave targets so drift affects them alike.
                for target in $(targets_for "${workload}"); do
                    local result
                    result=$(run_pgbench "${target}" "${workload}" "${protocol}" "${DURATION}")
                    echo "${rep},${workload},${protocol},${target},${result}" >> "${CSV}"
                    printf "%-15s %-9s %-9s rep %s  %s\n" "${workload}" "${protocol}" "${target}" "${rep}" \
                        "$(echo "${result}" | awk -F, '{printf "%10.0f tps  %7.3f ms", $1, $2}')"
                done
            done
        done
    done

    python3 "${SCRIPT_DIR}/report.py" report "${CSV}" "${META}" > "${REPORT}"
    echo
    cat "${REPORT}"
    echo
    echo "Results: ${REPORT}"
}

main "$@"
