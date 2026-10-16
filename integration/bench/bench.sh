#!/bin/bash
# Masking plugin overhead: pgbench against Postgres directly, PgDog without the
# plugin, and PgDog with the plugin for an exempt and a masked user.
#
# Requires `pgbench -i -s 20 masking_bench` and the tables in setup.sql, on
# the local Postgres.
set -e
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source "${SCRIPT_DIR}/../common.sh"
DURATION=${DURATION:-10}
CLIENTS=${CLIENTS:-16}
THREADS=${THREADS:-4}

(cd "${ROOT}" && cargo build --release)

# Config directories: the plugin config, or the same without the plugin.
BASELINE=$(mktemp -d)
cp "${SCRIPT_DIR}/pgdog-baseline.toml" "${BASELINE}/pgdog.toml"
cp "${SCRIPT_DIR}/users.toml" "${BASELINE}/users.toml"

function run() {
    local label=$1 port=$2 user=$3 script=$4 mode=$5
    local out
    out=$(pgbench -h 127.0.0.1 -p ${port} -U ${user} -n -M ${mode} -c ${CLIENTS} -j ${THREADS} \
        -T ${DURATION} -f ${SCRIPT_DIR}/${script} masking_bench 2>&1)
    local tps=$(echo "${out}" | grep -E "^tps" | sed -E 's/tps = ([0-9.]+).*/\1/')
    local lat=$(echo "${out}" | grep -E "latency average" | sed -E 's/.*= ([0-9.]+) ms/\1/')
    local failed=$(echo "${out}" | grep -E "number of failed" | sed -E 's/.*: ([0-9]+).*/\1/')
    printf "%-28s %-10s %-9s %12s %10s %8s\n" "${label}" "${script%.sql}" "${mode}" "${tps}" "${lat}" "${failed:-?}"
}

printf "%-28s %-10s %-9s %12s %10s %8s\n" target script protocol tps "lat ms" failed
for script in ${SCRIPTS:-point.sql join.sql orm.sql}; do
    for mode in simple prepared; do
        run "postgres" 5432 pgdog ${script} ${mode}
    done
done

start_pgdog "${BASELINE}" release
for script in ${SCRIPTS:-point.sql join.sql orm.sql}; do
    for mode in simple prepared; do
        run "pgdog" 6432 bench_masked ${script} ${mode}
    done
done
stop_pgdog

start_pgdog "${SCRIPT_DIR}" release
for script in ${SCRIPTS:-point.sql join.sql orm.sql}; do
    for mode in simple prepared; do
        run "pgdog+masking (exempt)" 6432 bench_admin ${script} ${mode}
        run "pgdog+masking (masked)" 6432 bench_masked ${script} ${mode}
    done
done
stop_pgdog
