#!/bin/bash
# Masking plugin overhead: pgbench against Postgres directly, PgDog without the
# plugin, and PgDog with the plugin for an exempt and a masked user.
#
# Requires: a release build (cargo build --release -p pgdog -p pgdog-masking),
# and `pgbench -i -s 20 masking_bench` on the local Postgres.
set -e
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
ROOT=${SCRIPT_DIR}/../../..
DURATION=${DURATION:-10}
CLIENTS=${CLIENTS:-16}
THREADS=${THREADS:-4}
export PGPASSWORD=pgdog
export DYLD_LIBRARY_PATH=${ROOT}/target/release
export LD_LIBRARY_PATH=${DYLD_LIBRARY_PATH}

PGDOG_PID=""
function start_pgdog() {
    pushd ${ROOT} > /dev/null
    target/release/pgdog --config integration/masking/bench/$1 --users integration/masking/bench/users.toml \
        > ${SCRIPT_DIR}/pgdog.log 2>&1 &
    PGDOG_PID=$!
    popd > /dev/null
    until pg_isready -h 127.0.0.1 -p 6432 -q; do sleep 0.1; done
    # Let the schema load before measuring.
    sleep 1
}
function stop_pgdog() {
    [ -n "${PGDOG_PID}" ] && kill ${PGDOG_PID} && wait ${PGDOG_PID} 2> /dev/null || true
    PGDOG_PID=""
}
trap stop_pgdog EXIT

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

start_pgdog pgdog-baseline.toml
for script in ${SCRIPTS:-point.sql join.sql orm.sql}; do
    for mode in simple prepared; do
        run "pgdog" 6432 bench_masked ${script} ${mode}
    done
done
stop_pgdog

start_pgdog pgdog.toml
for script in ${SCRIPTS:-point.sql join.sql orm.sql}; do
    for mode in simple prepared; do
        run "pgdog+masking (exempt)" 6432 bench_admin ${script} ${mode}
        run "pgdog+masking (masked)" 6432 bench_masked ${script} ${mode}
    done
done
stop_pgdog
