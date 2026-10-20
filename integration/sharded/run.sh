#!/bin/bash
# The end-to-end setup, sharded: masking_e2e.users is split across two
# shards by id, and the tests check masking survives cross-shard sorting,
# aggregation and COPY. Needs what integration/run.sh needs.
set -e
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source "${SCRIPT_DIR}/../common.sh"

cd "${ROOT}"
cargo build --features test-masks
# Each shard gets the schema, without rows: they're inserted through PgDog,
# which routes them.
for shard in pgdog_mask_shard_0 pgdog_mask_shard_1; do
    psql -v ON_ERROR_STOP=1 -q -d pgdog -c "DROP DATABASE IF EXISTS ${shard}" -c "CREATE DATABASE ${shard}"
    psql -v ON_ERROR_STOP=1 -q -d "${shard}" -f "${ROOT}/integration/setup.sql" \
        -c "TRUNCATE masking_e2e.users"
done

export PGDOG_MASK_E2E_HMAC_KEY=e2e-hmac-key
export PGDOG_MASK_E2E_FF1_KEY=2b7e151628aed2a6abf7158809cf4f3c
start_pgdog integration/sharded debug
# Arguments go to the test harness, e.g. --include-ignored.
PGDOG_MASK_SHARDED=1 cargo test --test sharded -- "$@"
