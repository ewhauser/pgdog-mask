#!/bin/bash
# End-to-end tests: PgDog loads the plugin and the tests connect through it as
# masked and exempt users. Needs Postgres with a pgdog/pgdog superuser and a
# pgdog database (override with the usual PG* variables).
set -e
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source "${SCRIPT_DIR}/common.sh"

cd "${ROOT}"
cargo build --features test-masks
psql -v ON_ERROR_STOP=1 -q -f "${SCRIPT_DIR}/setup.sql"

# Keys of the proxy masks in masking.toml.
export PGDOG_MASK_E2E_HMAC_KEY=e2e-hmac-key
export PGDOG_MASK_E2E_FF1_KEY=2b7e151628aed2a6abf7158809cf4f3c
start_pgdog integration debug
PGDOG_MASK_E2E=1 cargo test --test e2e --test protocol
