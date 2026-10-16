#!/bin/bash
# End-to-end tests for the data masking plugin: PgDog loads it as a shared
# library and the tests connect through PgDog as masked and exempt users.
set -e
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source ${SCRIPT_DIR}/../common.sh

pushd ${SCRIPT_DIR}/../..
cargo build -p pgdog-masking
popd

PGPASSWORD=pgdog psql -h 127.0.0.1 -p 5432 -U pgdog -d pgdog -v ON_ERROR_STOP=1 -f ${SCRIPT_DIR}/setup.sql

export LD_LIBRARY_PATH=${SCRIPT_DIR}/../../target/debug
export DYLD_LIBRARY_PATH=${LD_LIBRARY_PATH}

run_pgdog integration/masking
wait_for_pgdog

pushd ${SCRIPT_DIR}/../..
PGDOG_MASKING_E2E=1 cargo test -p pgdog-masking --test e2e
popd

stop_pgdog
