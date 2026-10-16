#!/bin/bash
# Driver and ORM compatibility: runs the Go suites (pgx, pq, gorm) through
# PgDog with the masking plugin loaded and every user masked. Compare with
# integration/go/run.sh, which runs them without the plugin.
set -e
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source ${SCRIPT_DIR}/../common.sh
ROOT=$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )

CONFIG_DIR=$(mktemp -d)
cp ${ROOT}/integration/users.toml ${CONFIG_DIR}/users.toml
cp ${ROOT}/integration/pgdog.toml ${CONFIG_DIR}/pgdog.toml
cat >> ${CONFIG_DIR}/pgdog.toml <<TOML

[[plugins]]
name = "pgdog_masking"
config = "${SCRIPT_DIR}/compat.toml"
required = true
TOML

pushd ${ROOT}
cargo build -p pgdog-masking
popd

export LD_LIBRARY_PATH=${ROOT}/target/debug
export DYLD_LIBRARY_PATH=${LD_LIBRARY_PATH}

run_pgdog ${CONFIG_DIR}
wait_for_pgdog

# Run every suite even if one fails, so results can be compared with a run
# without the plugin.
status=0
for suite in go_pgx go_pq go_gorm; do
    bash ${ROOT}/integration/go/${suite}/dev.sh || status=1
done

stop_pgdog
rm -rf ${CONFIG_DIR}
exit ${status}
