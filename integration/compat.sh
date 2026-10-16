#!/bin/bash
# Driver and ORM compatibility: runs the Go suites (pgx, pq, gorm) through
# PgDog with the masking plugin loaded and every user masked.
set -e
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source "${SCRIPT_DIR}/common.sh"

# The suites, their config and their databases come from PgDog's repository
# (see integration/setup.sh there).
SRC=$(pgdog_src)
CONFIG_DIR=$(mktemp -d)
cp "${SRC}/integration/users.toml" "${CONFIG_DIR}/users.toml"
cp "${SRC}/integration/pgdog.toml" "${CONFIG_DIR}/pgdog.toml"
cat >> "${CONFIG_DIR}/pgdog.toml" <<TOML

[[plugins]]
name = "pgdog_mask"
config = "${SCRIPT_DIR}/compat.toml"
required = true
TOML

cd "${ROOT}"
cargo build
# PgDog's config has paths relative to its repository (TLS certificates).
start_pgdog "${CONFIG_DIR}" debug "${SRC}"

# Run every suite even if one fails, so results can be compared with a run
# without the plugin (integration/go/run.sh in PgDog's repository).
status=0
for suite in go_pgx go_pq go_gorm; do
    bash "${SRC}/integration/go/${suite}/dev.sh" || status=1
done

stop_pgdog
rm -rf "${CONFIG_DIR}"
exit ${status}
