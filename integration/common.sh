#!/bin/bash
# Shared helpers for the integration scripts.
#
# PgDog is built from the repository and revision pgdog-plugin is pinned to in
# Cargo.toml: plugins only load into a PgDog with the same plugin API version,
# built by the same Rust compiler. Set PGDOG_BIN to use your own PgDog build.
ROOT=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )
PGDOG_REPO=$(sed -nE 's/^pgdog-plugin = \{ git = "([^"]+)".*/\1/p' "${ROOT}/Cargo.toml")
PGDOG_REV=$(sed -nE 's/^pgdog-plugin = \{ git = "[^"]+", rev = "([^"]+)".*/\1/p' "${ROOT}/Cargo.toml")

export PGHOST=${PGHOST:-127.0.0.1}
export PGPORT=${PGPORT:-5432}
export PGUSER=${PGUSER:-pgdog}
export PGPASSWORD=${PGPASSWORD:-pgdog}
export PGDATABASE=${PGDATABASE:-pgdog}

# A PgDog source checkout at the pinned revision.
function pgdog_src() {
    local src="${ROOT}/target/pgdog/${PGDOG_REV}"
    if [ ! -d "${src}/.git" ]; then
        rm -rf "${src}"
        git clone --quiet --filter=blob:none "${PGDOG_REPO}" "${src}" >&2
        git -C "${src}" checkout --quiet "${PGDOG_REV}" >&2
    fi
    echo "${src}"
}

# Path to a PgDog binary. $1: debug (default) or release.
#
# Built in PgDog's own checkout, so its .cargo/config.toml (tokio_unstable)
# and rust-toolchain.toml apply.
function pgdog_bin() {
    if [ -n "${PGDOG_BIN:-}" ]; then
        echo "${PGDOG_BIN}"
        return
    fi
    local profile=${1:-debug}
    local src
    src=$(pgdog_src)
    if [ ! -x "${src}/target/${profile}/pgdog" ]; then
        local flags=""
        if [ "${profile}" = "release" ]; then
            flags="--release"
        fi
        echo "Building PgDog (${profile}) at ${PGDOG_REV}" >&2
        (cd "${src}" && cargo build --quiet --locked ${flags} -p pgdog) >&2
    fi
    echo "${src}/target/${profile}/pgdog"
}

PGDOG_PID=""

# Start PgDog with the plugin. $1: config dir with pgdog.toml and users.toml,
# $2: debug or release (which plugin build to load), $3: working directory for
# relative paths in the config (default: this repository).
function start_pgdog() {
    local config=$1 profile=${2:-debug} cwd=${3:-${ROOT}}
    local bin
    bin=$(pgdog_bin "${profile}")
    export LD_LIBRARY_PATH="${ROOT}/target/${profile}"
    export DYLD_LIBRARY_PATH="${LD_LIBRARY_PATH}"
    pushd "${cwd}" > /dev/null
    "${bin}" --config "${config}/pgdog.toml" --users "${config}/users.toml" > "${config}/pgdog.log" 2>&1 &
    PGDOG_PID=$!
    popd > /dev/null
    trap stop_pgdog EXIT
    until pg_isready -h 127.0.0.1 -p 6432 -q; do
        if ! kill -0 "${PGDOG_PID}" 2> /dev/null; then
            echo "PgDog exited; log:"
            tail -20 "${config}/pgdog.log"
            exit 1
        fi
        sleep 0.1
    done
    # Let the schema snapshot reach the plugin.
    sleep 1
}

function stop_pgdog() {
    if [ -n "${PGDOG_PID}" ]; then
        kill "${PGDOG_PID}" 2> /dev/null || true
        wait "${PGDOG_PID}" 2> /dev/null || true
        PGDOG_PID=""
    fi
}
