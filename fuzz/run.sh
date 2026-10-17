#!/usr/bin/env bash
# Run one fuzz target, or all of them, for a while.
#
#   fuzz/run.sh <target|all> [seconds]
#   fuzz/run.sh <target|all> --cmin    # minimize the corpus
#
# New inputs go to fuzz/corpus/<target>; the committed seeds in
# fuzz/seeds/<target> are read too. Crashes land in fuzz/artifacts/<target>.
# FUZZ_RSS_LIMIT_MB overrides libFuzzer's memory limit (default 4096).
# Needs a nightly toolchain and cargo-fuzz (cargo install cargo-fuzz).
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET="${1:?usage: fuzz/run.sh <target|all> [seconds|--cmin]}"
SECONDS_PER_TARGET="${2:-60}"
TARGETS=(statement statement_grammar mask_rows redact_error catalog config)

# Extra libFuzzer flags per target.
flags() {
    case "$1" in
        statement | statement_grammar) echo "-dict=fuzz/dict/sql.dict -max_len=4096" ;;
        catalog) echo "-max_len=8192" ;;
        config) echo "-dict=fuzz/dict/config.dict -max_len=8192" ;;
        *) echo "-max_len=4096" ;;
    esac
}

# The repository pins a stable toolchain; fuzzing needs nightly. Put its
# binaries first, so no other rustc on the PATH is picked up.
if command -v rustup >/dev/null; then
    PATH="$(rustup run nightly rustc --print sysroot)/bin:$PATH"
    export PATH RUSTUP_TOOLCHAIN=nightly
fi

run() {
    local target="$1"
    mkdir -p "fuzz/corpus/$target" "fuzz/artifacts/$target"
    local seeds=() extra
    [[ -d "fuzz/seeds/$target" ]] && seeds=("fuzz/seeds/$target")
    read -ra extra <<<"$(flags "$target")"
    # Optimized, with debug assertions and overflow checks (cargo-fuzz's default).
    cargo fuzz run "$target" "fuzz/corpus/$target" ${seeds[@]+"${seeds[@]}"} -- \
        -max_total_time="$SECONDS_PER_TARGET" \
        -timeout=10 \
        -rss_limit_mb="${FUZZ_RSS_LIMIT_MB:-4096}" \
        -print_final_stats=1 \
        "${extra[@]}"
}

cmin() {
    local target="$1" extra
    [[ -d "fuzz/corpus/$target" ]] || return 0
    read -ra extra <<<"$(flags "$target")"
    cargo fuzz cmin "$target" "fuzz/corpus/$target" -- \
        -rss_limit_mb="${FUZZ_RSS_LIMIT_MB:-4096}" \
        "${extra[@]}"
}

action=run
[[ "$SECONDS_PER_TARGET" == --cmin ]] && action=cmin

if [[ "$TARGET" == all ]]; then
    for target in "${TARGETS[@]}"; do
        "$action" "$target"
    done
else
    "$action" "$TARGET"
fi
