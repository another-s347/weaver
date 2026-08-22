#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SUITE_DIR=${SUITE_DIR:-"$ROOT_DIR/target/netem-suite/$(date +%Y%m%d-%H%M%S)"}
mkdir -p "$SUITE_DIR"

run_profile() {
  local name=$1 delay=$2 jitter=$3 loss=$4 reorder=$5 rate=$6
  echo "running netem profile: $name"
  RESULT_DIR="$SUITE_DIR/$name" \
    NETEM_DELAY="$delay" NETEM_JITTER="$jitter" NETEM_LOSS="$loss" \
    NETEM_REORDER="$reorder" NETEM_RATE="$rate" \
    BENCH_BYTES=${BENCH_BYTES:-16777216} \
    bash "$ROOT_DIR/scripts/netem-e2e.sh"
}

run_profile latency 100ms 25ms 0.5% 5% 50mbit
run_profile lossy 40ms 10ms 5% 25% 20mbit
run_profile constrained 15ms 5ms 1% 5% 5mbit

echo "netem_suite_dir=$SUITE_DIR"
