#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BUILD_PROFILE=${BUILD_PROFILE:-debug}
if [[ "$BUILD_PROFILE" != "debug" && "$BUILD_PROFILE" != "release" ]]; then
  echo "BUILD_PROFILE must be debug or release" >&2
  exit 2
fi
SIM_BIN="$ROOT_DIR/target/$BUILD_PROFILE/weaver-net-sim"
RELAY_BIN="$ROOT_DIR/target/$BUILD_PROFILE/weaver-relay"
RESULT_DIR=${RESULT_DIR:-"$ROOT_DIR/target/netem-results/$(date +%Y%m%d-%H%M%S)"}
NETEM_DELAY=${NETEM_DELAY:-40ms}
NETEM_JITTER=${NETEM_JITTER:-10ms}
NETEM_LOSS=${NETEM_LOSS:-3%}
NETEM_REORDER=${NETEM_REORDER:-20%}
NETEM_CORRELATION=${NETEM_CORRELATION:-50%}
NETEM_RATE=${NETEM_RATE:-20mbit}
NETEM_DISABLED=${NETEM_DISABLED:-0}
BENCH_BYTES=${BENCH_BYTES:-33554432}
PING_COUNT=${PING_COUNT:-32}
E2E_TIMEOUT=${E2E_TIMEOUT:-90}

if [[ ${1:-} != "--inner" ]]; then
  for tool in ip tc nsenter unshare; do
    command -v "$tool" >/dev/null || {
      echo "missing required Linux tool: $tool" >&2
      exit 2
    }
  done
  build_args=(build --manifest-path "$ROOT_DIR/Cargo.toml" -p weaver-net-sim -p weaver-relay --offline)
  if [[ "$BUILD_PROFILE" == "release" ]]; then
    build_args+=(--release)
  fi
  CARGO_HOME=${CARGO_HOME:-"$ROOT_DIR/.cargo-home"} cargo "${build_args[@]}"
  mkdir -p "$RESULT_DIR"
  export ROOT_DIR SIM_BIN RELAY_BIN BUILD_PROFILE RESULT_DIR NETEM_DELAY NETEM_JITTER
  export NETEM_LOSS NETEM_REORDER NETEM_CORRELATION NETEM_RATE
  export NETEM_DISABLED
  export BENCH_BYTES PING_COUNT E2E_TIMEOUT
  echo "netem_result_dir=$RESULT_DIR"
  exec unshare --user --map-root-user --net -- \
    bash "$0" --inner
fi

declare -a CLEANUP_PIDS=()
cleanup() {
  local pid
  for pid in "${CLEANUP_PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait_for_line() {
  local file=$1
  local pattern=$2
  local timeout_seconds=$3
  local deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    if grep -q -- "$pattern" "$file" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for '$pattern' in $file" >&2
  sed -n '1,200p' "$file" >&2 || true
  return 1
}

apply_netem() {
  local command_prefix=$1
  local device=$2
  if [[ "$NETEM_DISABLED" == "1" ]]; then
    return 0
  fi
  # shellcheck disable=SC2086
  $command_prefix tc qdisc replace dev "$device" root netem \
    delay "$NETEM_DELAY" "$NETEM_JITTER" distribution normal \
    loss random "$NETEM_LOSS" "$NETEM_CORRELATION" \
    reorder "$NETEM_REORDER" "$NETEM_CORRELATION" \
    rate "$NETEM_RATE"
}

start_holder() {
  unshare --net -- sleep infinity &
  HOLDER_PID=$!
  CLEANUP_PIDS+=("$HOLDER_PID")
}

configure_wan() {
  local holder_pid=$1
  local host_if=$2
  local subnet=$3
  ip link add "$host_if" type veth peer name eth0
  ip link set eth0 netns "$holder_pid"
  ip addr add "10.10.${subnet}.1/24" dev "$host_if"
  ip link set "$host_if" up
  nsenter -t "$holder_pid" -n -- ip link set lo up
  nsenter -t "$holder_pid" -n -- ip addr add "10.10.${subnet}.2/24" dev eth0
  nsenter -t "$holder_pid" -n -- ip link set eth0 up
  nsenter -t "$holder_pid" -n -- ip route add default via "10.10.${subnet}.1"
  apply_netem "" "$host_if"
  apply_netem "nsenter -t $holder_pid -n --" eth0
}

start_holder
A_HOLDER=$HOLDER_PID
start_holder
C_HOLDER=$HOLDER_PID
ip link set lo up
ip addr add 10.255.0.1/32 dev lo
configure_wan "$A_HOLDER" wa-host 1
configure_wan "$C_HOLDER" wc-host 2

RELAY_LOG="$RESULT_DIR/relay.log"
SERVER_LOG="$RESULT_DIR/server.log"
CLIENT_LOG="$RESULT_DIR/client.log"
REPORT_JSON="$RESULT_DIR/report.json"

"$RELAY_BIN" --listen 0.0.0.0:3340 >"$RELAY_LOG" 2>&1 &
RELAY_PID=$!
CLEANUP_PIDS+=("$RELAY_PID")
wait_for_line "$RELAY_LOG" "relay_url=" 15

nsenter -t "$A_HOLDER" -n -- env \
  -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
  NO_PROXY=10.255.0.1,127.0.0.1 no_proxy=10.255.0.1,127.0.0.1 \
  "$SIM_BIN" server --relay-url http://10.255.0.1:3340 \
  >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
CLEANUP_PIDS+=("$SERVER_PID")
wait_for_line "$SERVER_LOG" "SIM_SERVER_READY" 20

nsenter -t "$C_HOLDER" -n -- env \
  -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
  NO_PROXY=10.255.0.1,127.0.0.1 no_proxy=10.255.0.1,127.0.0.1 \
  "$SIM_BIN" client --relay-url http://10.255.0.1:3340 \
    --report "$REPORT_JSON" --bytes "$BENCH_BYTES" --ping-count "$PING_COUNT" \
  >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
CLEANUP_PIDS+=("$CLIENT_PID")
wait_for_line "$CLIENT_LOG" "SIM_CLIENT_READY_FOR_LAN" 30

# Insert a new shared LAN while the same reliable stream is carrying checked data.
ip link add lan-a type veth peer name lan-c
ip link set lan-a netns "$A_HOLDER"
ip link set lan-c netns "$C_HOLDER"
nsenter -t "$A_HOLDER" -n -- ip addr add 10.20.0.1/24 dev lan-a
nsenter -t "$C_HOLDER" -n -- ip addr add 10.20.0.2/24 dev lan-c
nsenter -t "$A_HOLDER" -n -- ip link set lan-a up
nsenter -t "$C_HOLDER" -n -- ip link set lan-c up
apply_netem "nsenter -t $A_HOLDER -n --" lan-a
apply_netem "nsenter -t $C_HOLDER -n --" lan-c
kill -USR1 "$SERVER_PID" "$CLIENT_PID"

deadline=$((SECONDS + E2E_TIMEOUT))
while kill -0 "$CLIENT_PID" 2>/dev/null && (( SECONDS < deadline )); do
  sleep 0.2
done
if kill -0 "$CLIENT_PID" 2>/dev/null; then
  echo "client exceeded ${E2E_TIMEOUT}s" >&2
  exit 1
fi
if ! wait "$CLIENT_PID"; then
  echo "client benchmark failed" >&2
  sed -n '1,240p' "$CLIENT_LOG" >&2
  sed -n '1,160p' "$SERVER_LOG" >&2
  exit 1
fi
if ! wait "$SERVER_PID"; then
  echo "server benchmark failed" >&2
  sed -n '1,240p' "$SERVER_LOG" >&2
  exit 1
fi

if [[ "$NETEM_DISABLED" == "1" ]]; then
  echo "netem_profile=disabled"
else
  echo "netem_profile=delay:$NETEM_DELAY jitter:$NETEM_JITTER loss:$NETEM_LOSS reorder:$NETEM_REORDER rate:$NETEM_RATE"
fi
echo "benchmark_report=$REPORT_JSON"
{
  echo "wan-a outbound"
  tc -s qdisc show dev wa-host
  echo "wan-a inbound"
  nsenter -t "$A_HOLDER" -n -- tc -s qdisc show dev eth0
  echo "wan-c outbound"
  tc -s qdisc show dev wc-host
  echo "wan-c inbound"
  nsenter -t "$C_HOLDER" -n -- tc -s qdisc show dev eth0
  echo "lan-a"
  nsenter -t "$A_HOLDER" -n -- tc -s qdisc show dev lan-a
  echo "lan-c"
  nsenter -t "$C_HOLDER" -n -- tc -s qdisc show dev lan-c
} >"$RESULT_DIR/netem-stats.txt"
echo "netem_stats=$RESULT_DIR/netem-stats.txt"
cat "$REPORT_JSON"
