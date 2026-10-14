#!/usr/bin/env bash
# Phase 0 runner: reproduce the noisy-neighbor problem with schbench.
#
# Usage (on the lab VM, as root):
#   sudo ./run.sh <arm> [runs]
#
# Arms:
#   alone   schbench only, default kernel scheduler
#   noise   schbench + stress-ng on every CPU, default kernel scheduler
#   hand    schbench + stress-ng under scx_layered, once per config in CONFIGS
#           (results are labelled hand-<config name>)
#   all     every arm above, interleaved run by run
#
# Tunables (environment variables):
#   RPS=400          fixed request rate for schbench; each request is ~5ms of CPU,
#                    so 400 rps keeps the service at ~2 of 8 vCPUs
#   DURATION=30      seconds per schbench run
#   CONFIGS="s1-hand-g"  space-separated config names from bench/configs/ (no .json)
#   OUT=...          results directory (default: results/<timestamp>)

set -euo pipefail

ARM="${1:?usage: sudo ./run.sh <alone|noise|hand|all> [runs]}"
RUNS="${2:-5}"
RPS="${RPS:-400}"
DURATION="${DURATION:-30}"
CONFIGS="${CONFIGS:-s1-hand-g}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="$HERE/../configs"
OUT="${OUT:-$HERE/results/$(date +%Y%m%d-%H%M%S)}"
NCPU="$(nproc)"
SCX_STATE=/sys/kernel/sched_ext/state

NOISE_PID=""
SCHED_PID=""

die() { echo "error: $*" >&2; exit 1; }
log() { echo "[$(date +%H:%M:%S)] $*"; }

[[ $EUID -eq 0 ]] || die "run as root (sudo) so scx_layered can load"
command -v schbench >/dev/null || die "schbench not on PATH"
command -v stress-ng >/dev/null || die "stress-ng not on PATH"
command -v scx_layered >/dev/null || die "scx_layered not on PATH"
for c in $CONFIGS; do
	[[ -f $CONFIG_DIR/$c.json ]] || die "config not found: $CONFIG_DIR/$c.json"
done

wait_state() { # wait_state <enabled|disabled> <timeout_s>
	local want=$1 deadline=$((SECONDS + $2))
	while [[ $(cat "$SCX_STATE") != "$want" ]]; do
		((SECONDS < deadline)) || return 1
		sleep 0.2
	done
}

start_noise() { # start_noise <logfile>
	# One CPU hog per vCPU. The timeout covers ramp-up plus the schbench run,
	# so stress-ng exits on its own and prints its throughput (bogo ops/s).
	stress-ng --cpu "$NCPU" --metrics-brief --timeout "$((DURATION + 5))s" >"$1" 2>&1 &
	NOISE_PID=$!
	sleep 3 # let the hogs ramp up before measuring
}

stop_noise() { # stop_noise [kill]
	[[ -n $NOISE_PID ]] || return 0
	if [[ ${1:-} == kill ]]; then
		kill "$NOISE_PID" 2>/dev/null || true
		pkill -x stress-ng 2>/dev/null || true
	fi
	wait "$NOISE_PID" 2>/dev/null || true
	NOISE_PID=""
}

start_sched() { # start_sched <config> <logfile>
	# --stats 1 logs per-layer CPU allocation, utilization and task counts every second.
	scx_layered --stats 1 "f:$1" >"$2" 2>&1 &
	SCHED_PID=$!
	wait_state enabled 15 || die "scx_layered did not enable; see $2"
	log "scx_layered enabled ($(cat /sys/kernel/sched_ext/root/ops))"
}

stop_sched() {
	[[ -n $SCHED_PID ]] || return 0
	kill -INT "$SCHED_PID" 2>/dev/null || true
	wait "$SCHED_PID" 2>/dev/null || true
	SCHED_PID=""
	wait_state disabled 15 || die "sched_ext still enabled after stopping scx_layered"
}

cleanup() {
	stop_noise kill
	stop_sched
	[[ -n ${SUDO_USER:-} && -d $OUT ]] && chown -R "$SUDO_USER" "$OUT"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

run_one() { # run_one <arm> <n>   arm is alone, noise or hand-<config>
	local arm=$1 n=$2
	local base="$OUT/$arm-$n"
	[[ $(cat "$SCX_STATE") == disabled ]] || die "another sched_ext scheduler is loaded"
	log "arm=$arm run=$n/$RUNS"

	case $arm in
	alone) ;;
	noise) start_noise "$base.noise.log" ;;
	hand-*)
		start_sched "$CONFIG_DIR/${arm#hand-}.json" "$base.sched.log"
		start_noise "$base.noise.log"
		;;
	*) die "unknown arm: $arm" ;;
	esac

	schbench -m 2 -t 4 -r "$DURATION" -R "$RPS" >"$base.txt" 2>&1

	stop_noise
	stop_sched
	sleep 5 # cool down between runs
}

HAND_ARMS=()
for c in $CONFIGS; do HAND_ARMS+=("hand-$c"); done
case $ARM in
alone | noise) ARMS=("$ARM") ;;
hand) ARMS=("${HAND_ARMS[@]}") ;;
all) ARMS=(alone noise "${HAND_ARMS[@]}") ;;
*) die "unknown arm: $ARM" ;;
esac

mkdir -p "$OUT"
{
	echo "date: $(date -Is)"
	echo "host: $(hostname)"
	echo "kernel: $(uname -r)"
	echo "cpus: $NCPU"
	echo "cpu_model: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
	echo "scx_layered: $(scx_layered --version 2>&1 | head -1)"
	echo "schbench_args: -m 2 -t 4 -r $DURATION -R $RPS"
	echo "noise: stress-ng --cpu $NCPU"
	echo "arms: ${ARMS[*]}"
	echo "runs: $RUNS"
} >"$OUT/meta.txt"
for c in $CONFIGS; do cp "$CONFIG_DIR/$c.json" "$OUT/"; done

# Interleave arms run by run so slow drift on the host (thermal, cloud
# neighbours) hits every arm equally instead of biasing whichever ran last.
for n in $(seq 1 "$RUNS"); do
	for a in "${ARMS[@]}"; do run_one "$a" "$n"; done
done

log "done: $OUT"
python3 "$HERE/parse.py" "$OUT" || true
