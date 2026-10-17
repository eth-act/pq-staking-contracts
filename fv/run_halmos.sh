#!/usr/bin/env bash
# Run each Halmos check function separately (per-check timeout, limited parallelism) and
# collect the result line of each into fv/logs/summary_<tag>.txt.
# usage: run_halmos.sh TAG TIMEOUT_S PARALLEL CONTRACT:FUNCTION...
set -u
tag=$1 to=$2 par=$3
shift 3
cd "$(dirname "$0")/../contracts"
mkdir -p ../fv/logs
halmos --contract __none__ >/dev/null 2>&1 # build once
run() {
  local c=${1%%:*} f=${1##*:}
  local log=../fv/logs/h_${c}_${f}.log
  timeout "$to" halmos --contract "$c" --function "^${f}\\(" --loop 20 \
    --solver-timeout-branching 5s --solver-timeout-assertion 0 >"$log" 2>&1
  local rc=$?
  local line
  line=$(grep -E "\[(PASS|FAIL|ERROR|TIMEOUT)\]" "$log" | sed 's/\x1b\[[0-9;]*m//g' | head -1)
  [ -z "$line" ] && line="[NO RESULT rc=$rc] $f"
  local warn
  warn=$(grep -c "not been fully explored" "$log")
  echo "$c $line incomplete_warnings=$warn"
}
export -f run
export to
printf '%s\n' "$@" | xargs -P "$par" -I{} bash -c 'run "$@"' _ {} | tee ../fv/logs/summary_"$tag".txt
