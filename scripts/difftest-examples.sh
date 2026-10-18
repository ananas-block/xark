#!/usr/bin/env bash
# Adversarial test of every example on its own test inputs.
#
#   scripts/difftest-examples.sh [example …]     # default: every example under
#                                                # XARK_MAX_ROWS (200000) rows
#
# Builds each example, records its `xark test` inputs (`XARK_DUMP_INPUTS`), then runs
# `difftest --search`: every input, and single-leaf mutations of it, must get the
# verdict the test saw, decided by exhaustive witness search (exactly one witness
# where accepted, none where rejected; a search that can't decide in time is
# counted, not failed). Pass `XARK_DIFF_BASE=<dir>` holding `<example>/circuit.xbc`
# from another build (an older commit) to also compare the two builds' verdicts.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work="$root/target/difftest-examples"
mkdir -p "$work"
[ -n "${XARK_NO_BUILD:-}" ] || cargo build -q --release -p xark-cli -p xark-frontend --example difftest --example xbcstat --manifest-path "$root/Cargo.toml"
xark="$root/target/release/xark"
difftest="$root/target/release/examples/difftest"
stat="$root/target/release/examples/xbcstat"
max_rows="${XARK_MAX_ROWS:-200000}"
names=("$@")
if [ ${#names[@]} -eq 0 ]; then
  for d in "$root"/examples/*/; do
    [ -f "$d/src/lib.rs" ] && grep -q '#\[circuit\]' "$d/src/lib.rs" && names+=("$(basename "$d")")
  done
fi
fails=0
for n in "${names[@]}"; do
  out="$work/build/$n"
  dump="$work/dumps/$n"
  rm -rf "$dump"
  if ! "$xark" build "$root/examples/$n" --out "$out" > "$work/$n.build.log" 2>&1; then
    fails=$((fails + 1)); echo "$n: build FAILED"; continue
  fi
  rows=$("$stat" "$out/circuit.xbc" | awk '{ print $3 }')
  if [ "$rows" -gt "$max_rows" ]; then
    echo "$n: skipped ($rows rows)"
    continue
  fi
  XARK_DUMP_INPUTS="$dump" "$xark" test "$root/examples/$n" > "$work/$n.test.log" 2>&1 || true
  if [ ! -d "$dump" ]; then
    echo "$n: no recorded inputs"
    continue
  fi
  base="${XARK_DIFF_BASE:+$XARK_DIFF_BASE/$n/circuit.xbc}"
  if "$difftest" "${base:-$out/circuit.xbc}" "$out/circuit.xbc" "$dump" --search > "$work/$n.diff.log" 2>&1; then
    echo "$n: $(tail -2 "$work/$n.diff.log" | tr '\n' ' ')"
  else
    fails=$((fails + 1))
    echo "$n: FAILED — $(grep -m3 FAIL "$work/$n.diff.log" | tr '\n' ' ')"
  fi
done
[ $fails -eq 0 ]
