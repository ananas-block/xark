#!/usr/bin/env bash
# Differential + adversarial test of every example's two builds on its own test inputs.
#
#   scripts/difftest-examples.sh [example …]     # default: examples under 200k rows
#
# Records each example's `xark test` inputs (`XARK_DUMP_INPUTS`), then runs
# `difftest` on the MIR and stable builds from `scripts/frontend-compare.sh` (run
# that first): both builds must agree with the test on every input and on single-leaf
# mutations of it, and `--search` decides each one on the stable build by exhaustive
# witness search (exactly one witness where accepted, none where rejected).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work="$root/target/frontend-compare"
[ -n "${XARK_NO_BUILD:-}" ] || cargo build -q --release -p xark-cli -p xark-frontend --example difftest --manifest-path "$root/Cargo.toml"
xark="$root/target/release/xark"
difftest="$root/target/release/examples/difftest"
names=("$@")
if [ ${#names[@]} -eq 0 ]; then
  while read -r n rows; do
    [ "$rows" -lt 200000 ] && names+=("$n")
  done < <(awk -F'|' 'NR > 2 && $4 ~ /[0-9]/ { gsub(/ /, "", $2); gsub(/ /, "", $4); print $2, $4 }' "$work/table.md")
fi
fails=0
for n in "${names[@]}"; do
  dump="$work/dumps/$n"
  rm -rf "$dump"
  XARK_DUMP_INPUTS="$dump" "$xark" test "$root/examples/$n" > "$work/$n.test.log" 2>&1 || true
  if [ ! -d "$dump" ]; then
    echo "$n: no recorded inputs"
    continue
  fi
  if "$difftest" "$work/mir/$n/circuit.xbc" "$work/stable/$n/circuit.xbc" "$dump" --search > "$work/$n.diff.log" 2>&1; then
    echo "$n: $(tail -2 "$work/$n.diff.log" | tr '\n' ' ')"
  else
    fails=$((fails + 1))
    echo "$n: FAILED — $(grep -m3 FAIL "$work/$n.diff.log" | tr '\n' ' ')"
  fi
done
[ $fails -eq 0 ]
