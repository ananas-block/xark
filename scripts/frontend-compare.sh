#!/usr/bin/env bash
# Build every example with both frontends and tabulate circuit size (setup-minimized
# rows / variables, what Groth16 pays for), stable vs MIR.
#
#   scripts/frontend-compare.sh [example …]     # default: every example
#
# Needs the pinned nightly for the MIR builds. Writes target/frontend-compare/table.md.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work="$root/target/frontend-compare"
mkdir -p "$work"
cargo build -q --release -p xark-cli -p xark-frontend --example xbcstat --manifest-path "$root/Cargo.toml"
xark="$root/target/release/xark"
stat="$root/target/release/examples/xbcstat"
# The MIR driver, as the test harness builds it.
export XARK_RUSTC="${XARK_RUSTC:-$root/crates/rustc/target/release/xark-rustc}"
names=("$@")
if [ ${#names[@]} -eq 0 ]; then
  for d in "$root"/examples/*/; do
    [ -f "$d/src/lib.rs" ] && grep -q '#\[circuit\]' "$d/src/lib.rs" && names+=("$(basename "$d")")
  done
fi
table="$work/table.md"
{
  echo "| example | MIR rows | stable rows | Δ rows | MIR vars | stable vars | Δ vars |"
  echo "|---|---:|---:|---:|---:|---:|---:|"
} > "$table"
pct() { awk -v a="$1" -v b="$2" 'BEGIN { if (a == 0) print "–"; else printf "%+.1f%%", (b - a) * 100 / a }'; }
for n in "${names[@]}"; do
  d="$root/examples/$n"
  ok=1
  "$xark" build "$d" --frontend mir --out "$work/mir/$n" > "$work/$n.mir.log" 2>&1 || ok=0
  "$xark" build "$d" --out "$work/stable/$n" > "$work/$n.stable.log" 2>&1 || ok=0
  if [ $ok = 0 ]; then
    echo "| $n | build failed (see $work/$n.*.log) | | | | | |" >> "$table"
    continue
  fi
  read -r _ _ _ _ mr _ mv _ _ < <("$stat" "$work/mir/$n/circuit.xbc")
  read -r _ _ _ _ sr _ sv _ _ < <("$stat" "$work/stable/$n/circuit.xbc")
  echo "| $n | $mr | $sr | $(pct "$mr" "$sr") | $mv | $sv | $(pct "$mv" "$sv") |" >> "$table"
  echo "$n: rows $mr → $sr, vars $mv → $sv"
done
echo "wrote $table"
