#!/usr/bin/env bash
# Adversarial test of every example on its own test inputs.
#
#   scripts/difftest-examples.sh [example …]     # default: every example under
#                                                # XARK_MAX_ROWS (2500000) rows
#
# Builds each example, records its `xark test` inputs (`XARK_DUMP_INPUTS`), then runs
# `difftest --search`: every input, and single-leaf mutations of it, must get the
# verdict the test saw, decided by exhaustive witness search (exactly one witness
# where accepted, none where rejected; a search that can't decide in time is
# counted, not failed — but an example where *no* search decides is reported as
# undecided). A build failure or a failing `xark test` is a failure; an example
# whose tests record no inputs (heavy tests are `#[ignore]`d, or they only drive
# the prover) is listed, not failed. Pass `XARK_DIFF_BASE=<dir>` holding
# `<example>/circuit.xbc` from another build (an older commit) to also compare the
# two builds' verdicts. `XARK_SEARCH_SECS` / `XARK_SEARCH_BUDGET` set the per-search
# limits (see difftest.rs).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work="$root/target/difftest-examples"
mkdir -p "$work"
[ -n "${XARK_NO_BUILD:-}" ] || cargo build -q --release -p xark-cli --bin xark -p xark-frontend --example difftest --example xbcstat --manifest-path "$root/Cargo.toml"
xark="$root/target/release/xark"
difftest="$root/target/release/examples/difftest"
stat="$root/target/release/examples/xbcstat"
max_rows="${XARK_MAX_ROWS:-2500000}"
names=("$@")
if [ ${#names[@]} -eq 0 ]; then
  for d in "$root"/examples/*/; do
    [ -f "$d/src/lib.rs" ] && grep -q '#\[circuit\]' "$d/src/lib.rs" && names+=("$(basename "$d")")
  done
fi
# Intentionally unsound examples: the search must find their second witness.
unsound=" underconstrained_bit "
# Examples whose searches can't decide by design: non-native modular inverses over
# a ~256-bit prime (the witness_search.rs blind spot). The same gadget code is
# searched exhaustively over small fields (`small_field_curve_gadgets_are_sound`,
# both curve shapes) and proven in Lean (`ec_add_incomplete_*_sound`).
blindspot=" ec_incomplete ec_incomplete_r1 "
# The ECDSA circuits are made of those inverses: searching them only reaches
# "inconclusive", slowly. Their blocks are searched instead (`signature_blocks_are_sound`).
unsearchable=" secp256k1_ecdsa secp256r1_ecdsa "
# Per-search time limit (seconds) for examples that need more than the default:
# ed25519 is searched whole (2.4M rows, ~35 s a search).
slow=" ed25519:180 "
fails=0
skipped=0
undecided=""
noinputs=""
for n in "${names[@]}"; do
  if [[ "$unsearchable" == *" $n "* ]]; then
    skipped=$((skipped + 1)); echo "$n: skipped (256-bit inverses; its blocks are searched in snapshot.rs)"
    continue
  fi
  out="$work/build/$n"
  dump="$work/dumps/$n"
  rm -rf "$dump"
  if ! "$xark" build "$root/examples/$n" --out "$out" > "$work/$n.build.log" 2>&1; then
    fails=$((fails + 1)); echo "$n: build FAILED"; continue
  fi
  rows=$("$stat" --rows "$out/circuit.xbc")
  if [ "$rows" -gt "$max_rows" ]; then
    skipped=$((skipped + 1)); echo "$n: skipped ($rows rows > XARK_MAX_ROWS)"
    continue
  fi
  if ! XARK_DUMP_INPUTS="$dump" "$xark" test "$root/examples/$n" > "$work/$n.test.log" 2>&1; then
    fails=$((fails + 1)); echo "$n: FAILED — xark test (see $work/$n.test.log)"
    continue
  fi
  if [ ! -d "$dump" ]; then
    noinputs="$noinputs $n"; echo "$n: no recorded inputs — nothing to search"
    continue
  fi
  base="${XARK_DIFF_BASE:+$XARK_DIFF_BASE/$n/circuit.xbc}"
  if [[ "$unsound" == *" $n "* ]]; then
    "$difftest" "${base:-$out/circuit.xbc}" "$out/circuit.xbc" "$dump" --search > "$work/$n.diff.log" 2>&1 || true
    if grep -q "two witnesses" "$work/$n.diff.log"; then
      echo "$n: intentionally under-constrained — second witness found"
    else
      fails=$((fails + 1)); echo "$n: FAILED — its known under-constraint went undetected"
    fi
    continue
  fi
  status=0
  secs=$(sed -n "s/.* $n:\([0-9]*\) .*/\1/p" <<<"$slow")
  XARK_SEARCH_SECS="${secs:-${XARK_SEARCH_SECS:-20}}" \
    "$difftest" "${base:-$out/circuit.xbc}" "$out/circuit.xbc" "$dump" --search > "$work/$n.diff.log" 2>&1 || status=$?
  case $status in
    0) echo "$n: $(tail -2 "$work/$n.diff.log" | tr '\n' ' ')";;
    2) if [[ "$blindspot" == *" $n "* ]]; then
         echo "$n: verdicts agree; search inconclusive by design (256-bit inverse — covered by the small-field search and Lean)"
       else
         undecided="$undecided $n"; echo "$n: undecided — every search inconclusive"
       fi;;
    *) fails=$((fails + 1)); echo "$n: FAILED — $(grep -m3 FAIL "$work/$n.diff.log" | tr '\n' ' ')";;
  esac
done
echo "${#names[@]} examples: $fails failed, $skipped skipped, undecided:${undecided:- none}, no inputs:${noinputs:- none}"
[ $fails -eq 0 ]
