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
#
# Speed: examples share one cargo target (their host dependencies build once),
# `XARK_SWEEP_JOBS` of them (default: half the cores, at most 4) run at once, and
# `XARK_SWEEP_SHARD=k/n` runs only every n-th example from the k-th (CI splits
# the sweep across jobs this way).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work="$root/target/difftest-examples"
mkdir -p "$work/results"
[ -n "${XARK_NO_BUILD:-}" ] || cargo build -q --release -p xark-cli --bin xark -p xark-frontend --example difftest --example xbcstat --manifest-path "$root/Cargo.toml"
export root work
export xark="$root/target/release/xark"
export difftest="$root/target/release/examples/difftest"
export stat="$root/target/release/examples/xbcstat"
export max_rows="${XARK_MAX_ROWS:-2500000}"
# One cargo target for every example's `xark test` build.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$work/target}"
names=("$@")
if [ ${#names[@]} -eq 0 ]; then
  for d in "$root"/examples/*/; do
    [ -f "$d/src/lib.rs" ] && grep -q '#\[circuit\]' "$d/src/lib.rs" && names+=("$(basename "$d")")
  done
fi
if [ -n "${XARK_SWEEP_SHARD:-}" ]; then
  k=${XARK_SWEEP_SHARD%/*} n=${XARK_SWEEP_SHARD#*/} mine=()
  for i in "${!names[@]}"; do [ $((i % n)) -eq "$k" ] && mine+=("${names[$i]}"); done
  names=("${mine[@]}")
fi
# Intentionally unsound examples: the search must find their second witness.
export unsound=" underconstrained_bit "
# Examples whose searches can't decide by design: non-native modular inverses over
# a ~256-bit prime (the witness_search.rs blind spot). They get the verdict checks
# without search; the same gadget code is searched exhaustively over small fields
# (`small_field_curve_gadgets_are_sound`, both curve shapes) and proven in Lean
# (`ec_add_incomplete_*_sound`).
export blindspot=" ec_incomplete ec_incomplete_r1 "
# The ECDSA circuits are made of those inverses: skipped. Their blocks are searched
# instead (`signature_blocks_are_sound`).
export unsearchable=" secp256k1_ecdsa secp256r1_ecdsa "
# Per-search time limit (seconds) for examples that need more than the default:
# ed25519 is searched whole (2.4M rows, ~35 s a search).
export slow=" ed25519:180 "

# Sweep one example: print its line and write `results/<name>` (ok / fail / skip /
# undecided / noinputs).
sweep_one() {
  n=$1
  res="$work/results/$n"
  say() { echo "$n: $2"; echo "$1" > "$res"; }
  if [[ "$unsearchable" == *" $n "* ]]; then
    say skip "skipped (256-bit inverses; its blocks are searched in snapshot.rs)"; return
  fi
  out="$work/build/$n"
  dump="$work/dumps/$n"
  rm -rf "$dump"
  if ! "$xark" build "$root/examples/$n" --out "$out" > "$work/$n.build.log" 2>&1; then
    say fail "build FAILED"; return
  fi
  rows=$("$stat" --rows "$out/circuit.xbc")
  if [ "$rows" -gt "$max_rows" ]; then
    say skip "skipped ($rows rows > XARK_MAX_ROWS)"; return
  fi
  if ! XARK_DUMP_INPUTS="$dump" "$xark" test "$root/examples/$n" > "$work/$n.test.log" 2>&1; then
    say fail "FAILED — xark test (see $work/$n.test.log)"; return
  fi
  if [ ! -d "$dump" ]; then
    say noinputs "no recorded inputs — nothing to search"; return
  fi
  base="${XARK_DIFF_BASE:+$XARK_DIFF_BASE/$n/circuit.xbc}"
  log="$work/$n.diff.log"
  if [[ "$unsound" == *" $n "* ]]; then
    "$difftest" "${base:-$out/circuit.xbc}" "$out/circuit.xbc" "$dump" --search > "$log" 2>&1 || true
    if grep -q "two witnesses" "$log"; then
      say ok "intentionally under-constrained — second witness found"
    else
      say fail "FAILED — its known under-constraint went undetected"
    fi
    return
  fi
  if [[ "$blindspot" == *" $n "* ]]; then
    if "$difftest" "${base:-$out/circuit.xbc}" "$out/circuit.xbc" "$dump" > "$log" 2>&1; then
      say ok "verdicts agree; not searched (256-bit inverse — covered by the small-field search and Lean)"
    else
      say fail "FAILED — $(grep -m3 FAIL "$log" | tr '\n' ' ')"
    fi
    return
  fi
  status=0
  secs=$(sed -n "s/.* $n:\([0-9]*\) .*/\1/p" <<<"$slow")
  XARK_SEARCH_SECS="${secs:-${XARK_SEARCH_SECS:-20}}" \
    "$difftest" "${base:-$out/circuit.xbc}" "$out/circuit.xbc" "$dump" --search > "$log" 2>&1 || status=$?
  case $status in
    0) say ok "$(tail -2 "$log" | tr '\n' ' ')";;
    2) say undecided "undecided — every search inconclusive";;
    *) say fail "FAILED — $(grep -m3 FAIL "$log" | tr '\n' ' ')";;
  esac
}
export -f sweep_one

jobs="${XARK_SWEEP_JOBS:-$(( $(getconf _NPROCESSORS_ONLN) / 2 ))}"
[ "$jobs" -ge 1 ] || jobs=1
[ "$jobs" -le 4 ] || jobs=4
for n in "${names[@]}"; do rm -f "$work/results/$n"; done
printf '%s\n' "${names[@]}" | xargs -P "$jobs" -I{} bash -c 'sweep_one "$1"' _ {}

count() { local c=0; for n in "${names[@]}"; do [ "$(cat "$work/results/$n" 2>/dev/null)" = "$1" ] && c=$((c + 1)); done; echo $c; }
list() { local l=""; for n in "${names[@]}"; do [ "$(cat "$work/results/$n" 2>/dev/null)" = "$1" ] && l="$l $n"; done; echo "${l:- none}"; }
fails=$(count fail)
missing=0
for n in "${names[@]}"; do [ -f "$work/results/$n" ] || { echo "$n: FAILED — no result"; missing=$((missing + 1)); }; done
echo "${#names[@]} examples: $((fails + missing)) failed, $(count skip) skipped, undecided:$(list undecided), no inputs:$(list noinputs)"
[ $((fails + missing)) -eq 0 ]
