#!/usr/bin/env bash
# Check the generated TypeScript clients of the representative examples.
#
#   scripts/codegen-check.sh            # check
#   scripts/codegen-check.sh --update   # rewrite the committed clients
#
# For each example in EXAMPLES: build it, make dev keys, and regenerate its client
# with `xark codegen ts`; the committed `examples/<name>/client/<name>.ts` must
# match (so a codegen change shows up in review). Then typecheck every client and
# its `test.ts`, and run each test: prove with typed inputs through xark-wasm,
# verify, and check that wrong public inputs and unsatisfiable inputs fail.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
EXAMPLES="cube zk_kyc sha256 merkle"
cargo build -q --release -p xark-cli --bin xark --manifest-path "$root/Cargo.toml"
xark="$root/target/release/xark"
[ -f "$root/crates/wasm/dist/node/xark_wasm.js" ] && [ -z "${XARK_REBUILD_WASM:-}" ] ||
  wasm-pack build "$root/crates/wasm" --target nodejs --release --out-dir dist/node
tmp=$(mktemp -d)
stale=0
for n in $EXAMPLES; do
  d="$root/examples/$n"
  "$xark" build "$d" > "$tmp/$n.log" 2>&1 || { cat "$tmp/$n.log"; exit 1; }
  "$xark" setup "$d" --insecure-dev-mode --deterministic-rng 1 >> "$tmp/$n.log" 2>&1 ||
    { cat "$tmp/$n.log"; exit 1; }
  "$xark" codegen ts "$d" --out "$tmp/$n.ts" >> "$tmp/$n.log" 2>&1 || { cat "$tmp/$n.log"; exit 1; }
  if [ "${1:-}" = "--update" ]; then
    cp "$tmp/$n.ts" "$d/client/$n.ts"
  elif ! diff -u "$d/client/$n.ts" "$tmp/$n.ts"; then
    echo "$n: the committed client is stale (run scripts/codegen-check.sh --update)"
    stale=1
  fi
done
[ $stale -eq 0 ]
cd "$root/clients/codegen-check"
[ -d node_modules ] || npm ci --silent
npx tsc --noEmit
for n in $EXAMPLES; do
  npx tsx "$root/examples/$n/client/test.ts"
done
