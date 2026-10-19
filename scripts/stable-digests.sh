#!/usr/bin/env bash
# Fingerprint every example circuit built by the stable frontend with the ambient
# toolchain (`RUSTUP_TOOLCHAIN` selects another), one `<example> <digest>` per line.
#
#   scripts/stable-digests.sh            # print
#   scripts/stable-digests.sh --check    # compare with tests/stable-digests.txt
#   scripts/stable-digests.sh --update   # rewrite tests/stable-digests.txt
#
# The digest is `stream_digest` of the R1CS: the same on every supported rustc
# (1.89+), which is the stable frontend's reproducibility guarantee. A difference
# means either a toolchain changed the circuit (a bug to report) or the lowering
# changed on purpose (run --update and review).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
want="$root/tests/stable-digests.txt"
# The dev tool is built with the workspace's own toolchain (only the circuits are
# built with the toolchain under test).
env -u RUSTUP_TOOLCHAIN cargo build -q --release -p xark-frontend --example stablec --manifest-path "$root/Cargo.toml"
stablec="$root/target/release/examples/stablec"
tc=$(rustc --version | tr ' ' '_')
out=$(mktemp)
for d in "$root"/examples/*/; do
  [ -f "$d/src/lib.rs" ] && grep -q '#\[circuit\]' "$d/src/lib.rs" || continue
  n=$(basename "$d")
  r=$(XARK_WASM_TARGET_DIR="$root/target/stable-digests/$tc/$n" "$stablec" "$d" 2>&1) || true
  dg=$(sed -n 's/.*digest \([0-9a-f]*\).*/\1/p' <<<"$r" | head -1)
  echo "$n ${dg:-BUILD-FAILED}" >> "$out"
done
case "${1:-}" in
  --update) cp "$out" "$want"; echo "wrote $want ($(wc -l < "$want") circuits)";;
  --check)
    if diff -u "$want" "$out"; then echo "all $(wc -l < "$out") circuits match ($(rustc --version))";
    else echo "circuit digests differ under $(rustc --version)"; exit 1; fi;;
  *) cat "$out";;
esac
