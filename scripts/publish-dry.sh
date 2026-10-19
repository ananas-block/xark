#!/usr/bin/env bash
# Rehearse a crates.io release: package every publishable crate and build each
# one from its own `.crate`, as crates.io will see it. Uploads nothing.
#
#   scripts/publish-dry.sh            # (or: make -f Makefile.publish publish-dry)
#
# A plain `cargo publish --dry-run -p <crate>` can't do this before a release:
# it resolves the crate's xark dependencies at the new version from crates.io,
# where they aren't yet. `cargo package --workspace` resolves them from the
# other local packages instead, but `xark` (crates/lang) is its own workspace,
# so this runs in a throwaway copy of HEAD where it is a member. Uncommitted
# changes are not included.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
copy="$root/target/publish-dry"
rm -rf "$copy"
mkdir -p "$copy"
git -C "$root" archive HEAD | tar -x -C "$copy"
cd "$copy"
python3 - <<'EOF'
import re
s = open("Cargo.toml").read()
s = re.sub(r'(exclude = \[[^\]]*?)\s*"crates/lang",', r"\1", s, count=1)
s = re.sub(r'(members = \[[^\]]*?)\n\]', r'\1\n    "crates/lang",\n]', s, count=1)
open("Cargo.toml", "w").write(s)
EOF
rm -f crates/lang/Cargo.lock
excludes=$(cargo metadata --no-deps --format-version 1 | python3 -c '
import json, sys
print(" ".join("--exclude " + p["name"] for p in json.load(sys.stdin)["packages"] if p["publish"] == []))')
# Share the main build's dependency cache.
CARGO_TARGET_DIR="$root/target" cargo package --workspace $excludes
echo "Dry run complete: every crate packages and builds from its tarball."
