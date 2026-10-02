#!/usr/bin/env bash
# Refresh the vendored interoperability vectors from the reference implementation.
#
# Kestrel reproduces Starling's protocol v2 wire format so that circles, relays
# and invitations interoperate. These vectors are the contract: if a derivation
# here ever disagrees with them, Kestrel is wrong, not the vector.
#
# The files are committed rather than fetched at test time so the test suite
# runs offline and so a diff shows exactly which derivation changed.
set -euo pipefail

UPSTREAM="https://raw.githubusercontent.com/munzzyy/starling/main/test/vectors"
DEST="$(cd "$(dirname "$0")/.." && pwd)/tests/vectors"

for f in hkdf strings identity session; do
  echo "fetching $f.json"
  curl -fsSL "$UPSTREAM/$f.json" -o "$DEST/$f.json"
done

echo
echo "vectors updated in $DEST"
echo "run: cargo test -p kestrel-core --test vectors"
