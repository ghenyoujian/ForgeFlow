#!/usr/bin/env bash
set -euo pipefail
SOURCE_ROOT=${SOURCE_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
OUTPUT=${OUTPUT:?set OUTPUT to a new package tarball path}
EVIDENCE_ROOT=${EVIDENCE_ROOT:-$SOURCE_ROOT/evidence}
SCHEMA_ROOT=${SCHEMA_ROOT:-$SOURCE_ROOT/contracts/ecp}
PROFILE_ROOT=${PROFILE_ROOT:-$SOURCE_ROOT/crates/executors/presets}
SERVER_BINARY=${SERVER_BINARY:-$SOURCE_ROOT/target/release/forgeflow-server}
SOURCE_MANIFEST=${SOURCE_MANIFEST:-$EVIDENCE_ROOT/source_manifest.json}
GATE_SNAPSHOT=${GATE_SNAPSHOT:-$SOURCE_ROOT/planning/gates.json}
MANIFEST=$(mktemp)
trap 'rm -f "$MANIFEST"' EXIT
set +e
python3 "$SOURCE_ROOT/ops/ecp/release_manifest.py" --source-root "$SOURCE_ROOT" --source-manifest "$SOURCE_MANIFEST" --binary "$SERVER_BINARY" --schema-root "$SCHEMA_ROOT" --profile-root "$PROFILE_ROOT" --evidence-root "$EVIDENCE_ROOT" --gate-snapshot "$GATE_SNAPSHOT" --output "$MANIFEST"
set -e
status=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$MANIFEST")
if [[ "$status" != "CANDIDATE" && "${ECP_PACKAGE_ALLOW_DIRTY:-0}" != "1" ]]; then
  echo "release package blocked: manifest status=$status; set ECP_PACKAGE_ALLOW_DIRTY=1 only for an explicitly non-release preview" >&2
  exit 20
fi
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/control" "$stage/evidence"
cp "$MANIFEST" "$stage/release-manifest.json"
cp -a "$SCHEMA_ROOT" "$stage/control/contracts"
cp -a "$PROFILE_ROOT" "$stage/control/profiles"
cp -a "$EVIDENCE_ROOT" "$stage/evidence"
# Normalize ordering, timestamps, ownership and gzip headers so two packages
# built from the same staged bytes have the same archive digest.
tar -C "$stage" --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner --use-compress-program='gzip -n' -cf "$OUTPUT" .
printf '{"status":"PREVIEW_PACKAGED","release_approval":false,"package":"%s"}\n' "$OUTPUT"
