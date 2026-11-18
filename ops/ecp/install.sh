#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT=${SOURCE_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
INSTALL_ROOT=${INSTALL_ROOT:?set INSTALL_ROOT to a fresh installation directory}
SERVER_BINARY=${SERVER_BINARY:-$SOURCE_ROOT/target/release/forgeflow-server}
CONSOLE_DIR=${CONSOLE_DIR:-$SOURCE_ROOT/console/dist}
mkdir -p "$INSTALL_ROOT"
if [[ -e "$INSTALL_ROOT/install-manifest.json" ]]; then
  echo "refusing to overwrite an existing installation: $INSTALL_ROOT" >&2
  exit 20
fi
[[ -f "$SERVER_BINARY" ]] || { echo "server binary is missing: $SERVER_BINARY" >&2; exit 20; }
[[ -d "$CONSOLE_DIR" ]] || { echo "console directory is missing: $CONSOLE_DIR" >&2; exit 20; }
mkdir -p "$INSTALL_ROOT/bin" "$INSTALL_ROOT/console" "$INSTALL_ROOT/data" "$INSTALL_ROOT/config"
install -m 0755 "$SERVER_BINARY" "$INSTALL_ROOT/bin/forgeflow-server"
cp -a "$CONSOLE_DIR/." "$INSTALL_ROOT/console/"
source_sha=$(git -C "$SOURCE_ROOT" rev-parse HEAD 2>/dev/null || printf 'UNKNOWN')
dirty_entries=$(git -C "$SOURCE_ROOT" status --porcelain=v1 --untracked-files=normal 2>/dev/null | wc -l | tr -d ' ' || true)
binary_sha=$(sha256sum "$INSTALL_ROOT/bin/forgeflow-server" | awk '{print $1}')
# Bind the installed console to a deterministic path+content tree.  A tar
# stream includes filesystem metadata and can produce different digests for
# identical assets across filesystems or repeated installs.
console_sha=$(python3 - "$INSTALL_ROOT/console" <<'PY'
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1]).resolve()
entries = []
for path in sorted(root.rglob('*')):
    if not path.is_file():
        continue
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    entries.append((path.relative_to(root).as_posix(), digest))
payload = '\n'.join(f'{name}\0{digest}' for name, digest in entries).encode()
print(hashlib.sha256(payload).hexdigest())
PY
)
tmp="$INSTALL_ROOT/install-manifest.json.$$.tmp"
umask 077
cat >"$tmp" <<EOF
{
  "schema_version": "forgeflow.ecp-install.v1",
  "status": "INSTALLED_NOT_STARTED",
  "source_sha": "$source_sha",
  "dirty_entries": $dirty_entries,
  "server_binary": {"path": "bin/forgeflow-server", "sha256": "$binary_sha"},
  "console": {"path": "console", "sha256": "$console_sha"},
  "database_migrations": "server-owned-on-startup",
  "server_started": false,
  "worker_started": false,
  "model_calls": 0
}
EOF
mv "$tmp" "$INSTALL_ROOT/install-manifest.json"
chmod 0600 "$INSTALL_ROOT/install-manifest.json"
cat "$INSTALL_ROOT/install-manifest.json"
