#!/usr/bin/env bash
set -euo pipefail
SOURCE_ROOT=${SOURCE_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
BACKUP=${BACKUP:?set BACKUP to a verified backup directory}
DESTINATION=${DESTINATION:?set DESTINATION to a fresh restore directory}
DATABASE_ENV=${DATABASE_ENV:?set DATABASE_ENV to a private JSON file containing DATABASE_URL}
if [[ -n "${FORGEFLOW_PG_BIN:-}" ]]; then PATH="$FORGEFLOW_PG_BIN:$PATH"; export PATH; fi
if [[ -n "${FORGEFLOW_PG_LIB:-}" ]]; then LD_LIBRARY_PATH="$FORGEFLOW_PG_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"; export LD_LIBRARY_PATH; fi
[[ -f "$BACKUP/manifest.json" ]] || { echo "backup manifest is missing" >&2; exit 20; }
PREFLIGHT=${RESTORE_PREFLIGHT:-${BACKUP%/}.restore-preflight.json}
python3 "$SOURCE_ROOT/ops/ecp/backup_manifest_check.py" --backup "$BACKUP" --output "$PREFLIGHT"
exec python3 "$SOURCE_ROOT/ops/restore.py" --backup "$BACKUP" --destination "$DESTINATION" --database-env "$DATABASE_ENV"
