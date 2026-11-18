#!/usr/bin/env bash
set -euo pipefail
SOURCE_ROOT=${SOURCE_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
DESTINATION=${DESTINATION:?set DESTINATION to a new backup directory}
DATA_ROOT=${DATA_ROOT:?set DATA_ROOT to the authoritative ForgeFlow data root}
if [[ -n "${FORGEFLOW_PG_BIN:-}" ]]; then PATH="$FORGEFLOW_PG_BIN:$PATH"; export PATH; fi
if [[ -n "${FORGEFLOW_PG_LIB:-}" ]]; then LD_LIBRARY_PATH="$FORGEFLOW_PG_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"; export LD_LIBRARY_PATH; fi
[[ -n "${DATABASE_URL:-}" ]] || { echo "DATABASE_URL is required for a real backup" >&2; exit 20; }
[[ -n "${FORGEFLOW_API_URL:-}" && -n "${FORGEFLOW_OWNER_TOKEN:-}" ]] || { echo "FORGEFLOW_API_URL and FORGEFLOW_OWNER_TOKEN are required" >&2; exit 20; }
exec python3 "$SOURCE_ROOT/ops/backup.py" --destination "$DESTINATION" --data-root "$DATA_ROOT" ${REPOSITORY_ARGS:-}
