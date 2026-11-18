#!/usr/bin/env bash
set -euo pipefail

# Offline upgrade preflight. The server applies additive migrations on startup;
# this command proves the migration chain and records the exact source identity.
SOURCE_ROOT=${SOURCE_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
OUTPUT=${OUTPUT:?set OUTPUT to the upgrade preflight receipt path}
PREVIOUS=${PREVIOUS:-}
python3 - "$SOURCE_ROOT" "$OUTPUT" "$PREVIOUS" <<'PY'
import hashlib, json, re, subprocess, sys
from pathlib import Path
root=Path(sys.argv[1]).resolve(); out=Path(sys.argv[2]); previous=sys.argv[3]
migrations=[]
for path in sorted((root/'migrations').glob('*.sql')):
    match=re.match(r'(\d+)_',path.name)
    if match: migrations.append((int(match.group(1)),path))
numbers=[number for number,_ in migrations]
errors=[]
if numbers != sorted(set(numbers)): errors.append('migration numbers are not strictly increasing')
if numbers and numbers[0] != 1: errors.append('migration chain does not start at 0001')
head=subprocess.run(['git','rev-parse','HEAD'],cwd=root,capture_output=True,text=True,check=False).stdout.strip() or 'UNKNOWN'
receipt={'schema_version':'forgeflow.ecp-upgrade-preflight.v1','status':'PASS' if not errors else 'FAIL','qualification':'NOT_RUN','product_gate_effect':'NONE','source_sha':head,'previous_manifest':previous or None,'migration_numbers':numbers,'migration_sha256':{path.name:hashlib.sha256(path.read_bytes()).hexdigest() for _,path in migrations},'apply_performed':False,'server_restart_performed':False,'errors':errors}
out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n'); print(json.dumps(receipt,ensure_ascii=False)); raise SystemExit(0 if not errors else 10)
PY
