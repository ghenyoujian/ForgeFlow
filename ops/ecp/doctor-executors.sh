#!/usr/bin/env bash
set -euo pipefail

# Offline executor Doctor. It records profile identity and leaves runtime
# capabilities NOT_RUN unless a separate current receipt is supplied.
PROFILE=${PROFILE:?set PROFILE to a JSON executor profile}
OUTPUT=${OUTPUT:?set OUTPUT to a Doctor receipt path}
python3 - "$PROFILE" "$OUTPUT" <<'PY'
import hashlib,json,sys
from pathlib import Path
profile=Path(sys.argv[1]); output=Path(sys.argv[2])
data=json.loads(profile.read_text(encoding='utf-8'))
raw=profile.read_bytes(); profile_id=data.get('profile_id') or data.get('id')
provider=data.get('provider','UNKNOWN')
if not isinstance(profile_id,str) or not profile_id: raise SystemExit('profile_id is required')
capabilities=['managed_leaf','subagent','native_team','workflow','bot','session_resume','cancel','structured_events','child_supervision','write_isolation','cost_enforcement']
receipt={'schema_version':'forgeflow.ecp-doctor.v1','profile_id':profile_id,'provider':provider,'profile_sha256':hashlib.sha256(raw).hexdigest(),'binary_sha256':data.get('binary_digest'),'evidence_class':'OFFLINE_DISCOVERY','qualification':'NOT_RUN','checks':[{'capability':c,'status':'NOT_RUN','reason_code':'RUNTIME_QUALIFICATION_NOT_RUN','evidence_refs':[]} for c in capabilities]}
output.parent.mkdir(parents=True,exist_ok=True); output.write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n'); print(json.dumps(receipt,ensure_ascii=False))
PY
