#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,re
from pathlib import Path

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();root=Path(__file__).resolve().parents[2]
 migration=(root/'migrations/0020_ecp_release_qualification.sql').read_text(); release=json.loads((root/'contracts/ecp/release_manifest.schema.json').read_text()); backup=json.loads((root/'contracts/ecp/backup_manifest.schema.json').read_text())
 checks=[
  {'name':'candidate identity fields are bound','passed':all(x in release['required'] for x in ['source_sha','source_manifest_sha256','binary_manifest_sha256','schema_manifest_sha256','profile_manifest_sha256','evidence_manifest_sha256'])},
  {'name':'backup requires quiescent dispatch and zero unsettled attempts','passed':backup['properties']['dispatch_paused'].get('const') is True and backup['properties']['unsettled_attempts'].get('const') == 0 and backup['properties'].get('file_quiescence_checked',{}).get('const') is True},
  {'name':'restore rehearsal tracks old lease revocation','passed':'old_lease_count BIGINT NOT NULL CHECK(old_lease_count=0)' in migration},
  {'name':'upgrade rehearsal has rollback status','passed':'rollback_verified BOOLEAN NOT NULL DEFAULT false' in migration},
  {'name':'qualification rows cannot grant authority','passed':'approved_at' in migration and 'status TEXT NOT NULL CHECK(status IN (\'CANDIDATE\',\'VERIFIED\',\'REJECTED\',\'APPROVED\'))' in migration},
 ]
 report={'schema_version':'forgeflow.ecp-phase8-release-check.v1','product_gate_effect':'NONE','status':'PASS' if all(x['passed'] for x in checks) else 'FAIL','qualification':'NOT_RUN','checks':checks,'model_calls':0}
 a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n'); print(json.dumps({'status':report['status'],'checks':len(checks),'model_calls':0})); raise SystemExit(0 if report['status']=='PASS' else 10)
if __name__=='__main__':main()
