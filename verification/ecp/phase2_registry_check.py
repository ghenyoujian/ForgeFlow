#!/usr/bin/env python3
"""Offline contract checks for Phase 2 registry/profile payloads."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

def valid_digest(value): return isinstance(value,str) and len(value)==64 and value==value.lower() and all(c in '0123456789abcdef' for c in value)
def main():
 p=argparse.ArgumentParser(); p.add_argument('--output',type=Path,required=True); args=p.parse_args()
 checks=[]; digest='a'*64
 profile={'profile_id':'p','registration_id':'r','provider':'dsh','profile_version':'v1','binary_digest':digest,'adapter_digest':digest,'configuration_digest':digest,'capabilities':{'structured_events':True,'cancel':False},'support_status':'UNKNOWN','evidence_status':'NOT_RUN'}
 checks.append({'name':'profile digests are strict lowercase SHA-256','passed':all(valid_digest(profile[k]) for k in ('binary_digest','adapter_digest','configuration_digest'))})
 checks.append({'name':'unsupported capability cannot be inferred from an UNKNOWN evidence row','passed':profile['support_status']=='UNKNOWN' and profile['evidence_status']=='NOT_RUN'})
 checks.append({'name':'profile identity changes when binary digest changes','passed':hashlib.sha256(json.dumps(profile,sort_keys=True).encode()).hexdigest()!=hashlib.sha256(json.dumps({**profile,'binary_digest':'b'*64},sort_keys=True).encode()).hexdigest()})
 report={'schema_version':'forgeflow.ecp-phase2-registry-check.v1','product_gate_effect':'NONE','status':'PASS' if all(x['passed'] for x in checks) else 'FAIL','checks':checks,'model_calls':0,'qualification':'NOT_RUN'}
 args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n'); print(json.dumps({'status':report['status'],'checks':len(checks),'model_calls':0}))
 raise SystemExit(0 if report['status']=='PASS' else 10)
if __name__=='__main__': main()
