#!/usr/bin/env python3
"""Offline Phase 8 operator checks; release and restore remain NOT_RUN."""
from __future__ import annotations
import argparse,json,subprocess
from pathlib import Path

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args(); root=Path(__file__).resolve().parents[2]; checks=[]
 for name,cmd in [('release_manifest_help',[str(root/'ops/ecp/release_manifest.py'),'--help']),('backup_manifest_help',[str(root/'ops/ecp/backup_manifest_check.py'),'--help'])]:
  r=subprocess.run(cmd,capture_output=True,text=True);checks.append({'name':name,'status':'PASS' if r.returncode==0 else 'FAIL'})
 report={'schema_version':'forgeflow.ecp-phase8-ops.v1','product_gate_effect':'NONE','status':'PASS' if all(x['status']=='PASS' for x in checks) else 'FAIL','qualification':'NOT_RUN','checks':checks,'database_connections':0,'release_approval':False};a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');print(json.dumps({'status':report['status'],'checks':len(checks),'product_gate_effect':'NONE'}));raise SystemExit(0 if report['status']=='PASS' else 10)
if __name__=='__main__':main()
