#!/usr/bin/env python3
"""Static checks for Phase 6 resource/cost contracts; no runtime qualification."""
from __future__ import annotations
import argparse, json
from pathlib import Path


def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument('--output',type=Path,required=True); args=parser.parse_args()
    migration=Path(__file__).resolve().parents[2]/'migrations/0019_ecp_cost_resource.sql'
    schema=Path(__file__).resolve().parents[2]/'contracts/ecp/cost_ledger.schema.json'
    sql=migration.read_text(); contract=json.loads(schema.read_text())
    checks=[]
    required_tables=['ecp_resource_profiles','ecp_budget_reservations','ecp_cost_ledger','ecp_lease_revocations']
    checks.append({'name':'resource and cost tables are additive and present','passed':all(f'CREATE TABLE {name}' in sql for name in required_tables)})
    checks.append({'name':'logical and physical limits are separate','passed':'logical_limits JSONB' in sql and 'physical_limits JSONB' in sql and 'enforcement_status' in sql})
    checks.append({'name':'unknown settlement and reservation states are explicit','passed':all(x in sql for x in ["'UNKNOWN'","'QUARANTINED'","'PARTIAL'"])})
    checks.append({'name':'source and generation identities are bounded','passed':'source_sha256' in sql and 'generation BIGINT' in sql and 'idempotency_key' in sql})
    checks.append({'name':'cost schema is draft-marked and preserves unknown','passed':contract.get('x-status')=='DESIGN_DRAFT_NOT_IMPLEMENTATION' and 'UNKNOWN' in json.dumps(contract)})
    report={'schema_version':'forgeflow.ecp-phase6-resource-check.v1','scope':'ECP_PHASE6_CONTRACT_ONLY','product_gate_effect':'NONE','status':'PASS' if all(x['passed'] for x in checks) else 'FAIL','qualification':'NOT_RUN','checks':checks,'denominator':{'total':len(checks),'passed':sum(x['passed'] for x in checks)}}
    args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n'); print(json.dumps({'status':report['status'],'checks':len(checks),'product_gate_effect':'NONE'})); return 0 if report['status']=='PASS' else 10
if __name__=='__main__': raise SystemExit(main())
