#!/usr/bin/env python3
"""Static contract checks for the Phase 4 collaboration slice."""
from __future__ import annotations
import argparse, json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
    migration = Path(__file__).resolve().parents[2] / 'migrations' / '0018_ecp_collaboration_flow.sql'
    text = migration.read_text(encoding='utf-8')
    checks = []
    required_tables = ('ecp_assignments','ecp_proposals','ecp_reviews','ecp_decisions','ecp_escalations','ecp_collaboration_outbox')
    checks.append({'name':'all collaboration tables exist','passed':all(f'CREATE TABLE {name}' in text for name in required_tables)})
    checks.append({'name':'assignment has revision and bounded scopes','passed':all(x in text for x in ('parent_grant_id','action_set JSONB','write_set JSONB','executor_set JSONB','budget JSONB','expected_revision'))})
    checks.append({'name':'proposal and decision revisions are immutable facts','passed':all(x in text for x in ('base_revision BIGINT','payload_sha256 TEXT','UNIQUE(assignment_id,revision)','UNIQUE(proposal_id,revision)'))})
    checks.append({'name':'review outcomes and escalation lifecycle are explicit','passed':all(x in text for x in ('REQUEST_CHANGES','status IN (\'OPEN\',\'ACKNOWLEDGED\',\'RESOLVED\',\'REJECTED\')'))})
    checks.append({'name':'collaboration outbox is durable and deduplicated','passed':'UNIQUE(object_id,kind)' in text and 'WHERE delivered_at IS NULL' in text})
    report={'schema_version':'forgeflow.ecp-phase4-contract.v1','scope':'ECP_PHASE4_CONTRACT_ONLY','product_gate_effect':'NONE','status':'PASS' if all(c['passed'] for c in checks) else 'FAIL','qualification':'NOT_RUN','checks':checks,'denominator':{'total':len(checks),'passed':sum(c['passed'] for c in checks),'failed':sum(not c['passed'] for c in checks)}}
    args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n'); print(json.dumps(report,ensure_ascii=False)); return 0 if report['status']=='PASS' else 10

if __name__=='__main__': raise SystemExit(main())
