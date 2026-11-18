#!/usr/bin/env python3
"""Static Phase 3 message contract and migration scaffold check."""
from __future__ import annotations
import argparse, json
from pathlib import Path

STATUS='forgeflow.ecp-message-contract.v1'
REQUIRED_MESSAGE={'schema_version','message_id','workspace_id','conversation_id','thread_id','sender_principal_id','message_kind','sequence','client_request_id','payload','payload_sha256','created_at','expires_at','provenance'}
REQUIRED_TABLES=['ecp_conversations','ecp_conversation_participants','ecp_threads','ecp_messages','ecp_deliveries','ecp_delivery_attempts','ecp_delivery_receipts','ecp_inbox_checkpoints','ecp_message_outbox','ecp_dead_letters']

def main():
 p=argparse.ArgumentParser(); p.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[2]); p.add_argument('--output',type=Path,required=True); args=p.parse_args(); root=args.source_root.resolve(); checks=[]
 def check(name,ok,reason,details=None): checks.append({'name':name,'status':'PASS' if ok else 'FAIL','reason':reason,'details':details or {}})
 try:
  message=json.loads((root/'contracts/ecp/message.schema.json').read_text()); delivery=json.loads((root/'contracts/ecp/delivery.schema.json').read_text()); sql=(root/'migrations/0017_ecp_conversations_delivery.sql').read_text(); recovery=(root/'migrations/0021_ecp_message_recovery.sql').read_text()
  check('message_schema',message.get('x-status')=='DESIGN_DRAFT_NOT_IMPLEMENTATION' and REQUIRED_MESSAGE <= set(message.get('required',[])),'message schema is design-marked and contains the durable envelope fields')
  check('delivery_schema',delivery.get('x-status')=='DESIGN_DRAFT_NOT_IMPLEMENTATION' and 'state' in delivery.get('properties',{}),'delivery schema is design-marked and defines delivery state')
  missing=[table for table in REQUIRED_TABLES if f'CREATE TABLE {table}' not in sql]
  check('migration_tables',not missing,'migration declares all durable conversation/delivery tables',{'missing':missing})
  invariants=['UNIQUE (conversation_id,sequence)','UNIQUE (conversation_id,sender_principal_id,client_request_id)','ecp_message_outbox_pending','ecp_dead_letters','REFERENCES principals']
  absent=[item for item in invariants if item not in sql]
  check('migration_invariants',not absent,'migration contains ordering, idempotency, principal and outbox/dead-letter anchors',{'missing':absent})
  check('migration_safety','DROP TABLE' not in sql and 'TRUNCATE' not in sql,'migration is additive and has no destructive statement')
  recovery_tables=['ecp_checkpoint_commands','ecp_delivery_commands','ecp_conversation_commands']
  missing_recovery=[table for table in recovery_tables if f'CREATE TABLE {table}' not in recovery]
  check('recovery_command_tables',not missing_recovery,'recovery migration declares checkpoint, delivery and revoke command logs',{'missing':missing_recovery})
  recovery_invariants=['UNIQUE (conversation_id,principal_id,request_key)','UNIQUE (delivery_id,command_kind,request_key)','UNIQUE (conversation_id,principal_id,command_kind,request_key)','generation BIGINT NOT NULL']
  absent_recovery=[item for item in recovery_invariants if item not in recovery]
  check('recovery_invariants',not absent_recovery,'recovery command logs preserve idempotency and generation identity',{'missing':absent_recovery})
  check('recovery_migration_safety','DROP TABLE' not in recovery and 'TRUNCATE' not in recovery,'recovery migration is additive and has no destructive statement')
  status='PASS' if all(x['status']=='PASS' for x in checks) else 'FAIL'
  report={'schema_version':STATUS,'scope':'ECP_PHASE3_CONTRACT_ONLY','product_gate_effect':'NONE','status':status,'source_root':str(root),'checks':checks,'denominator':{'total':len(checks),'passed':sum(x['status']=='PASS' for x in checks),'failed':sum(x['status']=='FAIL' for x in checks),'not_run':0}}
 except Exception as exc:
  report={'schema_version':STATUS,'scope':'ECP_PHASE3_CONTRACT_ONLY','product_gate_effect':'NONE','status':'FAIL','error':str(exc),'checks':[],'denominator':{'total':1,'passed':0,'failed':1,'not_run':0}}
 args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n'); print(json.dumps(report,ensure_ascii=False)); return 0 if report['status']=='PASS' else 10
if __name__=='__main__': raise SystemExit(main())
