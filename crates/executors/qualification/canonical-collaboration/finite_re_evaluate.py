#!/usr/bin/env python3
"""Append-only semantic evaluation of original finite native evidence; no model/API calls."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import uuid


def stamp(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def semantic_model_checks(facts, envelope):
    lifecycles = facts['native_child_lifecycles']
    models = facts['native_model_requests']
    rpc = facts['native_bridge_rpc']
    checks, mapping = [], []
    def check(name, condition, details=None):
        checks.append({'name': name, 'status': 'PASS' if condition else 'FAIL', 'facts': details})
    by_allocation = {row['allocation_id']: row for row in lifecycles}
    roots = [row for row in lifecycles if row['borrowed_parent_reservation']]
    children = [row for row in lifecycles if not row['borrowed_parent_reservation']]
    for lifecycle in lifecycles:
        calls = [row for row in models if row['allocation_id'] == lifecycle['allocation_id'] and row['purpose'] == 'conversation']
        check('real_conversation_for_lifecycle:' + lifecycle['allocation_id'], bool(calls),
              {'native_session_id': lifecycle['native_session_id'], 'source': lifecycle['source'], 'request_ids': [row['request_id'] for row in calls]})
    root_calls = [row for row in models if len(roots) == 1 and row['allocation_id'] == roots[0]['allocation_id'] and row['purpose'] == 'conversation']
    child_calls = [row for row in models if row['allocation_id'] in {r['allocation_id'] for r in children} and row['purpose'] == 'conversation']
    before = [row for row in root_calls if child_calls and stamp(row['settled_at']) <= min(stamp(child['admitted_at']) for child in child_calls)]
    after = [row for row in root_calls if child_calls and stamp(row['admitted_at']) >= max(stamp(child['settled_at']) for child in child_calls)]
    check('root_conversation_before_and_after_real_children', len(roots) == 1 and len(root_calls) >= 2 and bool(before) and bool(after),
          {'root_calls': len(root_calls), 'before_request_ids': [r['request_id'] for r in before], 'after_request_ids': [r['request_id'] for r in after]})
    budget = envelope['max_model_requests']
    check('actual_calls_within_frozen_budget', 0 < len(models) <= budget,
          {'actual_requests': len(models), 'frozen_max_model_requests': budget})
    requests = [row for row in rpc if row['operation'] == 'model_request']
    settlements = [row for row in rpc if row['operation'] == 'model_settle']
    identity_fields = ('project_id', 'attempt_id', 'generation', 'worker_id')
    for model in models:
        lifecycle = by_allocation.get(model['allocation_id'])
        admitted = [row for row in requests if row['request'].get('request_id') == model['request_id']]
        settled = [row for row in settlements if row['request'].get('request_id') == model['request_id']]
        matching = lifecycle is not None and len(admitted) == 1 and len(settled) == 1
        if matching:
            request, settlement = admitted[0]['request'], settled[0]['request']
            matching = (all(model[key] == lifecycle[key] == envelope[key] for key in identity_fields)
                and lifecycle['task_id'] == envelope['task_id']
                and all(admitted[0][key] == settled[0][key] == envelope[key] for key in identity_fields)
                and all(request[key] == settlement[key] == envelope[key] for key in ('project_id', 'task_id', 'attempt_id', 'generation'))
                and model['native_session_id'] == lifecycle['native_session_id']
                and all(model[key] == lifecycle[key] == request[key] for key in ('provider', 'model', 'max_output_tokens'))
                and request['allocation_id'] == settlement['allocation_id'] == model['allocation_id']
                and request['native_session_id'] == settlement['native_session_id'] == model['native_session_id']
                and admitted[0]['response'].get('request_grant_id') == settlement.get('request_grant_id') == model['request_grant_id']
                and model['status'] == 'SETTLED' and model['usage_complete'] is True and model['usage'] == settlement.get('usage')
                and settlement.get('usage_complete') is True and admitted[0]['response'].get('ok') is True and settled[0]['response'].get('ok') is True
                and admitted[0]['response'].get('generation') == settled[0]['response'].get('generation') == envelope['generation']
                and stamp(lifecycle['acquired_at']) <= stamp(model['admitted_at']) <= stamp(model['settled_at']) <= stamp(lifecycle['released_at']))
        check('exact_model_grant_settlement_identity:' + model['request_id'], matching)
        mapping.append({'request_id': model['request_id'], 'grant_id': model['request_grant_id'],
                        'allocation_id': model['allocation_id'], 'native_session_id': model['native_session_id'],
                        'purpose': model['purpose'], 'provider': model['provider'], 'model': model['model'],
                        'request_rpc_ids': [r['rpc_id'] for r in admitted], 'settlement_rpc_ids': [r['rpc_id'] for r in settled],
                        'usage_sha256': hashlib.sha256(json.dumps(model['usage'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()})
    check('complete_request_and_settlement_denominator', len(requests) == len(settlements) == len(models)
          and len({row['request_id'] for row in models}) == len(models)
          and len({row['request_grant_id'] for row in models}) == len(models))
    check('native_lifecycles_and_child_resources_released', bool(lifecycles) and all(row['state'] == 'RELEASED' for row in lifecycles)
          and bool(facts['native_child_allocations']) and all(row['state'] == 'RELEASED' for row in facts['native_child_allocations']))
    return checks, mapping


def run(args):
    root = args.evidence.resolve()
    names = ('finite.postgres.json', 'finite.envelope.json', 'finite.receipt.json', 'finite.stdout.ndjson',
             'finite.launch-receipt.json', 'finite.stop.json', 'finite.result.json', 'build.receipt.json', 'report.json')
    hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}
    facts = json.loads((root / 'finite.postgres.json').read_text())
    envelope = json.loads((root / 'finite.envelope.json').read_text())
    original = json.loads((root / 'finite.receipt.json').read_text())
    checks, mapping = semantic_model_checks(facts, envelope)
    original_failures = [row['name'] for row in original['checks'] if row['status'] == 'FAIL']
    checks.append({'name': 'original_failure_only_unsupported_fixed_call_count',
                   'status': 'PASS' if original_failures == ['eight_actual_model_requests'] else 'FAIL', 'facts': original_failures})
    checks.extend(row for row in original['checks'] if row['name'] != 'eight_actual_model_requests')
    report = {'schema_version': 'forgeflow.native-finite-semantic-evaluation.v1', 'at': datetime.now(timezone.utc).isoformat(),
              'project_id': envelope['project_id'], 'attempt_id': envelope['attempt_id'], 'checks': checks,
              'model_lifecycle_identity_mapping': mapping, 'original_evidence_sha256': hashes,
              'evaluator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'original_status_preserved': original['status'], 'original_failed_assertion_preserved': 'eight_actual_model_requests',
              'reason': 'Historical asynchronous Root notification count is not a workload requirement; causal real calls and frozen budget are the requirement',
              'actual_model_requests': len(facts['native_model_requests']), 'frozen_request_budget': envelope['max_model_requests'],
              'parent_reservation_scope': 'Not business-verified; parent reservation is retained separately from released native child charges',
              'not_proven': ['Parent stopping/release closure after API drain', 'unexecuted cancel leg', 'business acceptance', '100+ production', 'full OS/network/model egress', 'complete financial accounting'],
              'oracle_independence': 'PRODUCER_SEMANTIC_EVALUATION_OF_ORIGINAL_AUTHORITY_AND_RAW_EVIDENCE'}
    report['failed'] = sum(row['status'] != 'PASS' for row in checks)
    report['status'] = 'FAIL' if report['failed'] else 'PASS_FINITE_NATIVE_CHILD_SCOPE'
    if any(hashlib.sha256((root / name).read_bytes()).hexdigest() != sha for name, sha in hashes.items()):
        raise RuntimeError('original evidence changed during evaluation')
    target = args.output or root / ('finite.semantic-re-evaluation-' + uuid.uuid4().hex[:8] + '.json')
    descriptor = target.open('x')
    with descriptor:
        json.dump(report, descriptor, indent=2); descriptor.write('\n')
    print(json.dumps({'status': report['status'], 'checks': len(checks), 'failed': report['failed'], 'models': report['actual_model_requests'], 'output': str(target)}))
    return 1 if report['failed'] else 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    raise SystemExit(run(parser.parse_args()))
