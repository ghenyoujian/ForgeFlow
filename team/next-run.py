#!/usr/bin/env python3
"""A00 finite experiment launcher: all prerequisite failures stop execution."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'evidence/next/20261015T003541Z-00f024640b'
HARNESS = ROOT / 'verification/next/dual_leaf.py'
LEDGER = ROOT / 'team/next-admissions.json'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def admission_reservation(reserved, limits):
    total = limits['total_requests']
    per_executor = limits['per_executor_requests']
    amount = limits['maximum_reserved_usd']
    if (type(total) is not int or not 1 <= total <= 12
            or type(per_executor) is not int or not 1 <= per_executor <= 6
            or type(amount) is not int or amount != total * 10
            or limits['per_request_reserve_usd'] != 10):
        raise RuntimeError('plan reservation is outside the fixed finite boundary')
    if reserved + amount > 300:
        raise RuntimeError('remaining cumulative reservation budget cannot cover this run')
    return amount

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--expected-harness-sha', required=True)
    args = p.parse_args()
    manifest = args.manifest.resolve(strict=True)
    if not manifest.is_relative_to(Path('/home/chenyoujian/.cache/forgeflow-next')):
        raise RuntimeError('manifest outside owned experiment runtime')
    if sha(HARNESS) != args.expected_harness_sha:
        raise RuntimeError('harness SHA changed; no execution')
    m = json.loads(manifest.read_text())
    run_id = m['run_id']
    if not run_id.startswith('next') or not run_id[4:].isdigit():
        raise RuntimeError('unexpected run id')
    if Path(m['output_root']).exists() or Path(m['private_runtime_root']).exists():
        raise RuntimeError('fresh experiment required')
    receipts = sorted(EVIDENCE.glob('dual-leaf-next*/receipt.json'))
    reserved = sum(json.loads(r.read_text())['real_provider_reservations'] * 10 for r in receipts)
    test = subprocess.run([sys.executable, str(HARNESS), '--selftest'], cwd=ROOT,
                          capture_output=True, text=True, check=True)
    tests = json.loads(test.stdout)
    if tests['status'] != 'VERIFIED' or tests['actual_provider_calls'] != 0 or tests['external_network_requests'] != 0:
        raise RuntimeError('local-only prerequisite failed')
    test_path = EVIDENCE / (run_id + '-launcher-selftest.json')
    with test_path.open('x') as f:
        f.write(test.stdout)
    plan = subprocess.run([sys.executable, str(HARNESS), '--run-manifest', str(manifest)],
                          cwd=ROOT, capture_output=True, text=True, check=True)
    validated_plan = json.loads(plan.stdout)
    if validated_plan['status'] != 'PLAN_VALIDATED_NOT_EXECUTED':
        raise RuntimeError('plan did not validate')
    # Never infer a refund from low usage or an UNKNOWN final bill.
    maximum_reservation = admission_reservation(reserved, validated_plan['limits'])
    if sha(HARNESS) != args.expected_harness_sha:
        raise RuntimeError('harness changed during prerequisite checks')
    ledger = json.loads(LEDGER.read_text())
    entry = {'run_id': run_id, 'at': datetime.now(timezone.utc).isoformat(),
        'status': 'ADMITTED_FINITE_REAL_TEST', 'manifest_path': str(manifest),
        'manifest_sha256': sha(manifest), 'harness_sha256': sha(HARNESS),
        'selftest_ref': str(test_path.relative_to(ROOT)),
        'prior_reserved_usd_not_released': reserved, 'maximum_this_run_reserved_usd': maximum_reservation,
        'request_limits': {k: validated_plan['limits'][k] for k in ['total_requests', 'per_executor_requests']},
        'total_authorized_usd': 300, 'exact_model': 'glm-5.3',
        'scope': 'Owned isolated Worker/DSH/Claude leaf experiment; no production install',
        'supplier_debit_status': 'UNKNOWN'}
    ledger['model_authorization'].setdefault('subsequent_runs', []).append(entry)
    LEDGER.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(entry), flush=True)
    result = subprocess.run([sys.executable, str(HARNESS), '--run-manifest', str(manifest), '--execute'], cwd=ROOT)
    receipt_path = Path(m['output_root']) / 'receipt.json'
    ledger = json.loads(LEDGER.read_text())
    entry = next(x for x in ledger['model_authorization']['subsequent_runs'] if x['run_id'] == run_id)
    if receipt_path.exists():
        receipt = json.loads(receipt_path.read_text())
        entry.update(status=receipt['status'], result_ref=str(receipt_path.relative_to(ROOT)),
                     provider_reservations=receipt['real_provider_reservations'],
                     reserved_usd_not_released=receipt['real_provider_reservations'] * 10,
                     real_upstream_http_attempts=receipt['real_upstream_http_attempts'])
    else:
        entry.update(status='INCONCLUSIVE', receipt_missing=True)
    completed = [json.loads(r.read_text()) for r in EVIDENCE.glob('dual-leaf-next*/receipt.json')]
    for old in completed:
        if 'real_upstream_http_attempts' not in old:
            # First pre-dispatch failure predates separate delivery counters.
            # Only a zero-reservation receipt is safe to normalize in memory.
            if old['real_provider_reservations'] != 0 or old['forwarder']['inflight_or_uncertain'] != 0:
                raise RuntimeError('legacy nonzero delivery requires explicit reconciliation')
            old['real_upstream_http_attempts'] = 0
            old['responses_with_matching_model_usage'] = {'count': 0}
    auth = ledger['model_authorization']
    auth['new_model_calls'] = sum(r['real_upstream_http_attempts'] for r in completed)
    auth['new_model_calls_semantics'] = 'Real upstream HTTP open attempts; not accepted or billed count'
    auth['spent_usd_confirmed'] = None
    auth['live_accounting'] = {
        'at': datetime.now(timezone.utc).isoformat(), 'scope': 'All completed experiment receipts',
        'real_upstream_http_open_attempts': auth['new_model_calls'],
        'provider_reservations': sum(r['real_provider_reservations'] for r in completed),
        'reserved_usd_not_released': sum(r['real_provider_reservations'] * 10 for r in completed),
        'matching_model_usage_responses': sum(r['responses_with_matching_model_usage']['count'] for r in completed),
        'supplier_debit_status': 'UNKNOWN', 'supplier_debit_usd': None}
    LEDGER.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + '\n')
    return result.returncode

if __name__ == '__main__':
    raise SystemExit(main())
