#!/usr/bin/env python3
"""Independent original-evidence oracle for the narrow native collaboration probe."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def verify(mode):
    receipt = json.loads((HERE / f'{mode}.receipt.json').read_text())
    ledger = [json.loads(line) for line in (HERE / f'{mode}.controller.ndjson').read_text().splitlines()]
    stdout = [json.loads(line) for line in (HERE / f'{mode}.stdout.ndjson').read_text().splitlines()]
    checks = {}
    mandatory_evidence = {f'{mode}.{suffix}' for suffix in ['stdout.ndjson', 'stderr.log', 'controller.ndjson']}
    mandatory_artifacts = {'presets/forgeflow/launch.py', 'presets/forgeflow/managed-bridge.mjs',
                           'presets/forgeflow/managed_controller.py', 'qualification/collaboration/probe-plugin.mjs'}
    checks['evidence_hashes'] = set(receipt.get('evidence_sha256', {})) == mandatory_evidence and all(hashlib.sha256((HERE / name).read_bytes()).hexdigest() == value
                                     for name, value in receipt['evidence_sha256'].items())
    checks['current_runtime_artifacts_match'] = set(receipt.get('artifact_sha256', {})) == mandatory_artifacts and all(hashlib.sha256((HERE.parents[1] / name).read_bytes()).hexdigest() == value
                                                   for name, value in receipt['artifact_sha256'].items())
    checks['bounded_original_run'] = not receipt['timed_out'] and not receipt['remaining_process_group']
    admissions = [row for row in ledger if row['operation'] == 'admit']
    requests = [row for row in ledger if row['operation'] == 'model_request']
    settlements = [row for row in ledger if row['operation'] == 'model_settle']
    releases = [row for row in ledger if row['operation'] == 'release']
    grant_times = {row['allocation_id']: row['time_ns'] for row in admissions}
    allocations = {row['allocation_id']: row for row in admissions}
    request_map = {row['request_id']: row for row in requests}
    checks['nonzero_native_child_denominator'] = len([row for row in admissions if row['parent_session_id']]) >= (3 if mode == 'finite' else 1)
    checks['every_request_preceded_by_allocation'] = bool(requests) and all(
        row['allocation_id'] in grant_times and grant_times[row['allocation_id']] < row['time_ns']
        and allocations[row['allocation_id']]['native_session_id'] == row['native_session_id'] for row in requests)
    checks['route_and_request_cap'] = bool(requests) and all(
        row['provider'] == 'newapi' and row['model'] == 'glm-5.3'
        and 0 < row['max_output_tokens'] <= receipt['policy']['max_output_tokens'] for row in requests)
    checks['all_model_requests_settled'] = bool(requests) and len(request_map) == len({row['request_grant_id'] for row in requests}) == len(requests) == len(settlements) and {row['request_id'] for row in requests} == {row['request_id'] for row in settlements} and all(
        all(row[key] == request_map[row['request_id']][key] for key in ['native_session_id', 'allocation_id', 'request_grant_id'])
        and row['time_ns'] > request_map[row['request_id']]['time_ns'] for row in settlements)
    checks['all_native_allocations_released'] = bool(admissions) and len(allocations) == len(admissions) == len(releases) and {row['allocation_id'] for row in admissions} == {row['allocation_id'] for row in releases} and all(
        row['native_session_id'] == allocations[row['allocation_id']]['native_session_id']
        and row['time_ns'] > allocations[row['allocation_id']]['time_ns']
        and all(settlement['time_ns'] < row['time_ns'] for settlement in settlements if settlement['allocation_id'] == row['allocation_id']) for row in releases)
    events = [row['event'] for row in ledger if row['operation'] == 'observe']
    checks['actual_workflow_and_subagent_trace'] = all(event in events for event in
        ['workflow/start', 'workflow/agent-start', 'workflow/agent-end', 'workflow/end', 'subagent/start', 'subagent/end'])
    if mode == 'finite':
        tool_results = [row for row in stdout if row.get('type') == 'tool_result']
        result = next((json.loads(row['result']) for row in tool_results if row.get('status') == 'completed'), {})
        checks['native_receipt_oracles'] = result.get('one_shot', {}).get('stopReason') == 'completed' and ''.join(
            block.get('text', '') for block in result.get('one_shot', {}).get('output', []) if block.get('type') == 'text') == 'ONE_SHOT_RECEIPT' and result.get('workflow', {}).get('stopReason') == 'completed' and result.get('workflow', {}).get('value', {}).get('receipt') == 'WORKFLOW_RECEIPT'
        checks['actual_team_durable_trace'] = 'team/member' in events
        resumed = [row for row in admissions if row['source'] == 'resume' and row['parent_session_id']]
        checks['actual_team_cold_resume'] = bool(resumed) and all(any(
            previous['native_session_id'] == row['native_session_id']
            and previous['allocation_id'] != row['allocation_id'] and previous['source'] == 'startup'
            for previous in admissions) for row in resumed)
        team_ids = {row['id'] for row in result.get('roster', []) if row.get('name') == 'finite-verifier'}
        checks['team_original_output_oracles'] = bool(team_ids) and all(any(
            row['operation'] == 'observe' and row['event'] == 'assistant/message'
            and row['value'].get('native_session_id') in team_ids and not row['value'].get('interrupted')
            and row['value'].get('assistant_text_sha256') == hashlib.sha256(token.encode()).hexdigest()
            for row in ledger) for token in ['TEAM_RECEIPT', 'TEAM_RESUME_RECEIPT'])
        checks['native_completed_outcome'] = receipt['exit_code'] == 0 and any(row.get('type') == 'final' for row in stdout)
    else:
        revocations = [row for row in ledger if row['operation'] == 'revoked']
        acknowledgements = [row for row in ledger if row['operation'] == 'cancel_ack']
        checks['controller_revoke_and_quiescence_ack'] = receipt['revoke_issued'] and bool(revocations) and bool(acknowledgements) and all(
            session['status'] == 'idle' for row in acknowledgements for session in row['sessions']) and all(
                row.get('active_model_requests') == 0 for row in acknowledgements)
        checks['no_model_egress_after_revoke'] = bool(revocations) and all(row['time_ns'] < revocations[0]['time_ns'] for row in requests)
        checks['ack_after_all_model_settlements'] = bool(acknowledgements) and all(
            row['time_ns'] < acknowledgements[0]['time_ns'] for row in settlements)
        checks['native_cancelled_outcome'] = receipt['exit_code'] != 0 and any(
            row['operation'] == 'observe' and row['event'] == 'subagent/end' and row['value'].get('stopReason') == 'aborted' for row in ledger)
    usage_available = [row for row in settlements if row.get('usage_complete') is True]
    report = {'schema_version': 'forgeflow.dsh-collaboration-verification.v1', 'mode': mode,
              'outcome': 'PASS_LOCAL_NATIVE_SCOPE' if all(checks.values()) else 'FAIL', 'checks': checks,
              'denominators': {'native_lifecycles': len(admissions), 'model_requests': len(requests),
                               'distinct_native_agents': len({row['native_session_id'] for row in admissions}),
                               'resumed_lifecycles': len([row for row in admissions if row['source'] == 'resume']),
                               'settled_model_requests': len(settlements), 'requests_with_usage': len(usage_available)},
              'missing_usage_is_zero': False, 'authority': 'LOCAL_QUALIFICATION_ONLY',
              'production_admission': 'BLOCKED_PENDING_CANONICAL_CHILD_ACCOUNTING'}
    (HERE / f'{mode}.verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    return report


if __name__ == '__main__':
    reports = [verify(mode) for mode in ['finite', 'cancel']]
    raise SystemExit(0 if all(report['outcome'] == 'PASS_LOCAL_NATIVE_SCOPE' for report in reports) else 1)
