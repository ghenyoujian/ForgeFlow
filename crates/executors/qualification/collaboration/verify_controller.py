#!/usr/bin/env python3
"""Exercise real UDS broker rejection paths without model calls; this is not a DSH workload."""
import json
from pathlib import Path
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'presets/forgeflow'))
from managed_controller import serve
from probe import call


def verify():
    private = Path(tempfile.mkdtemp(prefix='forgeflow-controller-cases-', dir='/home/chenyoujian/.cache'))
    identity = {'project_id': 'broker-cases', 'task_id': 'negative-cases', 'attempt_id': 'broker-attempt', 'generation': 7}
    policy = {**identity, 'provider': 'newapi', 'model': 'glm-5.3', 'max_depth': 2,
              'max_live_agents': 2, 'max_total_lifecycles': 4, 'max_model_requests': 2,
              'max_live_model_requests': 1,
              'max_output_tokens': 128}
    path, ledger = private / 'broker.sock', private / 'ledger.ndjson'
    server, controller = serve(policy, path, ledger)
    checks = {}
    def rejected(name, operation, code, **fields):
        response = call(path, identity, operation, **fields)
        checks[name] = response.get('ok') is False and response.get('code') == code
    def admit(native, parent=None, depth=0):
        return call(path, identity, 'admit', native_session_id=native, parent_session_id=parent,
                    delegation_depth=depth, source='startup', origin='subagent' if parent else None,
                    agent_options={'provider': None, 'model': None})
    stale = call(path, {**identity, 'generation': 6}, 'admit')
    checks['stale_generation'] = stale.get('code') == 'STALE_OR_WRONG_IDENTITY'
    checks['unallocated_parent'] = admit('orphan', 'missing', 1).get('code') == 'UNALLOCATED_PARENT'
    root = admit('root')
    checks['root_granted'] = root.get('ok') is True
    checks['duplicate_live_session'] = admit('root').get('code') == 'DUPLICATE_LIVE_SESSION'
    checks['second_root'] = admit('another-root').get('code') == 'SECOND_ROOT'
    checks['depth_limit'] = admit('deep', 'root', 3).get('code') == 'DEPTH_LIMIT'
    child = admit('child', 'root', 1)
    checks['child_granted'] = child.get('ok') is True
    checks['aggregate_slots'] = admit('extra', 'root', 1).get('code') == 'AGENT_SLOTS_EXHAUSTED'
    common = {'native_session_id': 'child', 'allocation_id': child['allocation_id'],
              'request_id': 'model-call', 'provider': 'newapi', 'model': 'glm-5.3',
              'max_output_tokens': 128, 'purpose': 'conversation'}
    rejected('wrong_route', 'model_request', 'MODEL_ROUTE_DENIED', **{**common, 'model': 'unauthorized'})
    rejected('missing_output_cap', 'model_request', 'OUTPUT_CAP_REQUIRED', **{**common, 'max_output_tokens': None})
    rejected('oversized_output_cap', 'model_request', 'OUTPUT_CAP_REQUIRED', **{**common, 'max_output_tokens': 129})
    rejected('stale_allocation', 'model_request', 'STALE_OR_MISSING_ALLOCATION', **{**common, 'allocation_id': 'old'})
    request = call(path, identity, 'model_request', **common)
    checks['request_granted'] = request.get('ok') is True
    rejected('aggregate_model_concurrency', 'model_request', 'MODEL_CONCURRENCY_EXHAUSTED', **{**common, 'request_id': 'extra'})
    rejected('premature_allocation_release', 'release', 'MODEL_REQUESTS_STILL_ACTIVE', native_session_id='child', allocation_id=child['allocation_id'], reason='native_disposed')
    settle = {'native_session_id': 'child', 'allocation_id': child['allocation_id'], 'request_id': 'model-call',
              'request_grant_id': request['request_grant_id'], 'usage': None, 'finish_reason': 'abandoned'}
    rejected('wrong_settlement_grant', 'model_settle', 'INVALID_MODEL_SETTLEMENT', **{**settle, 'request_grant_id': 'wrong'})
    checks['unknown_usage_preserved'] = call(path, identity, 'model_settle', **settle).get('ok') is True
    rejected('duplicate_settlement', 'model_settle', 'INVALID_MODEL_SETTLEMENT', **settle)
    second = call(path, identity, 'model_request', **{**common, 'request_id': 'second'})
    checks['model_concurrency_slot_reused_after_settlement'] = second.get('ok') is True
    rejected('aggregate_request_budget', 'model_request', 'MODEL_REQUEST_BUDGET_EXHAUSTED', **{**common, 'request_id': 'extra'})
    checks['second_settlement'] = call(path, identity, 'model_settle', **{**settle, 'request_id': 'second', 'request_grant_id': second['request_grant_id']}).get('ok') is True
    call(path, identity, 'revoke', reason='negative-case')
    checks['admit_after_revoke'] = admit('after', 'root', 1).get('code') == 'FENCE_REVOKED'
    rejected('request_after_revoke', 'model_request', 'FENCE_REVOKED', **{**common, 'request_id': 'after'})
    rejected('incomplete_cancel_ack', 'cancel_ack', 'CANCEL_NOT_QUIESCENT', active_model_requests=0, sessions=[{'native_session_id': 'root', 'status': 'idle'}])
    rejected('running_cancel_ack', 'cancel_ack', 'CANCEL_NOT_QUIESCENT', active_model_requests=0, sessions=[{'native_session_id': 'root', 'status': 'idle'}, {'native_session_id': 'child', 'status': 'running'}])
    rejected('missing_model_quiescence_count', 'cancel_ack', 'CANCEL_NOT_QUIESCENT', sessions=[{'native_session_id': value, 'status': 'idle'} for value in ['root', 'child']])
    checks['quiescent_cancel_ack'] = call(path, identity, 'cancel_ack', active_model_requests=0, sessions=[{'native_session_id': value, 'status': 'idle'} for value in ['root', 'child']]).get('ok') is True
    server.shutdown(); server.server_close(); controller.file.close(); path.unlink()
    # Open the original nonempty ledger: allocation release cannot be inferred from restart.
    server, controller = serve(policy, path, ledger)
    checks['restart_requires_reconciliation'] = admit('restart').get('code') == 'RECOVERY_RECONCILIATION_REQUIRED'
    checks['restart_poll_revoked'] = call(path, identity, 'poll').get('revoked') is True
    rejected('restart_cannot_ack_unknown_reservations', 'cancel_ack', 'RECOVERY_RECONCILIATION_REQUIRED', active_model_requests=0, sessions=[])
    server.shutdown(); server.server_close(); controller.file.close(); path.unlink()
    # Inject an actual writer error; the broker must latch uncertainty even if
    # the filesystem recovers before the following request.
    server, controller = serve(policy, path, private / 'io-failure.ndjson')
    writer = controller.file
    class FailedWriter:
        def write(self, _text):
            raise OSError('injected journal write failure')
    controller.file = FailedWriter()
    try:
        controller.handle({'schema_version': 'forgeflow.dsh-bridge.v1', 'operation': 'admit', **identity,
                           'native_session_id': 'io-root', 'parent_session_id': None,
                           'delegation_depth': 0, 'source': 'startup', 'origin': None})
        checks['journal_failure_latches_recovery'] = False
    except OSError:
        checks['journal_failure_latches_recovery'] = controller.recovery_required
    finally:
        controller.file = writer
    checks['recovered_io_cannot_grant_new_work'] = admit('post-io').get('code') == 'RECOVERY_RECONCILIATION_REQUIRED'
    rejected('recovered_io_cannot_ack', 'cancel_ack', 'RECOVERY_RECONCILIATION_REQUIRED', active_model_requests=0, sessions=[])
    server.shutdown(); server.server_close(); controller.file.close(); path.unlink()
    report = {'schema_version': 'forgeflow.local-controller-verification.v1',
              'scope': 'real_unix_socket_local_broker_guards_without_DSH_or_model_calls',
              'outcome': 'PASS' if all(checks.values()) else 'FAIL', 'checks': checks,
              'denominator': len(checks), 'production_admission': 'BLOCKED_PENDING_CANONICAL_CHILD_ACCOUNTING'}
    (HERE / 'controller-guards.verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    return report


if __name__ == '__main__':
    raise SystemExit(0 if verify()['outcome'] == 'PASS' else 1)
