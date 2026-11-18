#!/usr/bin/env python3
"""Private local qualification broker; deliberately not PostgreSQL admission authority."""
import argparse
import json
import os
from pathlib import Path
import socketserver
import threading
import time
import uuid

SCHEMA = 'forgeflow.dsh-bridge.v1'
IDENTITY = ('project_id', 'task_id', 'attempt_id', 'generation')


class Rejected(Exception):
    pass


class Controller:
    def __init__(self, policy, ledger):
        self.policy, self.ledger = policy, Path(ledger)
        self.lock = threading.Lock()
        self.allocations, self.requests = {}, {}
        self.root = None
        self.revoked = False
        self.recovery_required = self.ledger.exists() and self.ledger.stat().st_size > 0
        self.total = 0
        self.ledger.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.file = self.ledger.open('a', encoding='utf-8')
        self.ledger.chmod(0o600)
        self.record('broker_start', {'recovery_required': self.recovery_required,
                    'authority': 'LOCAL_QUALIFICATION_ONLY'})

    def record(self, operation, fields):
        try:
            self.file.write(json.dumps({'time_ns': time.time_ns(), 'operation': operation, **fields}) + '\n')
            self.file.flush()
            os.fsync(self.file.fileno())
        except OSError:
            self.recovery_required = True
            raise

    def handle(self, request):
        with self.lock:
            try:
                result = self.dispatch(request)
                return {'ok': True, 'generation': self.policy['generation'], **result}
            except Rejected as error:
                self.record('rejected', {'requested_operation': request.get('operation'), 'code': str(error),
                            'native_session_id': request.get('native_session_id')})
                return {'ok': False, 'generation': self.policy['generation'], 'code': str(error)}

    def dispatch(self, request):
        if request.get('schema_version') != SCHEMA:
            raise Rejected('SCHEMA_MISMATCH')
        if any(request.get(key) != self.policy[key] for key in IDENTITY):
            raise Rejected('STALE_OR_WRONG_IDENTITY')
        operation = request.get('operation')
        if operation == 'poll':
            return {'revoked': self.revoked or self.recovery_required}
        if operation == 'revoke':
            self.revoked = True
            self.record('revoked', {'reason': request.get('reason', 'probe')})
            return {}
        if operation == 'cancel_ack':
            if self.recovery_required:
                raise Rejected('RECOVERY_RECONCILIATION_REQUIRED')
            sessions = request.get('sessions', [])
            active = {native for native, value in self.allocations.items() if not value['released']}
            acknowledged = {row.get('native_session_id') for row in sessions}
            if not all(row.get('status') == 'idle' for row in sessions) or not active.issubset(acknowledged) or any(
                    not value['settled'] for value in self.requests.values()) or request.get('active_model_requests') != 0:
                raise Rejected('CANCEL_NOT_QUIESCENT')
            self.record(operation, {'reason': request.get('reason'), 'sessions': sessions, 'active_model_requests': 0})
            return {}
        if operation in ('admit', 'model_request') and (self.revoked or self.recovery_required):
            raise Rejected('RECOVERY_RECONCILIATION_REQUIRED' if self.recovery_required else 'FENCE_REVOKED')
        if operation == 'admit':
            native, parent = request['native_session_id'], request['parent_session_id']
            if native in self.allocations and not self.allocations[native]['released']:
                raise Rejected('DUPLICATE_LIVE_SESSION')
            if parent is None:
                if self.root is not None and native != self.root:
                    raise Rejected('SECOND_ROOT')
                self.root = native
            elif parent not in self.allocations or self.allocations[parent]['released']:
                raise Rejected('UNALLOCATED_PARENT')
            if request['delegation_depth'] > self.policy['max_depth']:
                raise Rejected('DEPTH_LIMIT')
            if sum(not value['released'] for value in self.allocations.values()) >= self.policy['max_live_agents']:
                raise Rejected('AGENT_SLOTS_EXHAUSTED')
            if self.total >= self.policy['max_total_lifecycles']:
                raise Rejected('LIFECYCLE_LIMIT')
            self.total += 1
            grant = {'allocation_id': str(uuid.uuid4()), 'provider': self.policy['provider'],
                     'model': self.policy['model'], 'max_output_tokens': self.policy['max_output_tokens']}
            self.allocations[native] = {**grant, 'released': False, 'parent_session_id': parent}
            self.record(operation, {key: request.get(key) for key in ('native_session_id', 'parent_session_id', 'source', 'delegation_depth', 'origin')} | grant)
            return grant
        if operation in ('model_request', 'model_settle', 'release'):
            native = request.get('native_session_id')
            allocation = self.allocations.get(native)
            if not allocation or allocation['released'] or request.get('allocation_id') != allocation['allocation_id']:
                raise Rejected('STALE_OR_MISSING_ALLOCATION')
            if operation == 'release':
                if any(not row['settled'] and row['allocation_id'] == allocation['allocation_id']
                       for row in self.requests.values()):
                    raise Rejected('MODEL_REQUESTS_STILL_ACTIVE')
                allocation['released'] = True
                self.record(operation, {key: request[key] for key in ('native_session_id', 'allocation_id', 'reason')})
                return {}
            if operation == 'model_request':
                if (request.get('provider'), request.get('model')) != (self.policy['provider'], self.policy['model']):
                    raise Rejected('MODEL_ROUTE_DENIED')
                cap = request.get('max_output_tokens')
                if not isinstance(cap, int) or isinstance(cap, bool) or cap < 1 or cap > self.policy['max_output_tokens']:
                    raise Rejected('OUTPUT_CAP_REQUIRED')
                if len(self.requests) >= self.policy['max_model_requests']:
                    raise Rejected('MODEL_REQUEST_BUDGET_EXHAUSTED')
                if sum(not row['settled'] for row in self.requests.values()) >= self.policy.get('max_live_model_requests', self.policy['max_model_requests']):
                    raise Rejected('MODEL_CONCURRENCY_EXHAUSTED')
                if request['request_id'] in self.requests:
                    raise Rejected('DUPLICATE_MODEL_REQUEST')
                grant = str(uuid.uuid4())
                self.requests[request['request_id']] = {**request, 'request_grant_id': grant, 'settled': False}
                self.record(operation, {key: request[key] for key in ('native_session_id', 'allocation_id', 'request_id', 'provider', 'model', 'max_output_tokens', 'purpose')} | {'request_grant_id': grant})
                return {'request_grant_id': grant}
            previous = self.requests.get(request.get('request_id'))
            if not previous or previous['settled'] or previous['request_grant_id'] != request.get('request_grant_id') or previous['allocation_id'] != request['allocation_id']:
                raise Rejected('INVALID_MODEL_SETTLEMENT')
            previous['settled'] = True
            self.record(operation, {key: request.get(key) for key in ('native_session_id', 'allocation_id', 'request_id', 'request_grant_id', 'usage', 'usage_complete', 'finish_reason')})
            return {}
        if operation == 'observe':
            self.record(operation, {'event': request.get('event'), 'value': request.get('value')})
            return {}
        raise Rejected('UNKNOWN_OPERATION')


def serve(policy, socket_path, ledger):
    controller = Controller(policy, ledger)
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            line = self.rfile.readline(65537)
            if len(line) > 65536:
                return
            try:
                response = controller.handle(json.loads(line))
            except (ValueError, KeyError, TypeError):
                response = {'ok': False, 'code': 'INVALID_REQUEST', 'generation': policy['generation']}
            try:
                self.wfile.write(json.dumps(response).encode() + b'\n')
            except (BrokenPipeError, ConnectionResetError):
                # The committed allocation remains reserved after client timeout.
                with controller.lock:
                    controller.record('response_delivery_failed', {'operation': 'reply'})
    class Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads = True
    path = Path(socket_path)
    if path.exists():
        raise RuntimeError('Refusing to replace an existing controller socket')
    server = Server(str(path), Handler)
    path.chmod(0o600)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, controller


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--socket', required=True)
    parser.add_argument('--ledger', required=True)
    args = parser.parse_args()
    server, _controller = serve(json.loads(args.policy.read_text()), args.socket, args.ledger)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        server.shutdown()
        server.server_close()
        Path(args.socket).unlink(missing_ok=True)
