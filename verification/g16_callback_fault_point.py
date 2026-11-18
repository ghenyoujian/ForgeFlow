#!/usr/bin/env python3
"""Missing real transport/lease/cancel fault points, source preparation by default.

A bounded private relay forwards original Worker bytes. It may drop real ACKs,
interrupt heartbeat transport, or hold a genuine result before forwarding it.
No fabricated result, SQL authority updates, Worker crash or Git crash replay.
"""
import argparse
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'verification'))
sys.path.insert(0, str(ROOT / 'verification/fixtures'))
from cross_project_business_chain import Client, actual_running, git, paused, policy, private_bytes, provision, save, stop_attempt, wait
from guarded_api_chain import create_database, database_command, secure_save
from metrics import process_fingerprint

IDENTITY = 'b3b419fb72104f880225205226198701ccd98cf1f5a30ba11aa3f916ad8eb034'
RECEIPT_SHA = 'a7c04716f8cb1836be4a8c523c85280b3ab7447f469404c0abd4c5ca9b5b09d7'


def load(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main_identity():
    r = subprocess.run(['systemctl', '--user', 'show', 'forgeflow-control.service', '--property=MainPID',
        '--property=ActiveState'], capture_output=True, text=True, check=True, timeout=15)
    return dict(line.split('=', 1) for line in r.stdout.splitlines())


def same_process(a, b):
    return bool(a and b and all(a[k] == b[k] for k in ('pid', 'start_ticks', 'cmdline')))


class Relay:
    def __init__(self, upstream_port, relay_port, token, private, output):
        self.upstream_port, self.token, self.private, self.output = upstream_port, token, private, output
        self.lock = threading.Lock()
        self.records = []
        self.counter = 0
        self.mode = 'ack-loss'
        self.claim_dropped = self.result_dropped = False
        self.heartbeat_block = False
        self.release_results = threading.Event()
        self.held_result = threading.Event()
        self.closed = False
        relay = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.0'

            def log_message(self, *args):
                pass

            def do_GET(self):
                self.forward()

            def do_POST(self):
                self.forward()

            def do_PATCH(self):
                self.forward()

            def forward(self):
                with relay.lock:
                    relay.counter += 1
                    number = relay.counter
                    mode = relay.mode
                stem = f'relay-{number:07d}'
                length = int(self.headers.get('Content-Length', '0'))
                if length > 32 * 1024 * 1024:
                    self.send_error(413)
                    return
                body = self.rfile.read(length) if length else b''
                worker = self.headers.get('Authorization') == 'Bearer ' + relay.token
                parsed = json.loads(body) if body else {}
                record = {'index': number, 'method': self.command, 'path': self.path, 'worker_transport': worker,
                    'mode': mode, 'request_sha256': digest(body), 'request': parsed, 'fault': None}
                private_bytes(relay.private / (stem + '.request.bin'), body)

                remembered = False

                def remember():
                    nonlocal remembered
                    if remembered:
                        return
                    remembered = True
                    with relay.lock:
                        relay.records.append(record)
                    save(relay.output / (stem + '.json'), record)

                def disconnect():
                    self.close_connection = True
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

                if worker and self.path.endswith('/heartbeat') and '/attempts/' in self.path and relay.heartbeat_block:
                    record['fault'] = 'ATTEMPT_HEARTBEAT_TRANSPORT_INTERRUPTED_NO_UPSTREAM_WRITE'
                    remember()
                    disconnect()
                    return
                result = worker and self.path.endswith('/execution-result')
                if result and mode in ('heartbeat', 'cancel-collision'):
                    record['fault'] = 'GENUINE_WORKER_RESULT_HELD_BEFORE_UPSTREAM'
                    relay.held_result.set()
                    if not relay.release_results.wait(75):
                        record['error'] = 'FINITE_HOLD_TIMEOUT; original request preserved, no invented response'
                        remember()
                        disconnect()
                        return
                connection = http.client.HTTPConnection('127.0.0.1', relay.upstream_port, timeout=35)
                headers = {k: v for k, v in self.headers.items() if k.lower() not in ('host', 'connection', 'content-length')}
                try:
                    connection.request(self.command, self.path, body=body or None, headers=headers)
                    response = connection.getresponse()
                    record['upstream_status'] = response.status
                    if response.getheader('Content-Type', '').startswith('text/event-stream'):
                        self.send_response(response.status)
                        self.send_header('Content-Type', 'text/event-stream')
                        self.end_headers()
                        while not relay.closed:
                            line = response.readline()
                            if not line:
                                break
                            self.wfile.write(line)
                            self.wfile.flush()
                        record['stream_passthrough'] = True
                        remember()
                        return
                    raw = response.read()
                    private_bytes(relay.private / (stem + '.response.bin'), raw)
                    record['response_sha256'] = digest(raw)
                    try:
                        record['response'] = json.loads(raw) if raw else None
                        record['response_format'] = 'json' if raw else 'empty'
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        record['response'] = None
                        record['response_format'] = 'opaque-original-bytes'
                    envelope = record['response'].get('envelope') if isinstance(record['response'], dict) else None
                    with relay.lock:
                        drop_claim = worker and self.path.endswith('/claim') and envelope is not None and not relay.claim_dropped
                        drop_result = result and mode == 'ack-loss' and response.status == 200 and not relay.result_dropped
                        if drop_claim:
                            relay.claim_dropped = True
                        if drop_result:
                            relay.result_dropped = True
                    if drop_claim or drop_result:
                        record['fault'] = ('FIRST_ACTUAL_CLAIM_RESPONSE_DROPPED_AFTER_COMMIT' if drop_claim
                            else 'FIRST_ACTUAL_RESULT_RESPONSE_DROPPED_AFTER_COMMIT')
                        remember()
                        disconnect()
                        return
                    self.send_response(response.status)
                    self.send_header('Content-Type', response.getheader('Content-Type', 'application/json'))
                    self.send_header('Content-Length', str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    remember()
                except Exception as error:
                    record['transport_error_type'] = type(error).__name__
                    remember()
                    disconnect()
                finally:
                    connection.close()

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', relay_port), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def phase(self, name):
        with self.lock:
            self.mode = name
            self.heartbeat_block = False
            self.held_result.clear()
            self.release_results.clear()

    def rows(self):
        with self.lock:
            return list(self.records)

    def stop(self):
        self.closed = True
        self.release_results.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


def prepare(args):
    receipt = load(args.build_receipt)
    assert receipt['source_identity'] == IDENTITY and sha(args.build_receipt) == RECEIPT_SHA
    assert receipt['consistent_copy'] and receipt['source_unchanged_after_build'] and all(c['exit_code'] == 0 for c in receipt['commands'])
    binaries = {n: receipt['binaries'][n] for n in ('forgeflow-server', 'forgeflow-worker', 'forgeflow-sandbox-guard', 'forgeflow')}
    assert all(sha(b['path']) == b['sha256'] for b in binaries.values())
    assert args.port != args.relay_port and all(p not in (8787, 8788, 8793) and 1024 <= p <= 65535 for p in (args.port, args.relay_port))
    paths = ['verification/g16_callback_fault_point.py', 'verification/cross_project_business_chain.py',
        'verification/guarded_api_chain.py', 'verification/algorithm_check.py', 'verification/fixtures/control_verifier.py', 'benchmarks/metrics.py']
    frozen = Path(receipt['snapshot_root'])
    components = ['crates/worker/src/lib.rs', 'crates/store/src/lifecycle.rs', 'crates/runtime/src/process.rs',
        'crates/runtime/src/journal.rs', 'crates/api/src/workers.rs', 'crates/server/src/main.rs']
    assert all(sha(frozen / p) == receipt['source_files'][p] for p in components)
    return {'schema_version': 'forgeflow.g16-callback-fault-source-plan.v1', 'status': 'SOURCE_READY_NO_ACTORS',
        'source_identity': IDENTITY, 'build_receipt': {'path': str(args.build_receipt.resolve()), 'sha256': RECEIPT_SHA},
        'binaries': binaries, 'helper_pins': {p: sha(ROOT / p) for p in paths},
        'frozen_components': {p: {'path': str(frozen / p), 'sha256': sha(frozen / p)} for p in components},
        'main_pid': args.main_pid, 'upstream_port': args.port, 'relay_port': args.relay_port,
        'caps': {'private_APIs': 1, 'private_relay_listener': 1, 'Workers': 1, 'controlled_authors': 3,
            'maximum_active_authors': 1, 'models': 0, 'verifiers': 0, 'Cargo': 0},
        'windows': ['Drop first genuine claimed envelope response after dispatch commit; actual Worker retry returns same envelope, one author',
            'Drop first genuine result response after upstream commit; immutable Worker result replay has one event/state/resource effect',
            'After genuine30s renewal interrupt attempt heartbeats; hold actual stop result until real expiry event/quarantine observed; forward original stop proof',
            'Hold genuine successful execution result; legitimate Owner cancel then forward unchanged result; cancellation cannot become business success'],
        'recording_policy': 'Relay request/response numbered under one locked counter; SELECT observations numbered per label; distinct single create_database diagnostics; no immutable overwrite.',
        'actor_alarm_seconds': 300, 'max_result_hold_seconds': 75, 'Root_GO_exact_plan_required': True,
        'not_proven': ['LaunchIntent-to-LaunchReceipt missing-receipt micro-window', 'Worker crash already qualified separately and not repeated',
            'Git commit crash already qualified separately and not repeated', 'Native DSH/model faults', 'Powerloss/fullfaultmatrix', 'Physical OS resource enforcement']}


def run(args, plan):
    p = args.output / 'source-ready-plan.json'
    assert sha(p) == args.expected_plan_sha256 and load(p) == plan and not (args.output / 'report.json').exists()
    original_main = main_identity()
    assert original_main == {'MainPID': str(args.main_pid), 'ActiveState': 'active'}
    for port in (args.port, args.relay_port):
        with socket.socket() as sk:
            assert sk.connect_ex(('127.0.0.1', port)) != 0
    private = Path(tempfile.mkdtemp(prefix='forgeflow-g16-callback-', dir='/home/chenyoujian/.cache'))
    private.chmod(0o700)
    (private / 'state').mkdir(mode=0o700)
    (private / 'relay').mkdir(mode=0o700)
    (private / 'diagnostics').mkdir(mode=0o700)
    maintenance = load(args.private_env)
    name = 'forgeflow_g16_callback_' + uuid.uuid4().hex[:16]
    env = {'DATABASE_URL': create_database(maintenance, name, private), 'FORGEFLOW_BIND': f'127.0.0.1:{args.port}',
        'FORGEFLOW_DATA_ROOT': str(private / 'state'), 'FORGEFLOW_OWNER_TOKEN': secrets.token_hex(32),
        'FORGEFLOW_WORKER_TOKEN': secrets.token_hex(32), 'RUST_LOG': 'info'}
    secure_save(private / 'runtime-env.json', env)
    client = Client(f'http://127.0.0.1:{args.relay_port}', env['FORGEFLOW_OWNER_TOKEN'], args.output / 'owner-http', private / 'diagnostics')
    client.worker_token, client.database_url = env['FORGEFLOW_WORKER_TOKEN'], env['DATABASE_URL']
    client.sensitive.add(client.worker_token)
    report = {'schema_version': 'forgeflow.g16-actual-callback-faults.v1', 'status': 'RUNNING', 'source_identity': IDENTITY,
        'source_plan_sha256': sha(p), 'private_root': str(private), 'database_name': name, 'checks': [], 'errors': [],
        'models': 0, 'verifiers': 0, 'attempts': [], 'not_proven': plan['not_proven']}
    api = log = relay = fixture = None
    counts = {}

    def check(label, condition, facts=None):
        report['checks'].append({'name': label, 'status': 'PASS' if condition else 'FAIL', 'facts': facts})
        save(args.output / 'report.json', report)
        if not condition:
            raise RuntimeError('Actual fault assertion failed: ' + label)

    def query(sql, url=None):
        result = database_command(url or env['DATABASE_URL'], sql)
        if result.returncode:
            raise RuntimeError('Owned database observation failed; private evidence retained')
        return result.stdout

    def observe(label, aid):
        sql = f"SELECT jsonb_build_object('attempt',(SELECT data FROM attempts WHERE attempt_id='{aid}'),'held',(SELECT count(*) FROM resource_allocations WHERE attempt_id='{aid}' AND state<>'RELEASED'),'leases',COALESCE((SELECT jsonb_agg(to_jsonb(l)) FROM leases l WHERE attempt_id='{aid}'),'[]'::jsonb),'allocations',COALESCE((SELECT jsonb_agg(to_jsonb(a)) FROM resource_allocations a WHERE attempt_id='{aid}'),'[]'::jsonb),'result_records',COALESCE((SELECT jsonb_agg(payload) FROM worker_event_ids WHERE attempt_id='{aid}'),'[]'::jsonb),'events',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY project_seq) FROM events e WHERE object_id='{aid}'),'[]'::jsonb),'dispatch',COALESCE((SELECT jsonb_agg(to_jsonb(o)) FROM outbox o WHERE payload->>'attempt_id'='{aid}'),'[]'::jsonb),'models',(SELECT count(*) FROM model_request_permit),'evidence',(SELECT count(*) FROM evidence_receipts),'merges',(SELECT count(*) FROM merge_intents));"
        raw = query(sql)
        counts[label] = counts.get(label, 0) + 1
        unique = label + f'-{counts[label]:06d}'
        private_bytes(private / (unique + '.authority.bin'), raw)
        value = json.loads(raw)
        save(args.output / (unique + '.authority.json'), value)
        return value

    def started(phase):
        relay.phase(phase)
        paused(client, fixture['project_id'], False)
        row = wait(lambda: actual_running(client, [fixture['project_id']], private,
            [a['attempt_id'] for a in report['attempts']]), 'next single actual controlled author', 45)[0]
        paused(client, fixture['project_id'], True)
        report['attempts'].append(row['attempt'])
        return row

    def finish_author(row):
        identity = row['fingerprint']
        assert same_process(process_fingerprint(identity['pid']), identity)
        os.kill(identity['pid'], signal.SIGUSR1)

    def settled(aid):
        def terminal():
            state = client.api('GET', f"/attempts/{aid}?project_id={fixture['project_id']}")
            return state if state['state'] in ('CANCELLED', 'FAILED', 'SUCCEEDED') else None
        return wait(terminal, 'actual terminal stop settlement', 35)

    def interrupt(signum, frame):
        raise RuntimeError('Finite actor deadline interrupted')

    previous_alarm = signal.signal(signal.SIGALRM, interrupt)
    previous_term = signal.signal(signal.SIGTERM, interrupt)
    signal.alarm(plan['actor_alarm_seconds'])
    try:
        log = os.fdopen(os.open(private / 'api.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
        api = subprocess.Popen([plan['binaries']['forgeflow-server']['path']], env={'PATH': '/usr/bin:/bin', **env}, stdout=log, stderr=subprocess.STDOUT)
        relay = Relay(args.port, args.relay_port, client.worker_token, private / 'relay', args.output / 'relay')
        def ready():
            assert api.poll() is None
            try:
                return client.request('GET', '/me')[0] == 200
            except OSError:
                return False
        wait(ready, 'one private upstream API and relay', 30)
        policy(client, 'global')
        fixture = provision(client, private, load(args.build_receipt), 'callback-faults', 3, 1, 416)
        report['project_id'] = fixture['project_id']
        baseline = git(fixture['canonical'], 'rev-parse', 'refs/heads/main')
        first = started('ack-loss')
        aid = first['attempt']['attempt_id']
        claim_rows = [r for r in relay.rows() if r['path'].endswith('/claim') and isinstance(r.get('response'), dict)
            and (r['response'].get('envelope') or {}).get('attempt_id') == aid]
        check('actual_lost_claim_ACK_redelivers_same_original_envelope_one_author', relay.claim_dropped
            and len(claim_rows) >= 2 and len({r['response_sha256'] for r in claim_rows}) == 1,
            {'claim_responses': claim_rows, 'actual_author': first['fingerprint']})
        finish_author(first)
        def replayed():
            rows = [r for r in relay.rows() if r['path'] == f'/api/v1/attempts/{aid}/execution-result'
                and r.get('upstream_status') == 200]
            return rows if relay.result_dropped and len(rows) >= 2 else None
        result_rows = wait(replayed, 'real lost result ACK followed by immutable Worker replay', 25)
        proof = observe('result-replay', aid)
        original_packet = result_rows[0]['request']
        check('lost_result_ACK_has_one_exact_event_revision_and_resource_effect', len({r['request_sha256'] for r in result_rows}) == 1
            and len([r for r in proof['result_records'] if r['event_id'] == original_packet['event_id']]) == 1
            and len([e for e in proof['events'] if e['kind'] == 'attempt.execution_returned']) == 1
            and proof['attempt']['state'] == 'VERIFYING' and proof['held'] == 28,
            {'result_transport': result_rows, 'authority': proof})
        stop_attempt(client, proof['attempt'])
        settled(aid)
        check('ack_fault_original_author_stopped_and_output_preserved', process_fingerprint(first['fingerprint']['pid']) is None
            and first['artifact']['sha256'] == sha(private / 'state/worktrees' / aid / 'result-0.json'))

        second = started('heartbeat')
        aid = second['attempt']['attempt_id']
        wait(lambda: any(r['path'] == f'/api/v1/attempts/{aid}/heartbeat' and r.get('upstream_status') == 200
            for r in relay.rows()), 'first genuine30second lease renewal', 10)
        relay.heartbeat_block = True
        before_expiry = observe('heartbeat-before-expiry', aid)
        def expired():
            state = observe('heartbeat-expiry-observation', aid)
            return state if any(e['kind'] == 'attempt.lease_expired' for e in state['events']) else None
        quarantined = wait(expired, 'actual server lease-expiry event with held stop callback', 45)
        check('real_heartbeat_expiry_revokes_and_quarantines_until_stop_proof', quarantined['attempt']['state'] == 'RECOVERY_REQUIRED'
            and quarantined['held'] == 28 and all(l['revoked_at'] for l in quarantined['leases'])
            and all(a['state'] == 'QUARANTINED' for a in quarantined['allocations']),
            {'before': before_expiry, 'after_expiry': quarantined, 'author_at_expiry': process_fingerprint(second['fingerprint']['pid'])})
        assert relay.held_result.wait(10), 'No genuine Worker stop packet captured after lease expiry'
        relay.release_results.set()
        terminal = settled(aid)
        after_expiry = observe('heartbeat-after-stop-proof', aid)
        check('heartbeat_expiry_authentic_stop_frees_no_earlier_than_ledger_settlement', terminal['state'] == 'CANCELLED'
            and after_expiry['held'] == 0 and process_fingerprint(second['fingerprint']['pid']) is None,
            {'terminal': terminal, 'stop': load(second['journal'] / 'stop.json')})

        third = started('cancel-collision')
        aid = third['attempt']['attempt_id']
        finish_author(third)
        assert relay.held_result.wait(15), 'No genuine successful completion packet captured'
        before_cancel = observe('before-cancel-completion-collision', aid)
        latest = client.api('GET', f"/attempts/{aid}?project_id={fixture['project_id']}")
        response = client.api('POST', f'/attempts/{aid}/cancel', {'project_id': fixture['project_id'],
            'expected_revision': latest['revision'], 'reason': 'Owner cancels while original successful Worker result is held in transport'})
        relay.release_results.set()
        terminal = settled(aid)
        after_cancel = observe('after-cancel-completion-collision', aid)
        packet = load(third['journal'] / 'result.json')
        check('actual_cancel_with_genuine_success_packet_never_revives_success', before_cancel['attempt']['state'] == 'RUNNING'
            and packet['outcome']['completion_reason'] == 'EXECUTOR_COMPLETED' and packet['outcome']['exit_code'] == 0
            and terminal['state'] == 'CANCELLED' and after_cancel['held'] == 0
            and not any(e['kind'] == 'attempt.succeeded' for e in after_cancel['events']),
            {'original_successful_packet': packet, 'owner_cancel_receipt': response, 'terminal': terminal,
                'original_author_stopped': process_fingerprint(third['fingerprint']['pid']) is None})
        final = json.loads(query("SELECT jsonb_build_object('attempts',(SELECT count(*) FROM attempts),'open',(SELECT count(*) FROM attempts WHERE terminal_at IS NULL),'held',(SELECT count(*) FROM resource_allocations WHERE state<>'RELEASED'),'leases',(SELECT count(*) FROM leases WHERE revoked_at IS NULL),'models',(SELECT count(*) FROM model_request_permit),'evidence',(SELECT count(*) FROM evidence_receipts),'merges',(SELECT count(*) FROM merge_intents));"))
        check('three_real_fault_windows_no_duplicate_attempts_or_business_completion', final['attempts'] == 3
            and all(final[k] == 0 for k in ('open', 'held', 'leases', 'models', 'evidence', 'merges'))
            and git(fixture['canonical'], 'rev-parse', 'refs/heads/main') == baseline, final)
    except BaseException as error:
        report['errors'].append({'type': type(error).__name__, 'message': str(error)})
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            report['interrupted'] = True
    finally:
        signal.alarm(0)
        if relay:
            relay.release_results.set()
            relay.heartbeat_block = False
        if fixture and api and api.poll() is None:
            for attempt in report['attempts']:
                try:
                    stop_attempt(client, attempt)
                except Exception as error:
                    report['errors'].append({'cleanup': 'Owner stop', 'type': type(error).__name__})
        report['process_shutdown'] = []
        for label, process in [(f'worker-{i}', w['process']) for i, w in enumerate(client.workers)] + [('api', api)]:
            if process is None:
                continue
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=35)
                except subprocess.TimeoutExpired:
                    report['errors'].append({'cleanup': label, 'error': 'positive exit unconfirmed'})
            report['process_shutdown'].append({'label': label, 'pid': process.pid, 'exit_code': process.poll(), 'confirmed': process.poll() is not None})
        for worker in client.workers:
            worker['log'].close()
        if log:
            log.close()
        if relay:
            relay.stop()
        closed = all(p['confirmed'] for p in report['process_shutdown'])
        cleanup = {'database': name, 'status': 'RETAINED', 'raw_journals_retained_private': str(private / 'state/attempts')}
        if closed:
            try:
                raw = query("SELECT jsonb_build_object('attempts',(SELECT jsonb_agg(to_jsonb(t)) FROM attempts t),'events',(SELECT jsonb_agg(to_jsonb(t) ORDER BY project_id,project_seq) FROM events t),'outbox',(SELECT jsonb_agg(to_jsonb(t)) FROM outbox t),'worker_result_records',(SELECT jsonb_agg(to_jsonb(t)) FROM worker_event_ids t),'held',(SELECT count(*) FROM resource_allocations WHERE state<>'RELEASED'),'leases',(SELECT count(*) FROM leases WHERE revoked_at IS NULL),'models',(SELECT count(*) FROM model_request_permit));")
                final = json.loads(raw)
                private_bytes(private / 'original-final-database-history.bin', raw)
                save(args.output / 'original-final-public-history.json', final)
                assert final['held'] == final['leases'] == final['models'] == 0
                assert all(t['terminal_at'] for t in final['attempts'] or [])
                query('DROP DATABASE "' + name + '";', maintenance['DATABASE_URL'])
                assert int(query("SELECT count(*) FROM pg_database WHERE datname='" + name + "';", maintenance['DATABASE_URL']).strip()) == 0
                cleanup.update(status='EXPORTED_AND_DROPPED', original_final_sha256=digest(raw))
            except Exception as error:
                cleanup['error_type'] = type(error).__name__
                report['errors'].append({'cleanup': name, 'type': type(error).__name__})
        report['main_after'] = main_identity()
        ports_closed = True
        for port in (args.port, args.relay_port):
            with socket.socket() as sk:
                ports_closed = ports_closed and sk.connect_ex(('127.0.0.1', port)) != 0
        report['checks'].append({'name': 'owned_actors_closed_main_unchanged_originals_exported', 'status': 'PASS'
            if closed and ports_closed and report['main_after'] == original_main and cleanup['status'] == 'EXPORTED_AND_DROPPED' else 'FAIL'})
        save(args.output / 'cleanup.json', cleanup)
        report['status'] = ('PASS_ACTUAL_CALLBACK_FAULT_WINDOWS' if not report['errors']
            and all(c['status'] == 'PASS' for c in report['checks']) else 'FAIL')
        report['raw_manifest'] = [{'path': str(f.relative_to(ROOT)), 'sha256': sha(f), 'bytes': f.stat().st_size}
            for f in args.output.rglob('*') if f.is_file() and f.name != 'report.json']
        save(args.output / 'report.json', report)
        signal.signal(signal.SIGALRM, previous_alarm)
        signal.signal(signal.SIGTERM, previous_term)
    print(json.dumps({'status': report['status'], 'checks': len(report['checks']), 'report': str(args.output / 'report.json')}))
    return 0 if report['status'] == 'PASS_ACTUAL_CALLBACK_FAULT_WINDOWS' else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build-receipt', type=Path, required=True)
    p.add_argument('--private-env', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--main-pid', type=int, required=True)
    p.add_argument('--port', type=int, default=8899)
    p.add_argument('--relay-port', type=int, default=8900)
    p.add_argument('--execute-authorized', action='store_true')
    p.add_argument('--expected-plan-sha256')
    args = p.parse_args()
    args.output = args.output.resolve()
    assert args.output.is_relative_to((ROOT / 'evidence/goal-gap-points-r4/g16/callback-faults-r1').resolve())
    plan = prepare(args)
    if args.execute_authorized:
        return run(args, plan)
    args.output.mkdir(parents=True, exist_ok=True)
    assert not (args.output / 'source-ready-plan.json').exists()
    save(args.output / 'source-ready-plan.json', plan)
    print(json.dumps({'status': plan['status'], 'plan': str(args.output / 'source-ready-plan.json'), 'plan_sha256': sha(args.output / 'source-ready-plan.json')}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
