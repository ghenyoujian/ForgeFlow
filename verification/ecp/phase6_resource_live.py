#!/usr/bin/env python3
"""Disposable API/PostgreSQL checks for the ECP 0019 resource runtime.

This is an observed slice check only. It does not qualify an ECP Gate or claim
physical OS/cgroup enforcement.
"""
from __future__ import annotations
import argparse, json, pathlib, secrets, urllib.error, urllib.request, uuid
import psycopg

PG = 'host=/home/chenyoujian/.local/state/forgeflow/postgres port=55432 user=forgeflow'
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def call(run, route, body=None, user=None, workspace=None, expected=200, key=None):
    headers = {'Accept': 'application/json'}
    if user:
        headers['Authorization'] = 'Bearer ' + user['token']
    if workspace:
        headers['X-ForgeFlow-Workspace'] = workspace
    if body is not None:
        headers.update({'Content-Type': 'application/json', 'Idempotency-Key': key or ('ecp-' + uuid.uuid4().hex)})
    request = urllib.request.Request(run['base'] + '/api/v1' + route,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers=headers)
    try:
        with OPENER.open(request, timeout=20) as response:
            status, payload = response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        status, payload = exc.code, json.loads(exc.read())
    if status != expected:
        raise AssertionError(f'{route}: expected {expected}, got {status}: {payload}')
    return payload.get('data', payload)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    run = json.loads((args.output / 'private.json').read_text())
    checks = []
    report = {'status': 'FAIL', 'qualification': 'OBSERVED_NOT_GATE', 'model_calls': 0}

    def verify(name, passed):
        checks.append({'name': name, 'passed': bool(passed)})
        if not passed:
            raise AssertionError(name)

    def register(label):
        email = f'{label}-{secrets.token_hex(3)}@example.test'
        password = secrets.token_hex(16)
        value = call(run, '/registrations', {'email': email, 'display_name': label, 'password': password})
        return {'token': value['token'], 'account_id': value['account']['account_id'], 'workspace': value['account']['workspace_id'], 'email': email}

    try:
        owner = register('resource-owner')
        workspace = owner['workspace']
        source = 'a' * 64
        profile_id = 'resource-profile-' + uuid.uuid4().hex
        profile = call(run, f'/workspaces/{workspace}/resource-profiles', {
            'profile_id': profile_id,
            'profile_version': 'v1',
            'logical_limits': {'active_slot': 2, 'model_cost': 10},
            'physical_limits': {'cpu_units': 4, 'memory_bytes': 1073741824},
            'enforcement_status': 'OBSERVED',
            'source_sha256': source,
        }, user=owner, workspace=workspace, key='profile-' + uuid.uuid4().hex)
        replay = call(run, f'/workspaces/{workspace}/resource-profiles', {
            'profile_id': profile_id,
            'profile_version': 'v1',
            'logical_limits': {'active_slot': 2, 'model_cost': 10},
            'physical_limits': {'cpu_units': 4, 'memory_bytes': 1073741824},
            'enforcement_status': 'OBSERVED',
            'source_sha256': source,
        }, user=owner, workspace=workspace, key='profile-replay-' + uuid.uuid4().hex)
        verify('logical and physical profile vectors persist separately', profile['logical_limits']['active_slot'] == 2 and replay['replayed'] is True)

        db = run['database']
        with psycopg.connect(PG + ' dbname=' + db, autocommit=True) as conn:
            epoch = conn.execute("SELECT authorization_epoch FROM principals WHERE principal_id=%s", ('human:' + owner['account_id'],)).fetchone()[0]
        reservation_id = 'reservation-' + uuid.uuid4().hex
        reservation_key = 'reservation-key-' + uuid.uuid4().hex
        reservation_body = {
            'reservation_id': reservation_id, 'profile_id': profile_id,
            'dimension': 'active_slot', 'amount': 1.5,
            'authorization_epoch': epoch, 'idempotency_key': reservation_key,
        }
        first = call(run, f'/workspaces/{workspace}/budget-reservations', reservation_body,
                     user=owner, workspace=workspace, key=reservation_key)
        replay = call(run, f'/workspaces/{workspace}/budget-reservations', reservation_body,
                      user=owner, workspace=workspace, key=reservation_key)
        verify('budget reservation is idempotent', first['reservation_id'] == reservation_id and replay['replayed'] is True)
        over = {**reservation_body, 'reservation_id': 'reservation-over-' + uuid.uuid4().hex,
                'idempotency_key': 'reservation-over-' + uuid.uuid4().hex, 'amount': 1}
        call(run, f'/workspaces/{workspace}/budget-reservations', over, user=owner,
             workspace=workspace, expected=409, key=over['idempotency_key'])
        verify('logical capacity rejects an over-reservation', True)

        unknown = call(run, f'/workspaces/{workspace}/cost-ledger', {
            'ledger_id': 'ledger-unknown-' + uuid.uuid4().hex,
            'reservation_id': reservation_id,
            'provider_request_id': 'provider-' + uuid.uuid4().hex,
            'currency': 'USD', 'estimated_cost': 1.0, 'settled_cost': None,
            'usage': {'tokens': None}, 'settlement_status': 'UNKNOWN', 'source_sha256': source,
        }, user=owner, workspace=workspace, key='cost-unknown-' + uuid.uuid4().hex)
        with psycopg.connect(PG + ' dbname=' + db, autocommit=True) as conn:
            state, held = conn.execute("SELECT state,reserved_amount>0 FROM ecp_budget_reservations WHERE reservation_id=%s", (reservation_id,)).fetchone()
        verify('unknown usage remains explicit and keeps budget held', unknown['settlement_status'] == 'UNKNOWN' and state == 'HELD' and held)

        settled = call(run, f'/workspaces/{workspace}/cost-ledger', {
            'ledger_id': 'ledger-settled-' + uuid.uuid4().hex,
            'reservation_id': reservation_id,
            'provider_request_id': 'provider-settled-' + uuid.uuid4().hex,
            'currency': 'USD', 'estimated_cost': 1.0, 'settled_cost': 0.75,
            'usage': {'tokens': 12}, 'settlement_status': 'SETTLED', 'source_sha256': source,
        }, user=owner, workspace=workspace, key='cost-settled-' + uuid.uuid4().hex)
        with psycopg.connect(PG + ' dbname=' + db, autocommit=True) as conn:
            state, held = conn.execute("SELECT state,reserved_amount>0 FROM ecp_budget_reservations WHERE reservation_id=%s", (reservation_id,)).fetchone()
        verify('settlement closes a reservation only explicitly', settled['settlement_status'] == 'SETTLED' and state == 'SETTLED' and not held)

        revocation_id = 'revocation-' + uuid.uuid4().hex
        revocation = call(run, f'/workspaces/{workspace}/lease-revocations', {
            'revocation_id': revocation_id, 'principal_id': 'human:' + owner['account_id'],
            'generation': 1, 'reason_code': 'operator_cancel', 'source_sha256': source,
        }, user=owner, workspace=workspace, key='revoke-' + uuid.uuid4().hex)
        replay = call(run, f'/workspaces/{workspace}/lease-revocations', {
            'revocation_id': revocation_id, 'principal_id': 'human:' + owner['account_id'],
            'generation': 1, 'reason_code': 'operator_cancel', 'source_sha256': source,
        }, user=owner, workspace=workspace, key='revoke-replay-' + uuid.uuid4().hex)
        verify('lease revocation is durable and replayable', revocation['status'] == 'REQUESTED' and replay['replayed'] is True)
        with psycopg.connect(PG + ' dbname=' + db, autocommit=True) as conn:
            stored = conn.execute("SELECT status FROM ecp_lease_revocations WHERE revocation_id=%s", (revocation_id,)).fetchone()[0]
        verify('revocation status remains an explicit non-stop observation', stored == 'REQUESTED')
        report.update({'status': 'PASS', 'database': db, 'checks': checks})
    except Exception as exc:
        report.update({'error': str(exc), 'checks': checks})
        raise
    finally:
        args.output.joinpath('phase6-resource-live-report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'checks': len(checks), 'model_calls': 0, 'qualification': report['qualification']}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
