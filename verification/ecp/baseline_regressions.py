#!/usr/bin/env python3
"""Capture offline Phase 0 subprocess claims without issuing a product Gate."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

def run(command: list[str], cwd: Path) -> dict:
    # Offline probes must never inherit a production database or an opt-in guard.
    # Do not inherit interpreter/shell startup hooks (for example BASH_ENV),
    # which could restore database opt-ins after a blacklist was applied.
    allowed = {'PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'LC_CTYPE'}
    env = {key: value for key, value in os.environ.items() if key in allowed}
    try:
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True,
                                text=True, timeout=120, check=False)
        try:
            payload = json.loads(result.stdout)
        except (ValueError, TypeError):
            payload = None
        return {'command': command, 'exit_code': result.returncode,
                'stdout': result.stdout, 'stderr': result.stderr, 'payload': payload}
    except subprocess.TimeoutExpired as exc:
        def as_text(value):
            return value.decode('utf-8', errors='replace') if isinstance(value, bytes) else value or ''
        return {'command': command, 'status': 'INCONCLUSIVE', 'reason': str(exc),
                'stdout': as_text(exc.stdout), 'stderr': as_text(exc.stderr)}
    except OSError as exc:
        return {'command': command, 'status': 'INCONCLUSIVE', 'reason': str(exc)}

def findings(doctor: dict, database: dict, head: str | None, root: Path) -> list[dict]:
    payload = doctor.get('payload')
    checks = payload.get('checks', []) if isinstance(payload, dict) else []
    if not isinstance(checks, list):
        checks = []
    source = None
    source_count = 0
    failure_reported = False
    for item in checks:
        if isinstance(item, dict) and item.get('name') == 'source_identity':
            source_count += 1
            if source is None:
                source = item
            if item.get('status') == 'FAIL':
                failure_reported = True
    if source_count > 1:
        # Never promote one of several source identities to the sole truth.
        # Preserve a failure claim even when it is not the first entry.
        status = 'INCONCLUSIVE'
        reason = ('multiple source_identity probe claims are ambiguous; ' +
                  ('at least one source probe reports failure; ' if failure_reported else '') +
                  'source identity is not independently authenticated')
    else:
        details = source.get('details', {}) if isinstance(source, dict) else {}
        if not isinstance(details, dict):
            details = {}
        digest = details.get('source_manifest_sha256')
        bound = bool(head and details.get('source_sha') == head
                     and details.get('source_root') == str(root)
                     and isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest))
        if source and source.get('status') == 'PASS' and bound and details.get('dirty') is False:
            status, reason = 'INCONCLUSIVE', 'source probe reports a clean state consistent with claimed HEAD; source identity is not independently authenticated'
        elif source and source.get('status') == 'FAIL' and bound:
            status, reason = 'FAIL', 'source probe reports failure for claimed HEAD; source identity is not independently authenticated'
        elif source and source.get('status') == 'FAIL':
            status, reason = 'INCONCLUSIVE', 'source probe reports failure but its claim is not bound to the supplied HEAD, root and manifest digest; source identity is not independently authenticated'
        else:
            status, reason = 'INCONCLUSIVE', 'source probe claim is dirty, unavailable, or inconsistent with claimed HEAD; source identity is not independently authenticated'
    db = database.get('payload')
    if isinstance(db, dict) and (db.get('status') == 'FAIL' or
                                 type(db.get('database_connections_attempted')) is int
                                 and db['database_connections_attempted'] > 0):
        db_status, db_reason = 'FAIL', 'database probe reports failure or an attempted connection; actual connections are not independently observed'
    elif (isinstance(db, dict) and db.get('status') == 'BLOCKED'
            and type(db.get('database_connections_attempted')) is int
            and db['database_connections_attempted'] == 0 and database.get('exit_code') == 20):
        db_status, db_reason = 'BLOCKED', 'database probe reports BLOCKED and zero attempts; actual connections are not independently observed'
    else:
        db_status, db_reason = 'INCONCLUSIVE', 'database probe did not provide a consistent blocked/zero self-report; actual connections are not independently observed'
    return [
        {'id': 'DIRTY_SOURCE', 'baseline_ids': ['FF-A01-001', 'FF-REL-0002'],
         'status': status, 'reason': reason, 'source_sha': head,
         'scope': 'Subprocess source_sha and clean state are unverified claims; source identity, source-to-binary and Gate binding remain unverified'},
        {'id': 'DATABASE_PROBE', 'baseline_ids': ['FF-A01-002', 'FF-REL-0001'],
         'status': db_status, 'reason': db_reason},
        {'id': 'NATIVE_EXECUTORS', 'baseline_ids': ['FF-A01-003', 'FF-REL-0003'],
         'status': 'NOT_RUN', 'reason': 'real DSH/Claude qualification belongs to Phase 5'},
        {'id': 'BROWSER_E2E', 'status': 'NOT_RUN', 'reason': 'offline probes do not run a browser journey'},
    ]

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root, requested_output = args.source_root.resolve(), args.output.expanduser().absolute()
    if os.path.lexists(requested_output):
        parser.error('evidence is immutable; choose a new output path')
    output = requested_output.resolve()
    if output == root or root in output.parents:
        parser.error('evidence output must be outside the source root')
    if os.path.lexists(output):
        parser.error('evidence is immutable; choose a new output path')
    try:
        head = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=root, capture_output=True,
                              text=True, timeout=30, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        head = None
    probes = [run(['ops/ecp/verify', 'doctor'], root),
              run(['ops/ecp/verify', '--suite', 'ECP-P0-02', '--profile', 'isolated'], root)]
    observed = findings(*probes, head, root)
    report = {'schema_version': 'forgeflow.ecp-baseline-findings.v1', 'product_gate_effect': 'NONE',
              'status': 'FAIL' if any(item['status'] == 'FAIL' for item in observed) else 'BLOCKED',
              'source_root': str(root), 'source_sha': head,
              'scope': 'Subprocess-reported observations only; source_sha is an unverified git subprocess claim; database connection counts are self-reported, not independently observed; FAIL records reported failure',
              'findings': observed, 'probes': probes}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps(report, ensure_ascii=False))
    return 10 if report['status'] == 'FAIL' else 20

if __name__ == '__main__':
    raise SystemExit(main())
