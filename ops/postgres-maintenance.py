#!/usr/bin/env python3
"""Archive explicitly evidenced, idle test databases; never prune the business ledger.

The default command is audit. Apply requires the exact plan SHA. Every database
is dumped with --create, fully decoded, hashed and fsynced before ordinary DROP
(never FORCE). A durable journal allows interrupted admission changes to recover.
Restore instructions are emitted by `restore --journal FILE`; restoration is an
explicit command to the ORIGINAL database name, which must not already exist.
Requires psycopg 3 and the same PostgreSQL major-version client as the server.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import uuid

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row

REPO = Path(__file__).resolve().parents[1]
STATE = Path.home() / '.local/state/forgeflow'
RUNTIME = STATE / 'control/runtime-env.json'
ARCHIVE = STATE / 'postgres-archive'
PGROOT = Path.home() / '.cache/forgeflow-postgres/root'
BIN = PGROOT / 'usr/lib/postgresql/16/bin'
SCHEMA = 'forgeflow.postgres.archive-plan.v1'
PROTECTED = {'forgeflow', 'postgres', 'template0', 'template1'}
UNREADABLE_MANAGERS = set()


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def durable(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as out:
        json.dump(value, out, ensure_ascii=False, sort_keys=True, indent=2)
        out.write('\n')
        out.flush()
        os.fsync(out.fileno())
    os.replace(tmp, path)
    sync_dir(path.parent)


def private_json(path):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise ValueError('Private file ownership/permissions invalid: ' + str(path))
    return json.loads(path.read_bytes())


def connection_params():
    params = conninfo_to_dict(private_json(RUNTIME)['DATABASE_URL'])
    params.update(connect_timeout='10', application_name='forgeflow-postgres-maintenance')
    return params


def connect(params, name='postgres'):
    return psycopg.connect(**dict(params, dbname=name), autocommit=True, row_factory=dict_row)


def cluster_identity(admin):
    return dict(admin.execute("SELECT system_identifier::text FROM pg_control_system()").fetchone(),
                version=admin.info.server_version)


def inventory(admin):
    return {r['datname']: r for r in admin.execute("""
        SELECT d.oid::bigint, d.datname, d.datallowconn, d.datistemplate,
               d.datconnlimit, pg_get_userbyid(d.datdba) AS owner,
               pg_encoding_to_char(d.encoding) AS encoding, d.datcollate, d.datctype,
               d.datlocprovider, d.daticulocale, d.daticurules, d.datcollversion,
               t.spcname AS tablespace, d.datacl::text AS acl,
               shobj_description(d.oid,'pg_database') AS comment,
               pg_database_size(d.oid) AS bytes,
               COALESCE((SELECT jsonb_agg(jsonb_build_object(
                 'role', CASE WHEN s.setrole=0 THEN NULL ELSE pg_get_userbyid(s.setrole) END,
                 'settings',s.setconfig) ORDER BY s.setrole)
                 FROM pg_db_role_setting s WHERE s.setdatabase=d.oid),'[]'::jsonb) AS settings
        FROM pg_database d JOIN pg_tablespace t ON t.oid=d.dattablespace ORDER BY d.datname
    """).fetchall()}


def state(admin, name, ignore_pids=()):
    rows = admin.execute('SELECT pid FROM pg_stat_activity WHERE datname=%s', (name,)).fetchall()
    return {'connections': sorted(r['pid'] for r in rows if r['pid'] not in ignore_pids),
            'prepared': admin.execute('SELECT count(*) AS n FROM pg_prepared_xacts WHERE database=%s', (name,)).fetchone()['n'],
            'slots': admin.execute('SELECT count(*) AS n FROM pg_replication_slots WHERE database=%s', (name,)).fetchone()['n']}


def references(names, ignore_pids=()):
    """Only return matching database names and origins, never secret process text."""
    hits = {name: [] for name in names}
    pattern = re.compile(r'(?<![A-Za-z0-9_])(' + '|'.join(re.escape(x) for x in names) + r')(?![A-Za-z0-9_])') if names else None
    def consume(raw, origin):
        if pattern:
            for match in set(pattern.findall(raw)):
                hits[match].append(origin)
    # The coordinator's own argv contains plan paths, not credentials; its runtime
    # DATABASE_URL is intentionally protected as well.
    own_ancestors = {os.getpid()}
    ancestor = os.getppid()
    while ancestor > 1:
        try:
            record = Path(f'/proc/{ancestor}/stat').read_text().rsplit(')', 1)[1].split()
            own_ancestors.add(ancestor); ancestor = int(record[1])
        except (OSError, ValueError):
            break
    manager_environment = None
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit() or int(proc.name) in ignore_pids:
            continue
        try:
            if proc.stat().st_uid != os.getuid():
                continue
            command = (proc/'cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace').strip()
            if int(proc.name) in own_ancestors and (int(proc.name)==os.getpid() or 'postgres-maintenance.py' in command):
                continue
            for member in ('cmdline', 'environ'):
                try:
                    consume((proc / member).read_bytes().replace(b'\0', b' ').decode(errors='replace'), f'process:{proc.name}:{member}')
                except FileNotFoundError:
                    pass  # Process exited during the scan.
                except PermissionError:
                    if command not in {'/usr/lib/systemd/systemd --user', '/lib/systemd/systemd --user', '(sd-pam)'}:
                        raise ValueError('Cannot inspect live process: ' + proc.name)
                    UNREADABLE_MANAGERS.add(proc.name + ':' + member)
                    if manager_environment is None:
                        manager_environment = subprocess.check_output(['systemctl', '--user', 'show-environment'], text=True, timeout=10)
                    consume(manager_environment, 'systemd-user-manager-environment')
        except FileNotFoundError:
            pass
    paths = {RUNTIME}
    for root in (Path.home()/'.config/systemd/user', Path('/etc/systemd/system'), Path('/etc/systemd/user')):
        if root.exists():
            paths.update(p for p in root.rglob('*') if p.is_file() and (p.suffix in {'.service', '.conf'}))
    # Include EnvironmentFile and literal local JSON/env/script references from
    # installed units, including stopped services and their drop-ins.
    for path in list(paths):
        raw = path.read_text(errors='replace')
        consume(raw, 'configuration:' + str(path))
        if path != RUNTIME:
            for value in re.findall(r'(?<!\w)(/[A-Za-z0-9_./~@%+-]+)', raw):
                ref = Path(value)
                if ref.is_file() and ref.suffix in {'.json', '.env', '.sh', '.py', '.conf'}:
                    paths.add(ref)
    for path in paths:
        consume(path.read_text(errors='replace'), 'configuration:' + str(path))
    return {k: sorted(set(v)) for k, v in hits.items()}


def evidence(names, roots):
    """One bounded rg pass; exact DB tokens plus a creator source are required."""
    found = {name: [] for name in names}
    pattern = re.compile(r'(?<![A-Za-z0-9_])(' + '|'.join(re.escape(x) for x in names) + r')(?![A-Za-z0-9_])')
    with tempfile.NamedTemporaryFile(mode='w', prefix='forgeflow-db-names-') as patterns:
        patterns.write('\n'.join(names)); patterns.flush()
        cmd = ['rg', '--json', '--no-messages', '--max-filesize', '16M', '--threads', '4',
               '-F', '-f', patterns.name, '-g', '*.json', '-g', '*.log', '-g', '*.txt',
               '-g', '!node_modules/**', '-g', '!target/**', '-g', '!postgres-archive/**',
               *[str(p) for p in roots if p.exists()]]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        try:
            for line in proc.stdout:
                item = json.loads(line)
                if item['type'] != 'match':
                    continue
                data = item['data']; filename = data['path'].get('text')
                if not filename:
                    continue
                for name in set(pattern.findall(data['lines'].get('text', ''))):
                    if len(found[name]) < 2 and filename not in {v['path'] for v in found[name]}:
                        path = Path(filename).resolve()
                        found[name].append({'path': str(path), 'sha256': sha(path), 'line': data['line_number']})
                if all(found.values()):
                    proc.terminate()
                    break
            code = proc.wait()
            if code not in (0, 1, -signal.SIGTERM):
                raise RuntimeError('Evidence search failed; no deletion plan issued')
        finally:
            if proc.poll() is None:
                proc.terminate(); proc.wait()
    return found


def creators(hint):
    result = []
    for match in re.finditer(r'([A-Za-z0-9_./-]+\.py):\d+', hint):
        path = (REPO / match.group(1)).resolve()
        if path.is_relative_to(REPO) and path.is_file() and 'CREATE DATABASE' in path.read_text():
            result.append({'path': str(path), 'sha256': sha(path)})
    return result


def audit(args):
    source = json.loads(args.candidates.read_bytes())
    entries = source['databases']
    names = sorted({entry['datname'] for entry in entries})
    refs = references(names)
    receipts = evidence(names, args.evidence_root or [REPO/'evidence', REPO/'verification/evidence', REPO/'benchmarks/evidence'])
    params = connection_params()
    protected = PROTECTED | {params['dbname']}
    with connect(params) as admin:
        databases = inventory(admin); identity = cluster_identity(admin)
        plan_entries = []
        for entry in entries:
            name = entry['datname']; meta = databases.get(name); reasons = []
            source_files = creators(entry.get('creation_source', ''))
            current = state(admin, name)
            if name in protected or (meta and meta['datistemplate']): reasons.append('PROTECTED')
            if not meta: reasons.append('DATABASE_ABSENT')
            if meta and not meta['datallowconn']: reasons.append('CONNECTIONS_ALREADY_DISABLED')
            if any(current.values()): reasons.append('LIVE_CONNECTION_PREPARED_TRANSACTION_OR_SLOT')
            if refs[name]: reasons.append('PROCESS_OR_INSTALLED_CONFIGURATION_REFERENCE')
            if not receipts[name] or not source_files: reasons.append('UNPROVEN_TEST_DATABASE_PROVENANCE')
            plan_entries.append({'name': name, 'metadata': meta, 'state': current, 'references': refs[name],
                                 'creation_source': entry.get('creation_source'), 'creator_files': source_files,
                                 'receipts': receipts[name], 'keep_reasons': reasons,
                                 'action': 'KEEP' if reasons else 'ARCHIVE_AND_RETIRE'})
    plan = {'schema_version': SCHEMA, 'created_at': now(), 'cluster': identity,
            'candidate_source': {'path': str(args.candidates.resolve()), 'sha256': sha(args.candidates)},
            'archive_root': str(ARCHIVE), 'protected': sorted(protected), 'entries': plan_entries,
            'unreadable_system_managers': sorted(UNREADABLE_MANAGERS),
            'manager_fallback': 'systemctl --user show-environment plus installed unit/drop-in files',
            'policy': 'Full compressed dump and durable recovery journal; original receipts and canonical database unchanged.'}
    durable(args.output, plan)
    print(json.dumps({'plan': str(args.output), 'sha256': sha(args.output),
                      'archive_candidates': sum(x['action']=='ARCHIVE_AND_RETIRE' for x in plan_entries),
                      'kept': sum(x['action']=='KEEP' for x in plan_entries)}))


def client_env(params, database):
    # Secrets stay in child environment rather than argv or command receipts.
    env = dict(os.environ)
    for key in list(env):
        if key.startswith('PG'): del env[key]
    mapping = {'host': 'PGHOST', 'hostaddr': 'PGHOSTADDR', 'port': 'PGPORT', 'user': 'PGUSER',
               'password': 'PGPASSWORD', 'sslmode': 'PGSSLMODE', 'sslrootcert': 'PGSSLROOTCERT',
               'sslcert': 'PGSSLCERT', 'sslkey': 'PGSSLKEY', 'passfile': 'PGPASSFILE'}
    for key, target in mapping.items():
        if key in params: env[target] = str(params[key])
    env.update(PGDATABASE=database, PGCONNECT_TIMEOUT='10', PGAPPNAME='forgeflow-postgres-archive-dump',
               LD_LIBRARY_PATH=str(PGROOT/'usr/lib/x86_64-linux-gnu') + ':' + os.environ.get('LD_LIBRARY_PATH', ''))
    return env


def verify_dump(journal, params):
    archive = Path(journal['dump'])
    if not archive.is_file() or sha(archive) != journal['dump_sha256']:
        raise ValueError('Dump missing or SHA mismatch')
    subprocess.run([str(BIN/'pg_restore'), '--create', '--file=/dev/null', str(archive)],
                   env=client_env(params, 'postgres'), check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE, timeout=600)


def check_entry(admin, entry, params, ignore_pids=(), allow_disabled=False):
    name = entry['name']; meta = inventory(admin).get(name)
    if name in PROTECTED | {params['dbname']} or not meta or meta['datistemplate']:
        raise ValueError('Database protected or missing: ' + name)
    if meta['oid'] != entry['metadata']['oid']:
        raise ValueError('Database OID changed: ' + name)
    # Size is expected to vary with PostgreSQL maintenance; all restore metadata
    # and identity fields must stay exactly as reviewed.
    for key in entry['metadata']:
        if key not in {'bytes', 'datallowconn'} and meta[key] != entry['metadata'][key]:
            raise ValueError('Database metadata changed: ' + name + ':' + key)
    if not meta['datallowconn'] and not allow_disabled:
        raise ValueError('Database admission unexpectedly disabled: ' + name)
    if any(state(admin, name, ignore_pids).values()):
        raise ValueError('Database became active: ' + name)
    if references([name], ignore_pids)[name]:
        raise ValueError('Database acquired live/configuration reference: ' + name)
    return meta


def verify_provenance(entry):
    if not entry['creator_files'] or not entry['receipts']:
        raise ValueError('Missing provenance')
    for item in entry['creator_files'] + entry['receipts']:
        if sha(item['path']) != item['sha256']:
            raise ValueError('Provenance changed: ' + item['path'])
    if not any(re.search(r'(?<![A-Za-z0-9_])' + re.escape(entry['name']) + r'(?![A-Za-z0-9_])', Path(x['path']).read_text(errors='replace')) for x in entry['receipts']):
        raise ValueError('Receipt does not contain exact database identity')


def archive_one(admin, params, entry, plan_sha):
    name = entry['name']
    if not re.fullmatch(r'[A-Za-z0-9_]+', name):
        raise ValueError('Unsupported database identifier')
    folder = ARCHIVE / (name + '-' + str(entry['metadata']['oid']))
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    sync_dir(folder.parent)
    path = folder/'journal.json'
    journal = private_json(path) if path.exists() else None
    existing = inventory(admin).get(name)
    if journal:
        if journal['plan_sha256'] != plan_sha or journal['metadata']['oid'] != entry['metadata']['oid']:
            raise ValueError('Journal identity mismatch')
        if journal['phase'] == 'RETIRED' or (not existing and journal['phase'] in {'ADMISSION_CLOSED', 'DROP_PENDING'}):
            if existing: raise ValueError('A retired database name was recreated; refusing to touch it')
            verify_dump(journal, params)
            journal.update(phase='RETIRED', completed_at=now()); durable(path, journal)
            return journal
        if existing and not existing['datallowconn']:
            if journal['phase'] not in {'ADMISSION_CLOSING', 'ADMISSION_CLOSED', 'DROP_PENDING'}:
                raise ValueError('Unowned disabled database admission')
            if existing['oid'] != entry['metadata']['oid']:
                raise ValueError('Journal database OID changed')
            # A preexisting backend might have outlived a crashed lock holder.
            # Reopen only our own admission change, then take a fresh frozen dump;
            # never infer that the previous archive remained current after a crash.
            admin.execute(sql.SQL('ALTER DATABASE {} ALLOW_CONNECTIONS true').format(sql.Identifier(name)))
            journal.update(phase='ADMISSION_RECOVERED', recovered_at=now()); durable(path, journal)
        durable(folder / ('journal-history-' + uuid.uuid4().hex + '.json'), journal)
    verify_provenance(entry)
    check_entry(admin, entry, params)
    journal = {'schema_version': 'forgeflow.postgres.archive-journal.v1', 'plan_sha256': plan_sha,
               'database': name, 'metadata': entry['metadata'], 'provenance': entry['receipts'],
               'started_at': now(), 'phase': 'LOCKING'}
    durable(path, journal)
    guard = None; admission_closed = False
    try:
        guard = connect(params, name)
        guard.execute('BEGIN')
        guard.execute("SET LOCAL lock_timeout='3s'")
        guard.execute("SET LOCAL statement_timeout='60s'")
        pid = guard.info.backend_pid
        check_entry(admin, entry, params, [pid])
        # Lock local catalogs first so creating a table after table enumeration
        # cannot evade the freeze. Never lock shared catalogs of other databases.
        guard.execute('LOCK TABLE pg_catalog.pg_class, pg_catalog.pg_namespace IN SHARE MODE')
        special = guard.execute("""SELECT count(*) AS n FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE c.relkind IN ('S','f') AND n.nspname NOT LIKE 'pg_temp_%'""").fetchone()['n']
        if special:
            raise ValueError('Sequence/foreign-table database requires separate archival procedure: ' + name)
        relations = guard.execute("""SELECT n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE c.relkind IN ('r','p','m') AND NOT c.relisshared AND n.nspname NOT LIKE 'pg_temp_%'
             ORDER BY c.oid""").fetchall()
        if relations:
            guard.execute(sql.SQL('LOCK TABLE {} IN SHARE MODE').format(sql.SQL(',').join(
                sql.Identifier(r['nspname'], r['relname']) for r in relations)))
        check_entry(admin, entry, params, [pid])
        dump = folder / ('database-' + uuid.uuid4().hex + '.dump')
        journal.update(phase='DUMPING', dump=str(dump), held_share_locks=len(relations))
        durable(path, journal)
        with os.fdopen(os.open(dump, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as out:
            subprocess.run([str(BIN/'pg_dump'), '--format=custom', '--compress=6', '--create', '--no-password', '--lock-wait-timeout=5s'],
                           env=client_env(params, name), check=True, stdout=out, stderr=subprocess.PIPE, timeout=600)
            out.flush(); os.fsync(out.fileno())
        sync_dir(folder)
        journal.update(dump_sha256=sha(dump), dump_bytes=dump.stat().st_size, phase='VERIFYING')
        durable(path, journal)
        verify_dump(journal, params)
        if guard.info.transaction_status != psycopg.pq.TransactionStatus.INTRANS:
            raise ValueError('Source freeze transaction was lost; archive cannot justify retirement')
        guard.execute('SELECT 1')  # Confirms the same lock-holding session survived the dump.
        check_entry(admin, entry, params, [pid])
        journal.update(phase='ADMISSION_CLOSING', verified_at=now()); durable(path, journal)
        admin.execute(sql.SQL('ALTER DATABASE {} ALLOW_CONNECTIONS false').format(sql.Identifier(name)))
        admission_closed = True
        check_entry(admin, entry, params, [pid], allow_disabled=True)
        guard.execute('SELECT 1')
        journal.update(phase='ADMISSION_CLOSED'); durable(path, journal)
        guard.close(); guard = None  # Releases locks only after new connections are forbidden.
        check_entry(admin, entry, params, allow_disabled=True)
        journal.update(phase='DROP_PENDING'); durable(path, journal)
        admin.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(name)))
        admission_closed = False
        journal.update(phase='RETIRED', completed_at=now()); durable(path, journal)
        return journal
    except BaseException as exc:
        # No forced backend termination. Restore admission only for the exact
        # original OID, never a database recreated under the same name.
        recovery_admin = admin
        if admin.closed or admin.broken:
            recovery_admin = connect(params)
        try:
            current = inventory(recovery_admin).get(name)
            if admission_closed or journal['phase'] in {'ADMISSION_CLOSING', 'ADMISSION_CLOSED', 'DROP_PENDING'}:
                if current and current['oid'] == entry['metadata']['oid'] and not current['datallowconn']:
                    recovery_admin.execute(sql.SQL('ALTER DATABASE {} ALLOW_CONNECTIONS true').format(sql.Identifier(name)))
        finally:
            if recovery_admin is not admin:
                recovery_admin.close()
        # If reconnect/reopening itself fails, the durable admission phase above
        # remains intact, so the next invocation can recover it without guessing.
        phase = 'DROP_PENDING' if not current and journal['phase']=='DROP_PENDING' else 'FAILED'
        journal.update(failed_phase=journal['phase'], phase=phase, failed_at=now(), error_type=type(exc).__name__)
        durable(path, journal)
        raise
    finally:
        if guard is not None:
            guard.close()


def apply(args):
    if sha(args.plan) != args.plan_sha256:
        raise ValueError('Exact plan SHA does not match')
    plan = private_json(args.plan)
    if plan['schema_version'] != SCHEMA or Path(plan['archive_root']) != ARCHIVE:
        raise ValueError('Unsupported plan')
    params = connection_params()
    ARCHIVE.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(ARCHIVE/'.maintenance.lock', 'a') as lock, connect(params) as admin:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if cluster_identity(admin) != plan['cluster']:
            raise ValueError('Cluster identity changed')
        selected = [e for e in plan['entries'] if e['action'] == 'ARCHIVE_AND_RETIRE' and (not args.database or e['name'] in args.database)]
        if args.database and set(args.database) != {e['name'] for e in selected}:
            raise ValueError('Selected database is not an approved archive candidate')
        results = []
        for entry in selected:
            result = archive_one(admin, params, entry, args.plan_sha256)
            results.append({'database': result['database'], 'phase': result['phase'], 'dump_bytes': result['dump_bytes']})
            print(json.dumps(results[-1]), flush=True)
        durable(args.output, {'schema_version': 'forgeflow.postgres.archive-result.v1', 'plan_sha256': args.plan_sha256,
                              'completed_at': now(), 'results': results, 'canonical_database_modified': False})


def restore(args):
    journal = private_json(args.journal)
    params = connection_params()
    verify_dump(journal, params)
    with connect(params) as admin:
        if journal['database'] in inventory(admin):
            raise ValueError('Original database name already exists; restore refuses overwrite')
    # Connection secrets are neither printed nor embedded in a shell command.
    command = [str(BIN/'pg_restore'), '--create', '--exit-on-error', '--dbname=postgres', journal['dump']]
    print(json.dumps({'database': journal['database'], 'dump_sha256': journal['dump_sha256'],
                      'command': shlex.join(command),
                      'connection': 'Use the same private runtime DATABASE_URL connection fields with PGDATABASE=postgres; include the PostgreSQL library path.',
                      'execute': args.execute, 'metadata_journal': str(args.journal)}, ensure_ascii=False))
    if args.execute:
        subprocess.run(command, env=client_env(params, 'postgres'), check=True, timeout=600)
        with connect(params) as admin:
            result = inventory(admin)[journal['database']]
        if any(result[k] != v for k, v in journal['metadata'].items() if k not in {'oid', 'bytes'}):
            raise ValueError('Restore metadata differs; retain the restored database for review')
        print(json.dumps({'status': 'RESTORED', 'database': journal['database'], 'new_oid': result['oid']}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='command')
    audit_parser = subs.add_parser('audit')
    audit_parser.add_argument('--candidates', type=Path, default=Path('/tmp/forgeflow-postgres-storage-audit-20261014.json'))
    audit_parser.add_argument('--output', type=Path, default=ARCHIVE/'plan.json')
    audit_parser.add_argument('--evidence-root', type=Path, action='append')
    apply_parser = subs.add_parser('apply')
    apply_parser.add_argument('--plan', type=Path, required=True)
    apply_parser.add_argument('--plan-sha256', required=True)
    apply_parser.add_argument('--database', action='append', help='Optional reviewed subset; repeatable')
    apply_parser.add_argument('--output', type=Path, default=ARCHIVE/'result.json')
    restore_parser = subs.add_parser('restore')
    restore_parser.add_argument('--journal', type=Path, required=True)
    restore_parser.add_argument('--execute', action='store_true', help='Explicit restore to the absent original database name')
    args = parser.parse_args(sys.argv[1:] or ['audit'])
    def interrupted(signum, frame):
        raise InterruptedError('Maintenance interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    {'audit': audit, 'apply': apply, 'restore': restore}[args.command](args)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # psycopg/subprocess errors can contain connection details; do not print
        # raw child output. The journal records the precise failed phase.
        print(json.dumps({'status': 'FAILED', 'error_type': type(exc).__name__,
                          'reason': str(exc) if isinstance(exc, ValueError) else 'Operation failed; no success claimed.'}), file=sys.stderr)
        sys.exit(1)
