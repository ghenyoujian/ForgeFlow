#!/usr/bin/env python3
"""Read-only carrier for a Store-approved retained Native candidate.

This command checks pinned provenance and actual Git bytes. Its ordinary stdout
is execution evidence, not a DSH event or independent business acceptance. The
API owns source custody validation, fresh verification and main integration.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time
import uuid


PROOF_LIMIT = 8 * 1024 * 1024
GIT_LIMIT = 16 * 1024 * 1024
STDIN_LIMIT = 64 * 1024 * 1024
OUTPUT_LIMIT = 4096
GIT_PROGRAM = '/usr/bin/git'
HEX64 = re.compile(r'^[0-9a-f]{64}$')
GIT_OID = re.compile(r'^(?:[0-9a-f]{40}|[0-9a-f]{64})$')
IDENTITY = re.compile(r'^[A-Za-z0-9_.:-]{1,160}$')
CURRENT_STAGE = 'INITIALIZATION'
EXCEPTION_CLASSES = frozenset({
    'CarrierError', 'OSError', 'PermissionError', 'FileNotFoundError',
    'NotADirectoryError', 'IsADirectoryError', 'BlockingIOError', 'TimeoutError',
    'UnicodeError', 'UnicodeDecodeError', 'UnicodeEncodeError', 'ValueError',
    'TypeError', 'JSONDecodeError', 'KeyError', 'IndexError', 'RecursionError',
    'SubprocessError', 'TimeoutExpired', 'CalledProcessError',
})


class CarrierError(Exception):
    """Only a fixed error code crosses the stdout boundary."""


def set_stage(value):
    # Every caller supplies a code literal, never an input path or document value.
    global CURRENT_STAGE
    CURRENT_STAGE = value


def require(condition, code):
    if not condition:
        raise CarrierError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical_path(value, directory=False, phase='INPUT'):
    set_stage(phase + '_PATH_PARSE')
    path = Path(value)
    require(path.is_absolute() and '..' not in path.parts, 'PATH_INVALID')
    set_stage(phase + '_PATH_RESOLVE')
    require(path.resolve(strict=True) == path, 'PATH_ALIAS_FORBIDDEN')
    set_stage(phase + '_PATH_METADATA')
    metadata = path.lstat()
    require(stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode),
            'PATH_TYPE_INVALID')
    return path


def read_leaf(path, limit, private=False, phase='INPUT'):
    path = canonical_path(path, phase=phase)
    set_stage(phase + '_FILE_OPEN')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        set_stage(phase + '_FILE_METADATA')
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
                'INPUT_NOT_SINGLE_REGULAR_FILE')
        if private:
            require(metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o600,
                    'PROVENANCE_PERMISSION_INVALID')
        require(0 < metadata.st_size <= limit, 'INPUT_BYTE_BUDGET_EXCEEDED')
        set_stage(phase + '_FILE_READ')
        raw = stream.read(limit + 1)
        require(len(raw) == metadata.st_size and len(raw) <= limit, 'INPUT_CHANGED_DURING_READ')
        return raw


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'PROVENANCE_DUPLICATE_KEY')
        result[key] = value
    return result


def reject_constant(_value):
    raise CarrierError('PROVENANCE_NONFINITE_NUMBER')


def read_provenance(path, expected_sha):
    set_stage('PROVENANCE_SHA_FORMAT')
    require(HEX64.fullmatch(expected_sha), 'PROVENANCE_SHA_INVALID')
    raw = read_leaf(path, PROOF_LIMIT, private=True, phase='PROVENANCE')
    set_stage('PROVENANCE_PIN_COMPARE')
    require(sha(raw) == expected_sha, 'PROVENANCE_PIN_CHANGED')
    set_stage('PROVENANCE_JSON_DECODE')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object,
                       parse_constant=reject_constant)
    require(isinstance(value, dict), 'PROVENANCE_OBJECT_REQUIRED')
    return value


def positive_integer(value):
    return type(value) is int and value > 0


def relative_path(value):
    if not isinstance(value, str) or not value or '\\' in value or '\0' in value:
        return False
    try:
        value.encode('utf-8', errors='strict')
    except UnicodeError:
        return False
    return all(part not in ('', '.', '..') for part in value.split('/'))


def scope_rule(value):
    return isinstance(value, str) and relative_path(value[:-1] if value.endswith('/') else value)


def permits(path, rules):
    return relative_path(path) and any(
        path.startswith(rule) if rule.endswith('/') else path == rule for rule in rules)


def git(worktree, arguments):
    """Run a fixed local Git reader with bounded pipes and optional locks off."""
    command = [GIT_PROGRAM, '--no-pager', '-C', str(worktree),
               '--git-dir', str(worktree / '.git'), '--work-tree', str(worktree),
               '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
               '-c', 'core.fsmonitor=false', '-c', 'core.filemode=true',
               '-c', 'core.ignorecase=false', '-c', 'credential.helper=',
               '-c', 'protocol.allow=never', '-c', 'gc.auto=0',
               '-c', 'maintenance.auto=false']
    if arguments[0] == 'diff':
        command += ['diff', '--no-ext-diff', '--no-textconv', *arguments[1:]]
    else:
        command += arguments
    environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/nonexistent',
                   'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_NOSYSTEM': '1',
                   'GIT_CONFIG_COUNT': '0', 'GIT_TERMINAL_PROMPT': '0',
                   'GIT_LITERAL_PATHSPECS': '1', 'GIT_NO_LAZY_FETCH': '1',
                   'GIT_OPTIONAL_LOCKS': '0'}
    set_stage('GIT_PROCESS_OPEN')
    # DEVNULL opens its character device O_RDWR in Python. The read-only carrier
    # has no such write grant; an immediately closed anonymous pipe supplies the
    # same real EOF without requesting a filesystem write permission.
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=environment, cwd=worktree)
    set_stage('GIT_STDIN_EOF')
    process.stdin.close()
    set_stage('GIT_PIPE_REGISTRATION')
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
    selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
    output = bytearray()
    total = 0
    deadline = time.monotonic() + 30
    try:
        set_stage('GIT_PIPE_READ')
        while selector.get_map():
            require(time.monotonic() < deadline, 'GIT_READ_TIMEOUT')
            for key, _events in selector.select(timeout=min(1, max(0, deadline-time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                total += len(chunk)
                require(total <= GIT_LIMIT, 'GIT_READ_BYTE_BUDGET_EXCEEDED')
                if key.data == 'stdout':
                    output.extend(chunk)
        set_stage('GIT_PROCESS_WAIT')
        require(process.wait(timeout=max(0.01, deadline-time.monotonic())) == 0, 'GIT_READ_FAILED')
        return bytes(output)
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
        process.stderr.close()


def text_git(worktree, arguments):
    raw = git(worktree, arguments)
    set_stage('GIT_TEXT_DECODE')
    return raw.decode('utf-8', errors='strict').strip()


def git_changes(raw):
    set_stage('GIT_DIFF_RECORD_DECODE')
    fields = [field.decode('utf-8', errors='strict') for field in raw.split(b'\0') if field]
    changes = []
    index = 0
    while index < len(fields):
        require(index + 1 < len(fields), 'GIT_DIFF_RECORD_INVALID')
        status, first = fields[index:index + 2]
        index += 2
        old_path = None
        if status.startswith(('R', 'C')):
            require(index < len(fields), 'GIT_DIFF_RECORD_INVALID')
            old_path, path = first, fields[index]
            index += 1
        else:
            path = first
        # Field order matches the Rust FileChange struct in the audit hash tuple.
        changes.append({'layer': 'committed', 'status': status, 'path': path, 'old_path': old_path})
    return changes


def check_source(proof, arguments):
    set_stage('SOURCE_IDENTITY_COMPARE')
    require(proof.get('schema_version') == 'forgeflow.retained-native-candidate-source.v1',
            'PROVENANCE_SCHEMA_INVALID')
    require(proof.get('project_id') == arguments.expected_project_id and
            proof.get('attempt_id') == arguments.expected_source_attempt_id,
            'SOURCE_IDENTITY_CHANGED')
    require(IDENTITY.fullmatch(arguments.expected_project_id), 'PROJECT_IDENTITY_INVALID')
    require(str(uuid.UUID(arguments.expected_source_attempt_id)) == arguments.expected_source_attempt_id,
            'SOURCE_ATTEMPT_IDENTITY_INVALID')
    require(isinstance(proof.get('task_id'), str) and IDENTITY.fullmatch(proof['task_id']) and
            positive_integer(proof.get('task_revision')) and positive_integer(proof.get('generation')),
            'SOURCE_TASK_IDENTITY_INVALID')
    for key in ('input_digest', 'execution_bindings_sha256', 'model_settlement_sha256',
                'physical_stop_proof_sha256'):
        require(isinstance(proof.get(key), str) and HEX64.fullmatch(proof[key]),
                'SOURCE_BINDING_DIGEST_INVALID')
    set_stage('SOURCE_MODEL_AND_ROLE_SHAPE')
    models = proof.get('model_request_ids')
    require(isinstance(models, list) and 0 < len(models) <= 10000 and
            all(isinstance(value, str) and IDENTITY.fullmatch(value) for value in models) and
            len(set(models)) == len(models), 'SOURCE_MODEL_IDENTITIES_INVALID')
    require(isinstance(proof.get('native_root_binding'), dict), 'SOURCE_NATIVE_ROLE_BINDING_MISSING')
    set_stage('SOURCE_CANDIDATE_SHAPE')
    candidate = proof.get('candidate')
    require(isinstance(candidate, dict), 'SOURCE_CANDIDATE_MISSING')
    base, head = candidate.get('base_sha'), candidate.get('candidate_sha')
    require(isinstance(base, str) and GIT_OID.fullmatch(base) and
            isinstance(head, str) and GIT_OID.fullmatch(head) and
            head == arguments.expected_source_candidate_sha and proof.get('base_sha') == base,
            'SOURCE_COMMIT_IDENTITY_CHANGED')
    require(isinstance(candidate.get('source_hash'), str) and GIT_OID.fullmatch(candidate['source_hash'])
            and isinstance(candidate.get('diff_manifest_hash'), str) and
            HEX64.fullmatch(candidate['diff_manifest_hash']), 'CANDIDATE_DIGEST_INVALID')
    manifest = candidate.get('manifest')
    require(isinstance(manifest, dict) and manifest.get('base_sha') == base and
            manifest.get('head_sha') == head and
            manifest.get('hash') == candidate['diff_manifest_hash'] and
            manifest.get('untracked') == [], 'FROZEN_MANIFEST_INVALID')
    set_stage('SOURCE_SCOPE_SHAPE')
    owner_paths, write_set = proof.get('owner_paths'), proof.get('write_set')
    require(all(isinstance(rules, list) and 0 < len(rules) <= 10000 and
                all(scope_rule(rule) for rule in rules) for rules in (owner_paths, write_set)),
            'SOURCE_WRITE_SCOPE_INVALID')
    worktree = canonical_path(arguments.source_worktree, directory=True, phase='SOURCE_WORKTREE')
    private_git = canonical_path(worktree / '.git', directory=True, phase='SOURCE_PRIVATE_GIT')
    set_stage('SOURCE_PRIVATE_GIT_STORAGE_CHECK')
    require(not (private_git / 'commondir').exists() and
            not (private_git / 'objects/info/alternates').exists(), 'SHARED_GIT_STORAGE_FORBIDDEN')
    require(text_git(worktree, ['rev-parse', '--verify', '--end-of-options', 'HEAD^{commit}']) == head and
            text_git(worktree, ['rev-parse', '--verify', '--end-of-options', base + '^{commit}']) == base,
            'ACTUAL_COMMIT_CHANGED')
    tree = text_git(worktree, ['rev-parse', '--verify', '--end-of-options', head + '^{tree}'])
    require(tree == candidate['source_hash'], 'ACTUAL_SOURCE_TREE_CHANGED')
    git(worktree, ['merge-base', '--is-ancestor', base, head])
    changes = git_changes(git(worktree, ['diff', '--name-status', '-z', '-M', base, head, '--']))
    set_stage('SOURCE_DIFF_AND_SCOPE_COMPARE')
    require(changes and changes == manifest.get('changes'), 'ACTUAL_FROZEN_DIFF_CHANGED')
    for change in changes:
        for path in (change['path'], change['old_path']):
            if path is not None:
                require(permits(path, owner_paths) and permits(path, write_set), 'SOURCE_WRITE_SCOPE_VIOLATION')
    require(not git(worktree, ['diff', '--cached', '--name-status', '-z', '-M', '--']) and
            not git(worktree, ['diff', '--name-status', '-z', '-M', '--']) and
            not git(worktree, ['ls-files', '--others', '-z']), 'SOURCE_WORKTREE_NOT_FROZEN')
    patch = git(worktree, ['diff', '--binary', base, head, '--']).decode('utf-8', errors='replace')
    set_stage('SOURCE_PATCH_AND_AUDIT_DIGEST_COMPARE')
    require(patch == manifest.get('patch'), 'ACTUAL_FROZEN_PATCH_CHANGED')
    tuple_bytes = json.dumps([base, head, changes, patch, []], ensure_ascii=False,
                            separators=(',', ':'), allow_nan=False).encode('utf-8')
    require(sha(tuple_bytes) == candidate['diff_manifest_hash'], 'ACTUAL_AUDIT_DIGEST_CHANGED')
    return {'schema_version': 'forgeflow.retained-candidate-carrier.v1',
            'check': 'PINNED_SOURCE_AND_READONLY_GIT_MATCH',
            'project_id': proof['project_id'], 'source_attempt_id': proof['attempt_id'],
            'source_task_id': proof['task_id'], 'source_task_revision': proof['task_revision'],
            'source_generation': proof['generation'], 'source_base_sha': base,
            'source_candidate_sha': head, 'source_tree_oid': tree,
            'source_diff_manifest_sha256': candidate['diff_manifest_hash'],
            'source_provenance_sha256': arguments.source_provenance_sha256,
            'changed_path_count': len(changes), 'source_model_request_count': len(models),
            'source_model_settlement_sha256': proof['model_settlement_sha256'],
            'source_physical_stop_proof_sha256': proof['physical_stop_proof_sha256'],
            'stop_proof_check': 'TYPED_SOURCE_PROVENANCE_BINDING',
            'carrier_kind': 'CONTROLLED_LIGHTWEIGHT', 'carrier_model_calls': 0,
            'carrier_business_suite_calls': 0, 'carrier_source_writes': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-provenance', required=True)
    parser.add_argument('--source-provenance-sha256', required=True)
    parser.add_argument('--source-worktree', required=True)
    parser.add_argument('--expected-project-id', required=True)
    parser.add_argument('--expected-source-attempt-id', required=True)
    parser.add_argument('--expected-source-candidate-sha', required=True)
    parser.add_argument('--carrier-sha256')
    arguments = parser.parse_args()
    try:
        # The supervisor always supplies the real bounded prompt on stdin. Drain
        # it without logging or retaining bytes so quick exit cannot break its writer.
        received = 0
        input_hash = hashlib.sha256()
        set_stage('STDIN_DRAIN')
        while True:
            chunk = sys.stdin.buffer.read(65536)
            if not chunk:
                break
            received += len(chunk)
            require(received <= STDIN_LIMIT, 'STDIN_BYTE_BUDGET_EXCEEDED')
            input_hash.update(chunk)
        if arguments.carrier_sha256 is not None:
            set_stage('CARRIER_SHA_FORMAT')
            require(HEX64.fullmatch(arguments.carrier_sha256), 'CARRIER_SHA_INVALID')
            raw_carrier = read_leaf(Path(__file__).absolute(), 65536, phase='CARRIER')
            set_stage('CARRIER_PIN_COMPARE')
            require(sha(raw_carrier) == arguments.carrier_sha256,
                    'CARRIER_PIN_CHANGED')
        proof = read_provenance(arguments.source_provenance, arguments.source_provenance_sha256)
        result = check_source(proof, arguments)
        set_stage('RESULT_JSON_ENCODE')
        result['stdin_bytes'] = received
        result['stdin_sha256'] = input_hash.hexdigest()
        raw = json.dumps(result, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
        require(len(raw) + 1 <= OUTPUT_LIMIT, 'RESULT_BYTE_BUDGET_EXCEEDED')
        set_stage('RESULT_STDOUT_WRITE')
        sys.stdout.buffer.write(raw + b'\n')
        sys.stdout.buffer.flush()
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, CarrierError) else 'SOURCE_CHECK_FAILED'
        exception_class = type(error).__name__
        if exception_class not in EXCEPTION_CLASSES:
            exception_class = 'Exception'
        error_number = getattr(error, 'errno', None)
        if type(error_number) is not int or not 0 <= error_number <= 4095:
            error_number = None
        print(json.dumps({'schema_version': 'forgeflow.retained-candidate-carrier.v1',
                          'check': 'FAILED', 'error_code': code, 'stage': CURRENT_STAGE,
                          'exception_class': exception_class, 'errno': error_number},
                         separators=(',', ':')), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
