#!/usr/bin/env python3
"""Non-qualifying observer of seven-suite v1 documents and caller-owned FDs.

The caller must already possess the right to read every supplied descriptor and
must provide a trusted, minimally privileged, single-owner/cooperative FD table.
This function does not establish that premise, authenticate any actor, source,
lease, path binding or workload, or issue a Gate. Do not expose it to untrusted
FD numbers in an authority-bearing process. No receipt path is opened.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import os
import re
import stat
import sys

SUITES = tuple(f'ECP-P0-{i:02d}' for i in range(1, 8))
KINDS = ('stdout', 'stderr')
STATUSES = ('PASS', 'FAIL', 'BLOCKED', 'NOT_RUN', 'INCONCLUSIVE', 'SKIPPED')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
SOURCE_ID = re.compile(r'(?:[0-9a-f]{40}|[0-9a-f]{64})\Z')
IDENT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}\Z')
MAX_JSON = 4 * 1024 * 1024
MAX_LOG = 128 * 1024 * 1024
MAX_TOTAL_LOG = 256 * 1024 * 1024
MAX_CASES = 50_000
CHUNK = 64 * 1024


class DocumentError(ValueError):
    pass


class ObservationUnavailable(Exception):
    pass


def _need(value, code='DOCUMENT_FIELDS_INVALID'):
    if not value:
        raise DocumentError(code)


def _exact(value, keys, code='OBJECT_FIELDS_INVALID'):
    _need(isinstance(value, dict) and set(value) == set(keys), code)


def _object(pairs):
    value = {}
    for k, v in pairs:
        _need(k not in value, 'JSON_DUPLICATE_KEY')
        value[k] = v
    return value


def _integer(s):
    _need(len(s.lstrip('-')) <= 128, 'JSON_INTEGER_TOO_LARGE')
    return int(s)


def _float(s):
    _need(len(s) <= 128, 'JSON_FLOAT_TOO_LARGE')
    value = float(s)
    _need(math.isfinite(value), 'JSON_FLOAT_NONFINITE')
    return value


def _json(raw):
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_object,
                          parse_int=_integer, parse_float=_float,
                          parse_constant=lambda _: (_ for _ in ()).throw(DocumentError('JSON_CONSTANT_INVALID')))
    except DocumentError:
        raise
    except (UnicodeError, ValueError, RecursionError, OverflowError) as exc:
        raise DocumentError('JSON_ENCODING_OR_SYNTAX_INVALID') from exc


def _id(value):
    _need(isinstance(value, str) and IDENT.fullmatch(value) is not None, 'IDENTIFIER_INVALID')
    return value


def _suite_map(value):
    _need(isinstance(value, list) and len(value) == len(SUITES), 'SUITE_SET_INVALID')
    result = {}
    for item in value:
        _need(isinstance(item, dict), 'SUITE_OBJECT_INVALID')
        name = item.get('suite_id')
        _need(isinstance(name, str) and name in SUITES and name not in result, 'SUITE_UNKNOWN_OR_DUPLICATE')
        result[name] = item
    _need(set(result) == set(SUITES), 'SUITE_SET_INVALID')
    return result


def _plan(value):
    _exact(value, ('schema_version', 'source_sha', 'suites'))
    _need(value['schema_version'] == 'forgeflow.ecp-g0-review-plan.v1', 'PLAN_SCHEMA_INVALID')
    _need(isinstance(value['source_sha'], str) and SOURCE_ID.fullmatch(value['source_sha']) is not None, 'SOURCE_ID_INVALID')
    suites = _suite_map(value['suites'])
    cases = {}; total = 0
    for sid in SUITES:
        suite = suites[sid]
        _exact(suite, ('suite_id', 'case_ids'))
        ids = suite['case_ids']
        _need(isinstance(ids, list) and ids, 'PLAN_CASES_EMPTY_OR_INVALID')
        total += len(ids)
        if total > MAX_CASES:
            raise ObservationUnavailable('case budget exceeded')
        ids = [_id(x) for x in ids]
        _need(len(set(ids)) == len(ids), 'PLAN_CASE_DUPLICATE')
        cases[sid] = frozenset(ids)
    return cases


def _safe_label(value):
    # v1 labels remain data only; no system call uses these bytes as a path.
    _need(isinstance(value, str) and value and not value.startswith('/') and '\0' not in value, 'PATH_LABEL_INVALID')
    _need(all(part not in ('', '.', '..') for part in value.split('/')), 'PATH_LABEL_INVALID')
    return value


def _receipt(value, plan, case_ids, expected_plan):
    _exact(value, ('schema_version', 'run_id', 'source_sha', 'plan_sha256', 'suites'))
    _need(value['schema_version'] == 'forgeflow.ecp-g0-review-input.v1', 'RECEIPT_SCHEMA_INVALID')
    _id(value['run_id'])
    _need(isinstance(value['source_sha'], str) and SOURCE_ID.fullmatch(value['source_sha']) is not None, 'SOURCE_ID_INVALID')
    _need(value['plan_sha256'] == expected_plan, 'RECEIPT_PLAN_PIN_CLAIM_MISMATCH')
    suites = _suite_map(value['suites']); result = {}; labels = set(); total = 0
    for sid in SUITES:
        suite = suites[sid]
        _exact(suite, ('suite_id', 'cases', 'denominator', 'exit_code', 'logs'))
        cases = suite['cases']; _need(isinstance(cases, list) and cases, 'RECEIPT_CASES_EMPTY_OR_INVALID')
        total += len(cases)
        if total > MAX_CASES:
            raise ObservationUnavailable('case budget exceeded')
        counts = {s: 0 for s in STATUSES}; seen = set()
        for case in cases:
            _exact(case, ('case_id', 'status'))
            ident = _id(case['case_id']); _need(ident not in seen, 'RECEIPT_CASE_DUPLICATE'); seen.add(ident)
            state = case['status']; _need(isinstance(state, str) and state in counts, 'CASE_STATUS_INVALID'); counts[state] += 1
        _need(seen == case_ids[sid], 'CASE_SET_MISMATCH')
        den = suite['denominator']; _exact(den, ('total', *STATUSES))
        _need(all(type(x) is int and x >= 0 for x in den.values()), 'DENOMINATOR_VALUE_INVALID')
        _need(den['total'] == len(cases) and all(den[x] == counts[x] for x in STATUSES), 'DENOMINATOR_MISMATCH')
        exit_code = suite['exit_code']; _need(type(exit_code) is int, 'EXIT_CODE_INVALID')
        _need(not (counts['PASS'] == len(cases) and exit_code != 0), 'ALL_PASS_NONZERO_EXIT')
        logs = suite['logs']; _exact(logs, KINDS); per = {}
        for kind in KINDS:
            item = logs[kind]; _exact(item, ('path', 'sha256'))
            label = _safe_label(item['path']); _need(label not in labels, 'PATH_LABEL_DUPLICATE'); labels.add(label)
            digest = item['sha256']; _need(isinstance(digest, str) and SHA256.fullmatch(digest) is not None, 'LOG_DIGEST_INVALID')
            per[kind] = digest
        result[sid] = {'denominator': dict(den), 'exit_code': exit_code, 'digests': per}
    return result, value['source_sha'] == plan['source_sha']


def _signature(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _acquire(fd, owned):
    if type(fd) is not int or fd < 3:
        raise ObservationUnavailable('FD unavailable')
    dup = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3)
    owned.append(dup)  # ownership immediately tracked, even if later validation fails
    flags = fcntl.fcntl(dup, fcntl.F_GETFL)
    st = os.fstat(dup)
    if flags & os.O_ACCMODE != os.O_RDONLY or flags & getattr(os, 'O_PATH', 0) or not stat.S_ISREG(st.st_mode):
        raise ObservationUnavailable('FD type or access unavailable')
    return dup, st


def _read(fd, before, limit, *, keep):
    if before.st_size < 0 or before.st_size > limit:
        raise ObservationUnavailable('read budget exceeded')
    offset = 0; digest = hashlib.sha256(); chunks = []
    # Never exceed the initially observed size or read budget, even if a file
    # grows. A short read and any endpoint metadata change stay unknown.
    while offset < before.st_size:
        chunk = os.pread(fd, min(CHUNK, before.st_size - offset), offset)
        if not chunk:
            raise ObservationUnavailable('short read')
        offset += len(chunk)
        digest.update(chunk)
        if keep:
            chunks.append(chunk)
    # A regular file with size zero may still expose bytes (e.g. procfs).
    # Reserve/probe one additional byte before claiming an EOF observation.
    if os.pread(fd, 1, before.st_size):
        raise ObservationUnavailable('content exceeds reported size')
    after = os.fstat(fd)
    if _signature(before) != _signature(after) or offset != before.st_size:
        raise ObservationUnavailable('FD content unstable')
    return digest.hexdigest(), offset, b''.join(chunks) if keep else None


def _role_fds(value):
    # Reject an invalid map without querying any of its descriptor numbers.
    if not isinstance(value, dict):
        raise ObservationUnavailable('invalid supplied roles')
    roles = {}
    for key, fd in value.items():
        if not (isinstance(key, tuple) and len(key) == 2 and key[0] in SUITES and key[1] in KINDS):
            raise ObservationUnavailable('invalid supplied role')
        if type(fd) is not int or fd < 3:
            raise ObservationUnavailable('invalid supplied FD')
        roles[key] = fd
    return roles


def observe(plan_fd, receipt_fd, stream_fds, expected_plan_sha256, *, expected_receipt_sha256=None):
    """Observe caller-supplied capabilities only; all authority remains unknown.

    Required prior to calling: exact externally authorized object-to-FD handoff,
    no untrusted concurrent FD-table operations or content writes, and a trusted
    caller that may read these files. The code cannot establish these premises.
    The broker must establish distinct underlying objects for every role before
    invocation: distinct FD numbers may still denote the same object, and a plan
    read can then touch a receipt/stream object before any post-pin alias check.
    Streams may be omitted; an omitted role is never touched by its FD number.
    On plan-pin failure no separate receipt/stream dup, stat or read is issued.
    Returned raw bytes are never printed or exposed. Identity comparisons occur
    only with held duplicates. EOF probes add one byte to each read budget.
    Expected pins are caller input; digests are byte observations; document IDs
    and source IDs are claims. None of these fields authenticate provenance.
    """
    out = {'scope': 'G0_FD_OBSERVATION_ONLY', 'status': 'INCONCLUSIVE', 'qualification': 'NOT_RUN',
           'product_gate_effect': 'NONE', 'source_sha': None, 'source_authentication': None,
           'principal_authentication': None, 'lease_authentication': None, 'path_binding': None,
           'execution_authentication': None,
           'caller_expected_plan_sha256': None, 'caller_expected_receipt_sha256': None,
           'observed_plan_fd_sha256': None, 'observed_receipt_fd_sha256': None,
           'plan_source_sha_claim': None, 'receipt_source_sha_claim': None, 'receipt_run_id_claim': None,
           'plan_pin_match': None, 'plan_checks_passed': None,
           'receipt_pin_match': None, 'receipt_checks_passed': None, 'source_claims_text_equal': None,
           'suite_counts': {}, 'streams': {sid: {kind: {'provided': False, 'sha256_match': None,
                            'claimed_sha256': None, 'observed_fd_sha256': None, 'size_bytes': None} for kind in KINDS} for sid in SUITES},
           'limitations': ['caller authority and stable FD handoff unverified',
                           'source, receipt provenance and workload not authenticated',
                           'caller pins and document claims do not authenticate source, actor or execution',
                           'observed FD digests do not authenticate roles, paths, provenance or authorization',
                           'path labels not opened or verified',
                           'checks are partial and do not establish complete schema conformance',
                           'broker must independently ensure distinct role objects before any FD touch',
                           'endpoint metadata do not prove continuous freeze',
                           'blocking system calls have no hard wall-clock guarantee'],
           'issues': [], 'document_contradictions': [],
           'document_contradictions_exhaustive': False, 'close_unknown': False}
    owned = []
    try:
        if not isinstance(expected_plan_sha256, str) or not SHA256.fullmatch(expected_plan_sha256):
            out['issues'].append('PLAN_PIN_INVALID'); return out
        out['caller_expected_plan_sha256'] = expected_plan_sha256
        if expected_receipt_sha256 is not None and (not isinstance(expected_receipt_sha256, str) or not SHA256.fullmatch(expected_receipt_sha256)):
            out['issues'].append('RECEIPT_PIN_INVALID'); return out
        out['caller_expected_receipt_sha256'] = expected_receipt_sha256
        try:
            roles = _role_fds(stream_fds)
        except ObservationUnavailable:
            out['issues'].append('ROLE_MAP_INVALID'); return out
        for sid, kind in roles:
            out['streams'][sid][kind]['provided'] = True
        # Numeric equality is rejected in pure memory before any dup/fstat/
        # pread. Distinct numbers may still alias; independent trusted role
        # isolation must be established by the caller before invocation.
        if type(plan_fd) is not int or plan_fd < 3:
            out['issues'].append('PLAN_FD_INVALID'); return out
        numbers = [plan_fd, *roles.values()]
        if type(receipt_fd) is int and receipt_fd >= 3:
            numbers.append(receipt_fd)
        if len(set(numbers)) != len(numbers):
            out['issues'].append('FD_NUMBER_REUSED'); return out
        try:
            pfd, pst = _acquire(plan_fd, owned)
            plan_digest, _, plan_raw = _read(pfd, pst, MAX_JSON, keep=True)
        except (OSError, ObservationUnavailable, ValueError, OverflowError):
            out['issues'].append('PLAN_OBSERVATION_UNKNOWN'); return out
        out['observed_plan_fd_sha256'] = plan_digest
        out['plan_pin_match'] = plan_digest == expected_plan_sha256
        if not out['plan_pin_match']:
            out['issues'].append('PLAN_PIN_MISMATCH'); return out
        try:
            plan = _json(plan_raw); cases = _plan(plan)
            out['plan_checks_passed'] = True
            out['plan_source_sha_claim'] = plan['source_sha']
        except DocumentError as exc:
            out['plan_checks_passed'] = False; out['issues'].append('PLAN_SHAPE_INVALID')
            out['document_contradictions'].append('PLAN_' + str(exc)); return out
        except ObservationUnavailable:
            out['issues'].append('PLAN_BUDGET_UNKNOWN'); return out
        try:
            rfd, rst = _acquire(receipt_fd, owned)
            # plan and receipt must be separate simultaneously held files.
            if (rst.st_dev, rst.st_ino) == (pst.st_dev, pst.st_ino):
                out['issues'].append('PLAN_RECEIPT_ALIAS_UNKNOWN'); return out
            rdigest, _, rraw = _read(rfd, rst, MAX_JSON, keep=True)
        except (OSError, ObservationUnavailable, ValueError, OverflowError):
            out['issues'].append('RECEIPT_OBSERVATION_UNKNOWN'); return out
        out['observed_receipt_fd_sha256'] = rdigest
        if expected_receipt_sha256 is not None:
            out['receipt_pin_match'] = rdigest == expected_receipt_sha256
            if not out['receipt_pin_match']:
                out['issues'].append('RECEIPT_PIN_MISMATCH'); return out
        try:
            receipt = _json(rraw)
            # These are validated document claims, never identity authentication.
            if isinstance(receipt, dict):
                claim = receipt.get('source_sha')
                if isinstance(claim, str) and SOURCE_ID.fullmatch(claim) is not None:
                    out['receipt_source_sha_claim'] = claim
                run_id = receipt.get('run_id')
                if isinstance(run_id, str) and IDENT.fullmatch(run_id) is not None:
                    out['receipt_run_id_claim'] = run_id
            # Preserve this safely observable top-level contradiction even if
            # a later suite check is invalid. Missing/non-string claims do not
            # imply a value; complete source identity remains unauthenticated.
            if isinstance(receipt, dict) and isinstance(receipt.get('source_sha'), str):
                out['source_claims_text_equal'] = receipt['source_sha'] == plan['source_sha']
                if not out['source_claims_text_equal']:
                    out['document_contradictions'].append('PLAN_RECEIPT_SOURCE_CLAIM_MISMATCH')
            suites, equal = _receipt(receipt, plan, cases, expected_plan_sha256)
            out['receipt_checks_passed'] = True; out['source_claims_text_equal'] = equal
        except DocumentError as exc:
            out['receipt_checks_passed'] = False; out['issues'].append('RECEIPT_SHAPE_INVALID')
            out['document_contradictions'].append('RECEIPT_' + str(exc)); return out
        except ObservationUnavailable:
            out['issues'].append('RECEIPT_BUDGET_UNKNOWN'); return out
        for sid in SUITES:
            out['suite_counts'][sid] = {'denominator': suites[sid]['denominator'], 'exit_code': suites[sid]['exit_code']}
            for kind in KINDS:
                out['streams'][sid][kind]['claimed_sha256'] = suites[sid]['digests'][kind]
        # Acquire all explicitly supplied stream handles first. Original caller
        # handles are never closed, sought, written, opened by path, or inherited.
        held = {}
        for role, fd in roles.items():
            try:
                held[role] = _acquire(fd, owned)
            except (OSError, ObservationUnavailable, ValueError, OverflowError):
                out['issues'].append('STREAM_OBSERVATION_UNKNOWN')
        protected = {(pst.st_dev, pst.st_ino), (rst.st_dev, rst.st_ino)}; groups = {}
        for role, (_, st) in held.items():
            groups.setdefault((st.st_dev, st.st_ino), []).append(role)
        total = 0
        for role, (fd, st) in held.items():
            sid, kind = role
            # Equal live FD identities conservatively prevent a read; no path
            # alias or unauthorized access is inferred from inode numbers alone.
            if (st.st_dev, st.st_ino) in protected or len(groups[(st.st_dev, st.st_ino)]) > 1:
                out['issues'].append('FD_ALIAS_OBSERVATION_UNKNOWN'); continue
            remaining = MAX_TOTAL_LOG - total
            if st.st_size < 0 or st.st_size > MAX_LOG or st.st_size + 1 > remaining:
                out['issues'].append('STREAM_BUDGET_UNKNOWN'); continue
            # Reserve the initial size plus one EOF probe even if reading fails.
            total += st.st_size + 1
            try:
                digest, size, _ = _read(fd, st, st.st_size, keep=False)
            except (OSError, ObservationUnavailable, ValueError, OverflowError):
                out['issues'].append('STREAM_OBSERVATION_UNKNOWN'); continue
            out['streams'][sid][kind]['size_bytes'] = size
            out['streams'][sid][kind]['observed_fd_sha256'] = digest
            out['streams'][sid][kind]['sha256_match'] = digest == suites[sid]['digests'][kind]
            if not out['streams'][sid][kind]['sha256_match']: out['issues'].append('STREAM_FD_DIGEST_MISMATCH')
        return out
    finally:
        # Disarm before closing: never retry an ambiguous close. Continue closing
        # other known duplicates and never close caller-owned original handles.
        while owned:
            fd = owned.pop()
            try:
                os.close(fd)
            except OSError:
                out['close_unknown'] = True


def _stream_argument(text):
    try:
        sid, kind, fd = text.split(':')
        if sid not in SUITES or kind not in KINDS or not fd.isascii() or not fd.isdecimal():
            raise ValueError
        number = int(fd)
        if number < 3:
            raise ValueError
        return (sid, kind), number
    except (ValueError, OverflowError):
        raise argparse.ArgumentTypeError('invalid stream FD role') from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan-fd', type=int, required=True)
    parser.add_argument('--receipt-fd', type=int, required=True)
    parser.add_argument('--plan-sha256', required=True)
    parser.add_argument('--receipt-sha256')
    parser.add_argument('--stream-fd', action='append', type=_stream_argument, default=[])
    args = parser.parse_args(argv)
    roles = {}
    for key, fd in args.stream_fd:
        if key in roles:
            parser.error('duplicate stream FD role')
        roles[key] = fd
    result = observe(args.plan_fd, args.receipt_fd, roles, args.plan_sha256,
                     expected_receipt_sha256=args.receipt_sha256)
    json.dump(result, sys.stdout, ensure_ascii=True, sort_keys=True); print()
    return 20


if __name__ == '__main__':
    raise SystemExit(main())
