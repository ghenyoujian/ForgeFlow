"""Research-only SQLx 0.8.6 migration expectations from supplied in-memory data.

No file/database/process access. Caller claims and digests do not authenticate
source, directory completeness, binary, database, principal or product Gate.
"""
from __future__ import annotations

import hashlib
import json
import re

MAX_ENTRIES = 4096
MAX_NAME_BYTES = 255
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_DB_ROWS = 4096
MAX_ROW_DESCRIPTION_BYTES = 4096
MAX_TOTAL_ROW_DESCRIPTION_BYTES = 1024 * 1024
I64_MIN = -(2**63)
I64_MAX = 2**63 - 1
_VERSION = re.compile(r"[+-]?[0-9]+\Z", re.ASCII)
_HEX384 = re.compile(r"[0-9a-f]{96}\Z", re.ASCII)


class OracleInputError(ValueError):
    """Stable structured rejection; it never turns malformed input into a match."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _name(value: object) -> str:
    if type(value) is not str or not value:
        raise OracleInputError('INVALID_FILENAME')
    # Character count is a cheap precondition before allocating encoded bytes.
    if len(value) > MAX_NAME_BYTES:
        raise OracleInputError('FILENAME_LIMIT')
    if value in ('.', '..') or '/' in value or '\0' in value:
        raise OracleInputError('INVALID_FILENAME')
    try:
        encoded = value.encode('utf-8', 'strict')
    except UnicodeError as exc:
        raise OracleInputError('INVALID_FILENAME_UTF8') from exc
    if len(encoded) > MAX_NAME_BYTES:
        raise OracleInputError('FILENAME_LIMIT')
    return value


def _parse(name: str, raw: bytes) -> dict | None:
    prefix, separator, rest = name.partition('_')
    if not separator or not rest.endswith('.sql'):
        return None
    if not _VERSION.fullmatch(prefix):
        raise OracleInputError('INVALID_SQLX_VERSION_PREFIX')
    version = int(prefix)
    if not I64_MIN <= version <= I64_MAX:
        raise OracleInputError('SQLX_VERSION_OUT_OF_RANGE')
    direction, suffix = ('up', '.up.sql') if rest.endswith('.up.sql') else (
        ('down', '.down.sql') if rest.endswith('.down.sql') else ('simple', '.sql')
    )
    description = rest
    # Rust str::trim_end_matches removes repeated matching suffixes.
    while description.endswith(suffix):
        description = description[:-len(suffix)]
    description = description.replace('_', ' ')
    try:
        raw.decode('utf-8', 'strict')
    except UnicodeDecodeError as exc:
        raise OracleInputError('INVALID_SQL_UTF8') from exc
    return {'filename': name, 'version': version, 'description': description,
            'direction': direction, 'no_transaction': raw.startswith(b'-- no-transaction'),
            'bytes': len(raw), 'sqlx_sha384': hashlib.sha384(raw).hexdigest(),
            'file_sha256': hashlib.sha256(raw).hexdigest()}


def inventory(entries: list[dict]) -> dict:
    """Construct expected facts from caller-declared entries; no IO occurs."""
    if type(entries) is not list or len(entries) > MAX_ENTRIES:
        raise OracleInputError('ENTRY_COUNT_INVALID')
    seen_names = set()
    ignored = []
    records = []
    total = 0
    for entry in entries:
        if type(entry) is not dict or set(entry) != {'name', 'sql'}:
            raise OracleInputError('ENTRY_SHAPE_INVALID')
        name = _name(entry['name'])
        raw = entry['sql']
        if name in seen_names:
            raise OracleInputError('DUPLICATE_FILENAME')
        seen_names.add(name)
        if type(raw) is not bytes or len(raw) > MAX_FILE_BYTES:
            raise OracleInputError('FILE_BYTES_INVALID')
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise OracleInputError('TOTAL_BYTES_LIMIT')
        record = _parse(name, raw)
        if record is None:
            ignored.append({'filename': name, 'bytes': len(raw),
                            'file_sha256': hashlib.sha256(raw).hexdigest()})
        else:
            records.append(record)
    forwards = {}
    downs = {}
    for record in records:
        version = record['version']
        target = downs if record['direction'] == 'down' else forwards
        if version in target:
            raise OracleInputError('AMBIGUOUS_DOWN_VERSION' if target is downs else 'AMBIGUOUS_FORWARD_VERSION')
        target[version] = record
    if not forwards:
        raise OracleInputError('NO_FORWARD_MIGRATIONS')
    if set(downs) - set(forwards):
        raise OracleInputError('ORPHAN_DOWN_POLICY')
    concerns = []
    for version in sorted(forwards):
        up = forwards[version]
        down = downs.get(version)
        if up['direction'] == 'up' and down is None:
            concerns.append({'version': version, 'reason': 'UP_WITHOUT_DOWN'})
        if up['direction'] == 'simple' and down is not None:
            concerns.append({'version': version, 'reason': 'SIMPLE_WITH_DOWN'})
        if down is not None and up['description'] != down['description']:
            concerns.append({'version': version, 'reason': 'PAIR_DESCRIPTION_DIFFERENCE'})
    return {'schema': 'forgeflow.ecp-p002-migration-expectation.research.v1',
            'qualification': 'NOT_RUN', 'product_gate_effect': 'NONE',
            'source_authentication': 'UNVERIFIED', 'source_file_set_completeness': 'CALLER_UNVERIFIED',
            'inputs': {'entries': len(entries), 'bytes': total},
            'forward': [forwards[v] for v in sorted(forwards)],
            'down': [downs[v] for v in sorted(downs)],
            'ignored': sorted(ignored, key=lambda value: value['filename']),
            'policy_concerns': concerns}


def compare(entries: list[dict], rows: list[dict], *, source_complete_claim: bool,
            row_complete_claim: bool) -> dict:
    """Compare input declarations only; no DB or source identity is observed."""
    if type(source_complete_claim) is not bool or type(row_complete_claim) is not bool:
        raise OracleInputError('COMPLETENESS_CLAIM_INVALID')
    expected = inventory(entries)
    if type(rows) is not list or len(rows) > MAX_DB_ROWS:
        raise OracleInputError('ROW_COUNT_INVALID')
    seen = {}
    total_description_bytes = 0
    for row in rows:
        if type(row) is not dict or set(row) != {'version', 'description', 'success', 'checksum_sha384'}:
            raise OracleInputError('ROW_SHAPE_INVALID')
        version, desc, success, checksum = (row['version'], row['description'], row['success'], row['checksum_sha384'])
        if type(version) is not int or not I64_MIN <= version <= I64_MAX:
            raise OracleInputError('ROW_VERSION_INVALID')
        if type(desc) is not str or type(success) is not bool or type(checksum) is not str or not _HEX384.fullmatch(checksum):
            raise OracleInputError('ROW_VALUE_INVALID')
        # Avoid encoding unbounded input, then enforce byte limits and valid PostgreSQL text.
        if len(desc) > MAX_ROW_DESCRIPTION_BYTES:
            raise OracleInputError('ROW_DESCRIPTION_LIMIT')
        if '\0' in desc:
            raise OracleInputError('ROW_DESCRIPTION_NUL')
        try:
            desc_bytes = desc.encode('utf-8', 'strict')
        except UnicodeError as exc:
            raise OracleInputError('ROW_DESCRIPTION_UTF8_INVALID') from exc
        if len(desc_bytes) > MAX_ROW_DESCRIPTION_BYTES:
            raise OracleInputError('ROW_DESCRIPTION_LIMIT')
        total_description_bytes += len(desc_bytes)
        if total_description_bytes > MAX_TOTAL_ROW_DESCRIPTION_BYTES:
            raise OracleInputError('TOTAL_DESCRIPTION_BYTES_LIMIT')
        if version in seen:
            raise OracleInputError('DUPLICATE_ROW_VERSION')
        seen[version] = row
    forwards = {item['version']: item for item in expected['forward']}
    possible_missing = sorted(set(forwards) - set(seen))
    possible_extra = sorted(set(seen) - set(forwards))
    # Absence only follows from the relevant independently supplied completeness
    # claim; both the row/source values and these claims remain UNVERIFIED.
    missing = possible_missing if row_complete_claim else []
    extra = possible_extra if source_complete_claim else []
    missing_unconfirmed = [] if row_complete_claim else possible_missing
    extra_unconfirmed = [] if source_complete_claim else possible_extra
    # SQLx dirty_version considers every reported success=false row, even one
    # whose version is extra or the declared source set is incomplete.
    bad_success = sorted(v for v in seen if seen[v]['success'] is not True)
    bad_checksum = sorted(v for v in set(forwards) & set(seen) if seen[v]['checksum_sha384'] != forwards[v]['sqlx_sha384'])
    bad_description = sorted(v for v in set(forwards) & set(seen) if seen[v]['description'] != forwards[v]['description'])
    discrepancies = {'missing_versions': missing, 'extra_versions': extra, 'unsuccessful_versions': bad_success,
                     'checksum_mismatch_versions': bad_checksum, 'description_mismatch_versions': bad_description}
    unconfirmed = {'possible_missing_versions': missing_unconfirmed, 'possible_extra_versions': extra_unconfirmed}
    mismatch = any(discrepancies.values())
    state = 'MISMATCH' if mismatch else ('MATCH_DECLARED' if source_complete_claim and row_complete_claim else 'INCONCLUSIVE')
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
    expected_digest = hashlib.sha256(canonical(expected)).hexdigest()
    row_digest = hashlib.sha256(canonical([seen[v] for v in sorted(seen)])).hexdigest()
    return {'schema': 'forgeflow.ecp-p002-migration-comparison.research.v1', 'state': state,
            'qualification': 'NOT_RUN', 'product_gate_effect': 'NONE',
            'source_authentication': 'UNVERIFIED', 'database_authentication': 'UNVERIFIED',
            'source_complete_claim': source_complete_claim, 'row_complete_claim': row_complete_claim,
            'claim_authority': 'UNVERIFIED', 'expected_forward_count': len(forwards),
            'observed_row_count': len(rows), 'expected_inventory_sha256': expected_digest,
            'observed_rows_sha256': row_digest, 'discrepancies': discrepancies,
            'unconfirmed': unconfirmed, 'policy_concerns': expected['policy_concerns']}
