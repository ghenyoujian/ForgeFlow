"""P001 dirty-source declaration research, pure in-memory; not a source scanner.

No repository, Git, filesystem, network or process access. Input claims, including
completeness and HEAD identity, are unverified; this cannot grant any Gate.
"""
import base64
import bisect
import hashlib
import json
import re

MAX_ENTRIES = 4096
MAX_PATH_BYTES = 4096
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_EXCLUSIONS = 4096


class ModelError(ValueError):
    pass


def _path(path):
    if type(path) is not bytes or not path or len(path) > MAX_PATH_BYTES:
        raise ModelError('INVALID_PATH')
    components = path.split(b'/')
    if any(c in (b'', b'.', b'..') or b'\0' in c for c in components):
        raise ModelError('INVALID_PATH')
    # A source materializer must never target Git's own authority directory.
    if any(c.lower() == b'.git' for c in components):
        raise ModelError('GIT_METADATA_PATH')
    return path


def _encoded(path):
    return base64.b64encode(path).decode('ascii')


def _prefix_check(paths):
    ordered = sorted(paths)
    for path in ordered:
        prefix = path + b'/'
        i = bisect.bisect_left(ordered, prefix)
        if i < len(ordered) and ordered[i].startswith(prefix):
            raise ModelError('FILE_DIRECTORY_COLLISION')


def _row(path, kind, mode, raw, object_format):
    digest = hashlib.sha256(raw).hexdigest()
    oid = hashlib.new(object_format, b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest()
    return {'path_b64': _encoded(path), 'kind': kind, 'mode': mode,
            'byte_count': len(raw), 'sha256': digest, 'computed_git_blob_oid': oid}


def create(*, head_commit, head, index, tracked_worktree, untracked, excluded,
           coverage_claims):
    """Build a deterministic evidence proposal and a content-addressed byte store.

    Each mapping has raw-byte paths and values exactly (kind, git_mode_or_None,
    content_bytes). ``None`` mode is allowed only for regular worktree files:
    it records unknown executable status, never inferred from an index. ``head``
    and ``index`` have authoritative-shaped modes but remain caller claims.
    ``excluded`` maps omitted raw-byte paths to explicit nonempty reasons.
    All four completeness booleans are caller claims, not observations.
    """
    if type(head_commit) is not str or not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', head_commit):
        raise ModelError('INVALID_HEAD_CLAIM')
    object_format = 'sha1' if len(head_commit) == 40 else 'sha256'
    required_claims = {'head', 'index', 'worktree', 'exclusions'}
    if type(coverage_claims) is not dict or set(coverage_claims) != required_claims or any(type(v) is not bool for v in coverage_claims.values()):
        raise ModelError('INVALID_COVERAGE_CLAIMS')
    maps = {'head': head, 'index': index, 'tracked_worktree': tracked_worktree, 'untracked': untracked}
    if any(type(entries) is not dict for entries in maps.values()) or type(excluded) is not dict:
        raise ModelError('INVALID_PROJECTION')
    if sum(len(entries) for entries in maps.values()) > MAX_ENTRIES or len(excluded) > MAX_EXCLUSIONS:
        raise ModelError('ENTRY_LIMIT')
    if set(tracked_worktree) - set(index):
        raise ModelError('WORKTREE_NOT_INDEXED')
    if set(untracked) & set(index):
        raise ModelError('UNTRACKED_IS_INDEXED')
    if set(excluded) & (set(head) | set(index) | set(tracked_worktree) | set(untracked)):
        raise ModelError('EXCLUSION_OVERLAP')
    # Prefix conflicts are checked per projection. An index file may legitimately
    # be staged for removal while an untracked descendant exists in the worktree.
    for entries in (head, index, {**tracked_worktree, **untracked}):
        for path in entries:
            _path(path)
        _prefix_check(entries)
    for path, reason in excluded.items():
        _path(path)
        if type(reason) is not str or not reason or len(reason) > 256:
            raise ModelError('INVALID_EXCLUSION_REASON')
    # Exclusions must not obscure an ancestor or descendant in any snapshot,
    # including paths staged for deletion and therefore absent from worktree.
    # Compare per projection: cross-projection file↔directory transitions remain
    # legal as long as no individual projection itself has a collision.
    for entries in (head, index, {**tracked_worktree, **untracked}):
        _prefix_check({**entries, **excluded})
    blobs, total, rows = {}, 0, {}
    for label, entries in maps.items():
        result = []
        for path in sorted(entries):
            value = entries[path]
            if type(value) is not tuple or len(value) != 3:
                raise ModelError('INVALID_ENTRY')
            kind, mode, raw = value
            if kind not in ('file', 'symlink') or type(raw) is not bytes:
                raise ModelError('INVALID_ENTRY')
            if kind == 'symlink' and mode != '120000':
                raise ModelError('INVALID_MODE')
            if kind == 'symlink' and (not raw or b'\0' in raw):
                raise ModelError('INVALID_SYMLINK_TARGET')
            if kind == 'file' and mode not in ('100644', '100755'):
                if not (label in ('tracked_worktree', 'untracked') and mode is None):
                    raise ModelError('INVALID_MODE')
            if len(raw) > MAX_FILE_BYTES:
                raise ModelError('FILE_LIMIT')
            total += len(raw)
            if total > MAX_TOTAL_BYTES:
                raise ModelError('TOTAL_LIMIT')
            item = _row(path, kind, mode, raw, object_format)
            previous = blobs.setdefault(item['sha256'], raw)
            if previous != raw:
                raise ModelError('DIGEST_COLLISION')
            result.append(item)
        rows[label] = result
    def diff(left, right, left_complete, right_complete):
        changes = []
        for path in sorted(set(left) | set(right)):
            old, new = left.get(path), right.get(path)
            if old == new:
                continue
            if old is None:
                change = 'ADDED' if left_complete else 'EXTRA_UNCONFIRMED'
            elif new is None:
                change = 'DELETED' if right_complete else 'MISSING_UNCONFIRMED'
            elif old[0] == new[0] and old[2] == new[2] and (old[1] is None or new[1] is None):
                change = 'INDETERMINATE_MODE'
            else:
                change = 'MODIFIED'
            changes.append({'path_b64': _encoded(path), 'change': change})
        return changes
    # Worktree comparison concerns the index paths only: a staged deletion and
    # a replacement untracked file at the same HEAD path stay distinct.
    staged = diff(head, index, coverage_claims['head'], coverage_claims['index'])
    unstaged = diff(index, tracked_worktree, coverage_claims['index'], coverage_claims['worktree'])
    worktree = {**tracked_worktree, **untracked}
    core = {'schema': 'forgeflow.ecp-dirty-source-declaration.research.v1',
            'qualification': 'NOT_RUN', 'product_gate_effect': 'NONE',
            'source_authentication': 'UNVERIFIED', 'snapshot_atomicity': 'UNKNOWN',
            'completeness_authority': 'UNVERIFIED', 'head_commit_claim': head_commit,
            'git_object_format_claim': object_format, 'coverage_claims': coverage_claims.copy(),
            'head': rows['head'], 'index': rows['index'],
            'tracked_worktree': rows['tracked_worktree'], 'untracked': rows['untracked'],
            'excluded': [{'path_b64': _encoded(p), 'reason': excluded[p]} for p in sorted(excluded)],
            'staged_changes': staged, 'unstaged_changes': unstaged,
            'unknown_worktree_modes': [_encoded(p) for p in sorted(worktree) if worktree[p][1] is None],
            'input_bytes_counting_each_projection': total}
    canonical = json.dumps(core, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')
    return {'manifest': core, 'manifest_sha256': hashlib.sha256(canonical).hexdigest(), 'blobs': blobs}
