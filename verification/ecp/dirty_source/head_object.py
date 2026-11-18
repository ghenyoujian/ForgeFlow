"""Research-only content verification of a supplied Git HEAD object.

Pure in-memory: no Git, filesystem, source identity or completeness authority.
Supports ordinary blob/symlink trees only; parent history and auxiliary objects
are not supplied. A match is not an authenticated source or a product Gate.
"""
import base64
import hashlib
import json
import re

MAX_COMMIT = 2 * 1024 * 1024
MAX_ROWS = 4096
MAX_PATH = 4096
MAX_PATH_DEPTH = 128
MAX_TOTAL_PATH_BYTES = 2 * 1024 * 1024
MAX_TRIE_NODES = 20_000
MAX_BLOB = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_TREE_TOTAL = 16 * 1024 * 1024


class HeadObjectError(ValueError):
    pass


def _object_id(kind, raw, algorithm):
    return hashlib.new(algorithm, kind + b' ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest()


def _path(encoded):
    if type(encoded) is not str or len(encoded) > 4 * ((MAX_PATH + 2) // 3):
        raise HeadObjectError('INVALID_PATH')
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, UnicodeError) as exc:
        raise HeadObjectError('INVALID_PATH') from exc
    if (base64.b64encode(raw).decode('ascii') != encoded or not raw or len(raw) > MAX_PATH
            or any(x in (b'', b'.', b'..') or b'\0' in x or x.lower() == b'.git' for x in raw.split(b'/'))):
        raise HeadObjectError('INVALID_PATH')
    return raw


def verify(manifest, blobs, commit_raw):
    """Validate caller-supplied HEAD rows/blobs against exact raw commit bytes.

    Input manifest follows dirty-source declaration research v1. Blob bytes are
    keyed by their SHA-256. Git trees are recomputed using byte names, Git mode
    and blob IDs. Raw commit is the exact commit object body, excluding Git's
    '<type> <size>\\0' header. Returns commit and all reconstructed tree bodies;
    parent history, object-store association, source identity and atomicity are
    not established. Raises on unsupported/inconsistent data; never claims PASS.
    """
    if type(manifest) is not dict or manifest.get('schema') != 'forgeflow.ecp-dirty-source-declaration.research.v1':
        raise HeadObjectError('INVALID_MANIFEST')
    if type(blobs) is not dict or type(commit_raw) is not bytes or len(commit_raw) > MAX_COMMIT:
        raise HeadObjectError('INVALID_INPUT')
    commit_claim = manifest.get('head_commit_claim')
    alg = manifest.get('git_object_format_claim')
    if (alg not in ('sha1', 'sha256') or type(commit_claim) is not str
            or not re.fullmatch(r'[0-9a-f]{40}' if alg == 'sha1' else r'[0-9a-f]{64}', commit_claim)):
        raise HeadObjectError('INVALID_COMMIT_CLAIM')
    rows = manifest.get('head')
    if type(rows) is not list or len(rows) > MAX_ROWS:
        raise HeadObjectError('INVALID_HEAD_ROWS')
    header, sep, _body = commit_raw.partition(b'\n\n')
    lines = header.split(b'\n')
    if (not sep or not lines or b'\0' in header or not lines[0].startswith(b'tree ')
            or any(line.startswith(b'tree ') for line in lines[1:])):
        raise HeadObjectError('INVALID_COMMIT_HEADER')
    try:
        tree_claim = lines[0][5:].decode('ascii')
    except UnicodeError as exc:
        raise HeadObjectError('INVALID_COMMIT_TREE') from exc
    if not re.fullmatch(r'[0-9a-f]{40}' if alg == 'sha1' else r'[0-9a-f]{64}', tree_claim):
        raise HeadObjectError('INVALID_COMMIT_TREE')
    if _object_id(b'commit', commit_raw, alg) != commit_claim:
        raise HeadObjectError('COMMIT_OID_MISMATCH')
    trie = {}
    seen = set()
    total = 0
    path_total = 0
    trie_nodes = 0
    required = {'path_b64', 'kind', 'mode', 'byte_count', 'sha256', 'computed_git_blob_oid'}
    for row in rows:
        if type(row) is not dict or set(row) != required:
            raise HeadObjectError('INVALID_HEAD_ROW')
        path = _path(row['path_b64'])
        parts = path.split(b'/')
        if len(parts) > MAX_PATH_DEPTH:
            raise HeadObjectError('PATH_DEPTH_LIMIT')
        path_total += len(path)
        if path_total > MAX_TOTAL_PATH_BYTES:
            raise HeadObjectError('TOTAL_PATH_BYTES_LIMIT')
        if path in seen:
            raise HeadObjectError('DUPLICATE_PATH')
        seen.add(path)
        mode, kind, sha, oid, size = (row[k] for k in ('mode','kind','sha256','computed_git_blob_oid','byte_count'))
        if ((kind, mode) not in (('file','100644'),('file','100755'),('symlink','120000'))
                or type(sha) is not str or not re.fullmatch(r'[0-9a-f]{64}', sha)
                or type(oid) is not str or not re.fullmatch(r'[0-9a-f]{40}' if alg == 'sha1' else r'[0-9a-f]{64}', oid)
                or type(size) is not int or not 0 <= size <= MAX_BLOB):
            raise HeadObjectError('INVALID_HEAD_ROW')
        raw = blobs.get(sha)
        if type(raw) is not bytes or len(raw) != size or hashlib.sha256(raw).hexdigest() != sha:
            raise HeadObjectError('BLOB_CONTENT_MISMATCH')
        if kind == 'symlink' and (not raw or b'\0' in raw):
            raise HeadObjectError('INVALID_SYMLINK')
        if _object_id(b'blob', raw, alg) != oid:
            raise HeadObjectError('BLOB_OID_MISMATCH')
        total += len(raw)
        if total > MAX_TOTAL:
            raise HeadObjectError('TOTAL_BYTES_LIMIT')
        node = trie
        for part in parts[:-1]:
            current = node.get(part)
            if current is None:
                if trie_nodes >= MAX_TRIE_NODES:
                    raise HeadObjectError('TRIE_NODE_LIMIT')
                current = {}; node[part] = current
                trie_nodes += 1
            if type(current) is not dict:
                raise HeadObjectError('PATH_COLLISION')
            node = current
        if parts[-1] in node:
            raise HeadObjectError('PATH_COLLISION')
        if trie_nodes >= MAX_TRIE_NODES:
            raise HeadObjectError('TRIE_NODE_LIMIT')
        node[parts[-1]] = (mode.encode('ascii'), bytes.fromhex(oid))
        trie_nodes += 1
    trees = {}
    tree_total = 0
    def make_tree(node):
        nonlocal tree_total
        items = []
        for name, entry in node.items():
            if type(entry) is dict:
                child = make_tree(entry)
                items.append((name + b'/', b'40000', name, bytes.fromhex(child)))
            else:
                mode, raw_oid = entry
                items.append((name + b'\0', mode, name, raw_oid))
        body = b''.join(mode + b' ' + name + b'\0' + oid for _,mode,name,oid in sorted(items))
        tree_total += len(body)
        if tree_total > MAX_TREE_TOTAL:
            raise HeadObjectError('TREE_BYTES_LIMIT')
        oid = _object_id(b'tree', body, alg)
        if oid in trees and trees[oid] != body:
            raise HeadObjectError('TREE_OID_COLLISION')
        trees[oid] = body
        return oid
    try:
        computed_tree = make_tree(trie)
    except RecursionError as exc:
        raise HeadObjectError('PATH_DEPTH_LIMIT') from exc
    if computed_tree != tree_claim:
        raise HeadObjectError('TREE_OID_MISMATCH')
    core = {'schema':'forgeflow.ecp-head-object-evidence.research.v1',
            'qualification':'NOT_RUN','product_gate_effect':'NONE',
            'source_authentication':'UNVERIFIED','snapshot_atomicity':'UNKNOWN',
            'coverage_authority':'UNVERIFIED','history_completeness':'NOT_MEASURED',
            'object_format_claim':alg,'commit_oid':commit_claim,'tree_oid':computed_tree,
            'head_rows':len(rows),'head_bytes_counting_rows':total,
            'commit_bytes_base64':base64.b64encode(commit_raw).decode('ascii'),
            'trees_base64':{oid:base64.b64encode(trees[oid]).decode('ascii') for oid in sorted(trees)}}
    canonical = json.dumps(core, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')
    return {'evidence': core, 'evidence_sha256': hashlib.sha256(canonical).hexdigest()}
