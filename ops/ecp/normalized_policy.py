#!/usr/bin/env python3
"""Draft source-normalization policy construction and structural validation.

This module neither materializes nor observes a source/candidate. The caller
must independently pin the policy digest, authenticate any approver and lease,
and verify every asserted source fact. No result produced here grants a Gate.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
from typing import Any

import source_snapshot

SUPPLEMENT_SCHEMA = "forgeflow.ecp-source-supplement.v1"
POLICY_SCHEMA = "forgeflow.ecp-normalization-policy.v1"
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_NODES = 2_000_000
MAX_DEPTH = 128
MAX_ENTRIES = 100_000
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_UID_GID = (1 << 32) - 2
MAX_PATH_OPERATIONS = 2_000_000
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEAD = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
MODE = re.compile(r"0[0-7]{3}\Z")


class InvalidPolicy(ValueError):
    """The supplied draft is malformed or its declared bindings disagree."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise InvalidPolicy(reason)


def _shape(value: Any) -> None:
    stack = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        require(nodes <= MAX_NODES and depth <= 32, "JSON shape exceeds budget")
        if type(item) is dict:
            require(len(item) <= MAX_ENTRIES, "JSON object exceeds budget")
            for key, child in item.items():
                require(type(key) is str, "JSON object key must be a string")
                try:
                    key_bytes = key.encode("utf-8", "strict")
                except UnicodeError as exc:
                    raise InvalidPolicy("invalid UTF-8 in JSON key") from exc
                require(len(key_bytes) <= 4096, "JSON key exceeds budget")
                stack.append((child, depth + 1))
        elif type(item) is list:
            require(len(item) <= MAX_ENTRIES, "JSON array exceeds budget")
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            try:
                encoded = item.encode("utf-8", "strict")
            except UnicodeError as exc:
                raise InvalidPolicy("invalid UTF-8 in JSON string") from exc
            require(len(encoded) <= 4096, "JSON string exceeds budget")
        elif item is None or type(item) is bool:
            continue
        elif type(item) is int:
            require(0 <= item <= (1 << 63) - 1, "JSON integer outside budget")
        else:
            raise InvalidPolicy("unsupported JSON value")


def canonical_bytes(value: Any) -> bytes:
    """Bound and encode one complete JSON value; the digest excludes no fields."""
    _shape(value)
    encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    output = bytearray()
    for chunk in encoder.iterencode(value):
        encoded = chunk.encode("utf-8", "strict")
        require(len(output) + len(encoded) <= MAX_JSON_BYTES, "canonical JSON exceeds budget")
        output.extend(encoded)
    return bytes(output)


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def parse_unique_json(raw: bytes) -> Any:
    """Parse bounded UTF-8 JSON, rejecting duplicate keys and non-integers."""
    require(type(raw) is bytes and len(raw) <= MAX_JSON_BYTES, "raw JSON exceeds budget")
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        out = {}
        for key, value in rows:
            require(key not in out, "duplicate JSON key")
            out[key] = value
        return out
    def integer(text: str) -> int:
        require(len(text) <= 19 and not text.startswith("-"), "invalid JSON integer")
        return int(text)
    def forbidden(_text: str) -> None:
        raise InvalidPolicy("non-integer JSON number")
    try:
        result = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                            parse_int=integer, parse_float=forbidden, parse_constant=forbidden)
        _shape(result)
        return result
    except InvalidPolicy:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvalidPolicy("invalid JSON") from exc


def _exact(value: Any, fields: set[str], what: str) -> None:
    require(type(value) is dict and set(value) == fields, f"invalid {what} fields")


def _hex(value: Any, pattern: re.Pattern, what: str) -> str:
    require(type(value) is str and pattern.fullmatch(value) is not None, f"invalid {what}")
    return value


def _path(path: Any, *, root: bool = False) -> str:
    require(type(path) is str and bool(path), "invalid path")
    if root and path == ".":
        return path
    require(not path.startswith("/") and "\\" not in path, "unsafe path")
    require(all(part not in ("", ".", "..") for part in path.split("/")), "noncanonical path")
    require(len(path.split("/")) <= MAX_DEPTH, "path depth exceeds budget")
    require(not any(ord(c) < 32 or ord(c) == 127 for c in path), "control in path")
    require(len(path.encode("utf-8", "strict")) <= 4096, "path exceeds budget")
    return path


def _ordered(rows: Any, name: str, *, nonempty: bool = False) -> list[dict[str, Any]]:
    require(type(rows) is list and len(rows) <= MAX_ENTRIES and (not nonempty or bool(rows)),
            f"invalid {name} list")
    previous = None
    for row in rows:
        require(type(row) is dict, f"invalid {name} row")
        path = _path(row.get("path"), root=(name == "directories"))
        encoded = path.encode("utf-8", "strict")
        require(previous is None or previous < encoded, f"{name} paths not uniquely sorted")
        previous = encoded
    return rows


def _parent(path: str) -> str:
    return PurePosixPath(path).parent.as_posix()


def _mode(value: Any, name: str) -> int:
    require(type(value) is str and MODE.fullmatch(value) is not None, f"invalid {name} mode")
    return int(value, 8)


def _target_bytes(target: Any) -> bytes:
    require(type(target) is str and bool(target), "invalid symlink target")
    raw = target.encode("utf-8", "strict")
    require(len(raw) <= 4096 and not target.startswith("/") and "\\" not in target,
            "unsafe symlink target")
    require(not any(ord(c) < 32 or ord(c) == 127 for c in target), "control in symlink target")
    return raw


def _verify_links(directories: set[str], entries: list[dict[str, Any]]) -> None:
    kinds = {r["path"]: r["kind"] for r in entries}
    kinds.update({path: "directory" for path in directories})
    links = {r["path"]: r["target"] for r in entries if r["kind"] == "symlink"}
    # A link can resolve successfully and still make recursive directory walks
    # cyclic (e.g. root/loop -> .). Include both real tree edges and resolved
    # directory-link edges, then require their union to be a DAG.
    edges = {path: set() for path in directories}
    for path in directories - {"."}:
        edges[_parent(path)].add(path)
    total_steps = 0
    for path, target in links.items():
        stack = [] if _parent(path) == "." else _parent(path).split("/")
        remaining = deque(target.split("/"))
        # The outer link whose target is being resolved counts as one.
        followed, steps = 1, 0
        while remaining:
            steps += 1
            total_steps += 1
            require(steps <= 4096, "symlink resolution exceeds budget")
            require(total_steps <= MAX_PATH_OPERATIONS, "total symlink resolution exceeds budget")
            part = remaining.popleft()
            if part in ("", "."):
                continue
            if part == "..":
                require(bool(stack), "symlink escapes projection")
                stack.pop()
                continue
            stack.append(part)
            current = "/".join(stack)
            kind = kinds.get(current)
            require(kind is None or not source_snapshot.v3_excluded(current, kind),
                    "symlink enters excluded path")
            if current in links:
                followed += 1
                require(followed <= 40, "symlink cycle or too many links")
                stack.pop()
                remaining.extendleft(reversed(links[current].split("/")))
            elif remaining:
                require(kinds.get(current) == "directory", "symlink traverses absent or nondirectory path")
        resolved = "/".join(stack) if stack else "."
        require(resolved in kinds, "symlink target absent from projection")
        if kinds[resolved] == "directory":
            edges[_parent(path)].add(resolved)
    indegree = {path: 0 for path in directories}
    for targets in edges.values():
        for target in targets:
            indegree[target] += 1
    pending = deque(path for path, degree in indegree.items() if degree == 0)
    seen = 0
    while pending:
        node = pending.popleft()
        seen += 1
        for target in edges[node]:
            indegree[target] -= 1
            if indegree[target] == 0:
                pending.append(target)
    require(seen == len(directories), "directory and symlink graph contains a cycle")


def _manifest(manifest: Any) -> tuple[str, str, list[dict[str, Any]]]:
    fields = {"schema_version", "source_root", "head", "worktree_state", "exclude_patterns",
              "untracked_scan_mode", "untracked_scan_roots", "tracked_changes", "untracked_business_files",
              "excluded_generated_files", "patch_sha256", "manifest_sha256", "created_at",
              "release_qualifiable", "inventory_complete", "inventory_error", "index_visibility_exceptions",
              "directory_projection", "projection_sha256"}
    _exact(manifest, fields, "source manifest")
    require(manifest["schema_version"] == "forgeflow.ecp-source-manifest.v3", "unsupported source manifest")
    root = manifest["source_root"]
    require(type(root) is str and os.path.isabs(root) and os.path.abspath(root) == root, "invalid source root")
    head = _hex(manifest["head"], HEAD, "source head")
    require(any(c != "0" for c in head), "source head is a null object ID")
    _hex(manifest["manifest_sha256"], HEX64, "source manifest digest")
    _hex(manifest["projection_sha256"], HEX64, "source projection digest")
    core = {k: v for k, v in manifest.items() if k not in ("manifest_sha256", "created_at", "release_qualifiable")}
    require(canonical_sha256(core) == manifest["manifest_sha256"], "source manifest digest mismatch")
    require(manifest["release_qualifiable"] is False and manifest["inventory_complete"] is True
            and manifest["inventory_error"] is None and manifest["worktree_state"] == "CLEAN", "source is not a clean draft")
    require(all(manifest[k] == [] for k in ("tracked_changes", "untracked_business_files",
                                           "excluded_generated_files", "index_visibility_exceptions")),
            "source manifest contains unresolved entries")
    require(manifest["patch_sha256"] == hashlib.sha256(b"").hexdigest(), "source patch is nonempty")
    require(manifest["exclude_patterns"] == list(source_snapshot.V3_EXCLUDES)
            and manifest["untracked_scan_roots"] == list(source_snapshot.EXPAND_UNTRACKED_PREFIXES)
            and manifest["untracked_scan_mode"] in ("all", "bounded"), "source inventory policy mismatch")
    try:
        stamp = manifest["created_at"]
        require(type(stamp) is str and datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%dT%H:%M:%SZ") == stamp,
                "invalid source timestamp")
    except (TypeError, ValueError) as exc:
        raise InvalidPolicy("invalid source timestamp") from exc
    projection = manifest["directory_projection"]
    _exact(projection, {"version", "mode_availability", "exclusion_policy_sha256", "directories",
                        "excluded_directory_boundaries"}, "source projection")
    require(projection["version"] == "forgeflow.ecp-directory-projection.v1"
            and projection["mode_availability"] == "UNAVAILABLE", "source mode must be unavailable")
    require(projection["exclusion_policy_sha256"] == canonical_sha256(list(source_snapshot.V3_EXCLUDES))
            and manifest["projection_sha256"] == canonical_sha256(projection), "source projection digest mismatch")
    dirs = _ordered(projection["directories"], "directories", nonempty=True)
    dir_paths = set()
    for item in dirs:
        _exact(item, {"path", "kind", "mode", "origin"}, "source directory")
        path = item["path"]
        require(item["kind"] == "directory" and item["mode"] is None, "source directory mode must remain unknown")
        require(type(item["origin"]) is str and item["origin"] in {"source_root", "git_ancestor", "excluded_container"}
                and (path == ".") == (item["origin"] == "source_root"), "invalid directory origin")
        require(path == "." or not source_snapshot.v3_excluded(path, "directory"),
                "excluded directory in source projection")
        dir_paths.add(path)
    require("." in dir_paths and all(_parent(p) in dir_paths for p in dir_paths if p != "."), "source directory parent missing")
    boundaries = _ordered(projection["excluded_directory_boundaries"], "boundaries")
    covered = set()
    for item in boundaries:
        _exact(item, {"path", "kind", "excluded_by"}, "exclusion boundary")
        path = item["path"]
        pattern = source_snapshot.v3_excluded(path, "directory")
        require(item["kind"] == "directory" and item["excluded_by"] == pattern and pattern is not None
                and path not in dir_paths and _parent(path) in dir_paths, "invalid excluded directory boundary")
        covered.update(parent.as_posix() for parent in PurePosixPath(path).parents)
    require(all(item["path"] in covered for item in dirs if item["origin"] == "excluded_container"),
            "excluded container has no boundary")
    return manifest["manifest_sha256"], head, dirs


def validate_source_supplement(manifest: Any, supplement: Any) -> None:
    """Validate declarations only; actual index, blobs and authorization remain unverified."""
    _shape(manifest)
    _shape(supplement)
    digest, head, manifest_dirs = _manifest(manifest)
    _exact(supplement, {"schema_version", "source_manifest_sha256", "source_head", "source_mode_claim",
                        "directories", "entries", "qualification", "product_gate_effect"}, "source supplement")
    require(supplement["schema_version"] == SUPPLEMENT_SCHEMA and supplement["source_manifest_sha256"] == digest
            and supplement["source_head"] == head and supplement["source_mode_claim"] == "UNKNOWN"
            and supplement["qualification"] == "NOT_RUN" and supplement["product_gate_effect"] == "NONE",
            "source supplement binding or state mismatch")
    dirs = _ordered(supplement["directories"], "directories", nonempty=True)
    for item in dirs:
        _exact(item, {"path", "origin"}, "supplement directory")
    require(dirs == [{"path": x["path"], "origin": x["origin"]} for x in manifest_dirs],
            "supplement directories differ from source projection")
    dir_paths = {r["path"] for r in dirs}
    entries = _ordered(supplement["entries"], "entries", nonempty=True)
    require(len(dirs) + len(entries) <= MAX_ENTRIES, "source path count exceeds budget")
    total = 0
    for item in entries:
        kind = item.get("kind")
        _exact(item, {"path", "kind", "git_mode", "git_oid", "size", "sha256"} |
               ({"target"} if kind == "symlink" else set()), "supplement entry")
        path = item["path"]
        require(path not in dir_paths and _parent(path) in dir_paths, "file parent missing or path collides")
        require((kind == "file" and item["git_mode"] in ("100644", "100755")) or
                (kind == "symlink" and item["git_mode"] == "120000"), "invalid Git entry kind or mode")
        require(not source_snapshot.v3_excluded(path, kind), "excluded source file")
        oid = item["git_oid"]
        require(type(oid) is str and re.fullmatch(r"[0-9a-f]{%d}" % len(head), oid) is not None,
                "invalid Git blob ID")
        require(any(c != "0" for c in oid), "Git blob ID is null")
        _hex(item["sha256"], HEX64, "file SHA-256")
        size = item["size"]
        require(type(size) is int and 0 <= size <= MAX_FILE_BYTES, "source file size outside budget")
        total += size
        require(total <= MAX_TOTAL_BYTES, "source bytes exceed budget")
        if kind == "symlink":
            target = _target_bytes(item["target"])
            algorithm = hashlib.sha1 if len(head) == 40 else hashlib.sha256
            require(size == len(target) and item["sha256"] == hashlib.sha256(target).hexdigest()
                    and oid == algorithm(b"blob " + str(len(target)).encode("ascii") + b"\0" + target).hexdigest(),
                    "symlink bytes or Git blob ID mismatch")
    require(sum(len(item["path"].split("/")) for item in entries) <= MAX_PATH_OPERATIONS,
            "total source path depth exceeds budget")
    entry_ancestors = {p.as_posix() for item in entries for p in PurePosixPath(item["path"]).parents}
    require(all((row["path"] in entry_ancestors) == (row["origin"] == "git_ancestor")
                for row in dirs if row["path"] != "."), "directory origin disagrees with source entries")
    _verify_links(dir_paths, entries)


def _limits(value: Any) -> dict[str, int]:
    _exact(value, {"max_entries", "max_file_bytes", "max_total_bytes", "max_depth"}, "limits")
    for key, maximum in (("max_entries", MAX_ENTRIES), ("max_file_bytes", MAX_FILE_BYTES),
                         ("max_total_bytes", MAX_TOTAL_BYTES), ("max_depth", MAX_DEPTH)):
        require(type(value[key]) is int and 0 < value[key] <= maximum, f"invalid {key}")
    return value


def validate_policy(policy: Any, manifest: Any, supplement: Any, expected_policy_sha256: str) -> None:
    """Validate a pinned draft without authenticating it or conferring authority."""
    _shape(policy)
    _hex(expected_policy_sha256, HEX64, "expected policy digest")
    require(canonical_sha256(policy) == expected_policy_sha256, "policy digest mismatch")
    validate_source_supplement(manifest, supplement)
    _exact(policy, {"schema_version", "source_manifest_sha256", "source_supplement_sha256", "source_head",
                    "source_mode_claim", "directories", "entries", "owner", "attributes", "limits",
                    "authority", "status", "qualification", "product_gate_effect"}, "policy")
    require(policy["schema_version"] == POLICY_SCHEMA and policy["source_manifest_sha256"] == manifest["manifest_sha256"]
            and policy["source_supplement_sha256"] == canonical_sha256(supplement)
            and policy["source_head"] == manifest["head"] and policy["source_mode_claim"] == "UNKNOWN",
            "policy source binding mismatch")
    require(policy["authority"] == "UNVERIFIED" and policy["status"] == "DRAFT"
            and policy["qualification"] == "NOT_RUN" and policy["product_gate_effect"] == "NONE",
            "policy cannot claim qualification or authority")
    _exact(policy["owner"], {"uid", "gid"}, "owner")
    for field in ("uid", "gid"):
        require(type(policy["owner"][field]) is int and 0 <= policy["owner"][field] <= MAX_UID_GID,
                "invalid candidate identity")
    _exact(policy["attributes"], {"access_acl", "default_acl", "xattrs", "hardlinks", "symlinks", "umask"}, "attributes")
    require(policy["attributes"] == {"access_acl": "ABSENT", "default_acl": "ABSENT", "xattrs": "NONE",
                                    "hardlinks": "REJECT", "symlinks": "INTERNAL_PROJECTION_ONLY", "umask": "0077"},
            "unsupported candidate attribute rules")
    limits = _limits(policy["limits"])
    dirs = _ordered(policy["directories"], "directories", nonempty=True)
    entries = _ordered(policy["entries"], "entries", nonempty=True)
    require(len(dirs) + len(entries) <= limits["max_entries"], "policy path count exceeds limit")
    require([r["path"] for r in dirs] == [r["path"] for r in supplement["directories"]]
            and [r["path"] for r in entries] == [r["path"] for r in supplement["entries"]],
            "policy path set differs from source")
    for row in dirs:
        _exact(row, {"path", "mode"}, "policy directory")
        _mode(row["mode"], "directory")
    total = 0
    for row, source in zip(entries, supplement["entries"]):
        _exact(row, {"path", "kind", "mode"}, "policy entry")
        require(row["kind"] == source["kind"], "policy entry kind differs from source")
        if row["kind"] == "symlink":
            require(row["mode"] is None, "symlink mode must not be asserted")
        else:
            mode = _mode(row["mode"], "file")
            require((source["git_mode"] == "100644" and mode & 0o111 == 0) or
                    (source["git_mode"] == "100755" and mode & 0o100 != 0), "file mode differs from Git executable class")
        require(source["size"] <= limits["max_file_bytes"], "source file exceeds policy limit")
        total += source["size"]
    require(total <= limits["max_total_bytes"], "source bytes exceed policy limit")
    require(all((0 if row["path"] == "." else len(row["path"].split("/"))) <= limits["max_depth"]
                for row in [*dirs, *entries]), "source depth exceeds policy limit")


def build_policy(manifest: Any, supplement: Any, *, directory_modes: dict[str, str],
                 file_modes: dict[str, str], uid: int, gid: int, attributes: dict[str, str],
                 limits: dict[str, int]) -> dict[str, Any]:
    """Build a draft from explicit rules; the caller must externally pin its digest."""
    validate_source_supplement(manifest, supplement)
    require(type(directory_modes) is dict and type(file_modes) is dict, "mode rules must be dictionaries")
    require(set(directory_modes) == {r["path"] for r in supplement["directories"]}
            and set(file_modes) == {r["path"] for r in supplement["entries"] if r["kind"] == "file"},
            "explicit mode rules do not cover exactly the source paths")
    policy = {
        "schema_version": POLICY_SCHEMA, "source_manifest_sha256": manifest["manifest_sha256"],
        "source_supplement_sha256": canonical_sha256(supplement), "source_head": manifest["head"],
        "source_mode_claim": "UNKNOWN", "directories": [{"path": r["path"], "mode": directory_modes[r["path"]]}
            for r in supplement["directories"]],
        "entries": [{"path": r["path"], "kind": r["kind"],
                     "mode": file_modes[r["path"]] if r["kind"] == "file" else None}
                    for r in supplement["entries"]],
        "owner": {"uid": uid, "gid": gid}, "attributes": dict(attributes), "limits": dict(limits),
        "authority": "UNVERIFIED", "status": "DRAFT", "qualification": "NOT_RUN", "product_gate_effect": "NONE",
    }
    validate_policy(policy, manifest, supplement, canonical_sha256(policy))
    return policy
