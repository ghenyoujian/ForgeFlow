#!/usr/bin/env python3
"""Materialize and verify a source snapshot in a disposable sibling tree.

The candidate is reconstructed from the recorded Git HEAD plus the captured
tracked patch and untracked business files. The source tree is read-only from
this command's perspective, and an existing destination is never overwritten.
"""
from __future__ import annotations

import hashlib
import errno
import fcntl
import selectors
import json
import os
import posixpath
import re
from pathlib import Path, PurePosixPath
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from typing import Any

from source_snapshot import (DEFAULT_EXCLUDES, V3_EXCLUDES, build_manifest, matches_exclude,
                             sha256_file, v3_excluded, _v3_require_boundary_directory)


def _canonical_manifest_sha(manifest: dict[str, Any]) -> str:
    core = {
        key: value for key, value in manifest.items()
        if key not in {"manifest_sha256", "created_at", "release_qualifiable"}
    }
    payload = json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _safe_relative_path(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value:
        raise ValueError("manifest entry path must be a non-empty string")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"unsafe manifest path: {value!r}")
    if "\\" in value:
        raise ValueError(f"non-portable manifest path: {value!r}")
    return path


def _entry_for_path(root: Path, relative: PurePosixPath) -> dict[str, Any]:
    path = root.joinpath(*relative.parts)
    info = path.lstat()
    mode = f"{stat.S_IMODE(info.st_mode):04o}"
    if stat.S_ISLNK(info.st_mode):
        target = os.readlink(path)
        return {
            "path": relative.as_posix(), "kind": "symlink", "mode": mode,
            "target": target, "sha256": hashlib.sha256(os.fsencode(target)).hexdigest(),
        }
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"unsupported source entry type at {relative.as_posix()}")
    return {
        "path": relative.as_posix(), "kind": "file", "mode": mode,
        "sha256": sha256_file(path),
    }


def _ensure_safe_parent(root: Path, relative: PurePosixPath) -> Path:
    current = root
    for component in relative.parts[:-1]:
        current = current / component
        try:
            info = current.lstat()
        except FileNotFoundError:
            current.mkdir()
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"untracked path traverses a non-directory: {current}")
    return current / relative.parts[-1]


def _copy_untracked(source: Path, destination: Path, entry: dict[str, Any]) -> None:
    relative = _safe_relative_path(entry.get("path"))
    actual = _entry_for_path(source, relative)
    if entry.get("kind") not in {"file", "symlink"}:
        raise ValueError(f"untracked entry cannot be materialized: {entry.get('path')}")
    expected = {key: entry.get(key) for key in ("path", "kind", "mode", "target", "sha256") if key in entry}
    if actual != expected:
        raise ValueError(f"source entry changed since snapshot: {relative.as_posix()}")
    target = _ensure_safe_parent(destination, relative)
    if os.path.lexists(target):
        raise ValueError(f"untracked entry collides with tracked source: {relative.as_posix()}")
    source_path = source.joinpath(*relative.parts)
    if actual["kind"] == "symlink":
        os.symlink(actual["target"], target)
    else:
        shutil.copyfile(source_path, target, follow_symlinks=False)
        os.chmod(target, int(actual["mode"], 8))
    if _entry_for_path(destination, relative) != actual:
        raise ValueError(f"materialized entry does not match source: {relative.as_posix()}")


def _tree_inventory(root: Path, exclude_patterns: tuple[str, ...]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for directory, directories, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        kept: list[str] = []
        for name in directories:
            path = base / name
            relative = PurePosixPath(path.relative_to(root).as_posix())
            if matches_exclude(relative.as_posix() + "/", exclude_patterns):
                continue
            if path.is_symlink():
                entries.append(_entry_for_path(root, relative))
            else:
                kept.append(name)
        directories[:] = kept
        for name in files:
            path = base / name
            relative = PurePosixPath(path.relative_to(root).as_posix())
            if matches_exclude(relative.as_posix(), exclude_patterns):
                continue
            entry = _entry_for_path(root, relative)
            entries.append(entry)
    return sorted(entries, key=lambda item: item["path"])


def _inventory_digest(entries: list[dict[str, Any]]) -> str:
    encoded = json.dumps(entries, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _remove_excluded_paths(root: Path, exclude_patterns: tuple[str, ...]) -> list[str]:
    """Physically remove excluded generated paths before candidate publication.

    Record each pruned directory once at its boundary instead of listing every
    child; excluded files outside such directories are recorded individually.
    Symlinks are unlinked as entries and are never traversed.
    """
    excluded: list[str] = []
    for directory, directories, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        kept_directories: list[str] = []
        for name in directories:
            path = base / name
            relative = path.relative_to(root).as_posix()
            if matches_exclude(relative + "/", exclude_patterns):
                if path.is_symlink():
                    path.unlink()
                else:
                    shutil.rmtree(path)
                excluded.append(relative)
            else:
                kept_directories.append(name)
        directories[:] = kept_directories
        for name in files:
            path = base / name
            relative = path.relative_to(root).as_posix()
            if matches_exclude(relative, exclude_patterns):
                path.unlink()
                excluded.append(relative)
    return sorted(set(excluded))


def _prune_empty_ancestors(root: Path) -> list[str]:
    """Remove empty stage-only ancestors left by excluded tracked entries.

    Git cannot record empty directories, and untracked directory summaries are
    rejected before materialization. The private stage therefore has no
    admitted empty-directory inputs to preserve. Never descend through links.
    """
    pruned: list[str] = []
    def fail_walk(error: OSError) -> None:
        raise error
    for current, directories, _files in os.walk(root, topdown=False, followlinks=False, onerror=fail_walk):
        for name in directories:
            path = Path(current) / name
            if path.is_symlink():
                continue
            try:
                path.rmdir()
            except OSError as exc:
                if exc.errno not in (errno.ENOTEMPTY, errno.EEXIST):
                    raise
            else:
                pruned.append(path.relative_to(root).as_posix())
    return sorted(pruned)


def materialize_snapshot(source_root: Path, manifest: dict[str, Any], candidate_root: Path) -> dict[str, Any]:
    """Create a verified source candidate, preserving the source worktree.

    The candidate output must not exist and must not be inside the source tree.
    Directory-summary entries are rejected because they do not identify enough
    bytes to reconstruct safely.
    """
    source = source_root.resolve(strict=True)
    destination = candidate_root.expanduser().resolve()
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"candidate destination already exists: {destination}")
    if destination == source or source in destination.parents:
        raise ValueError("candidate destination must be outside the source tree")
    destination.parent.mkdir(parents=True, exist_ok=True)
    resolved_parent = destination.parent.resolve(strict=True)
    if resolved_parent == source or source in resolved_parent.parents:
        raise ValueError("candidate destination parent resolves inside the source tree")
    destination = resolved_parent / destination.name
    if manifest.get("schema_version") != "forgeflow.ecp-source-manifest.v2":
        raise ValueError("unsupported source manifest schema")
    if manifest.get("source_root") != str(source):
        raise ValueError("manifest source root does not match requested source")
    if manifest.get("manifest_sha256") != _canonical_manifest_sha(manifest):
        raise ValueError("source manifest digest is invalid")
    summary_entries = [
        entry for field in ("tracked_changes", "untracked_business_files")
        for entry in manifest.get(field, [])
        if entry.get("kind") == "directory_summary"
    ]
    if summary_entries:
        raise ValueError("manifest contains directory summaries and cannot be fully materialized")

    exclude_patterns = tuple(manifest.get("exclude_patterns", DEFAULT_EXCLUDES))
    before = build_manifest(source, exclude_patterns, manifest.get("untracked_scan_mode") == "all")
    if before.get("manifest_sha256") != manifest.get("manifest_sha256"):
        raise ValueError("source changed after the captured manifest was created")

    patch = subprocess.run(
        ["git", "diff", "--binary", "HEAD", "--"], cwd=source,
        capture_output=True, check=True, timeout=180,
    ).stdout
    if hashlib.sha256(patch).hexdigest() != manifest.get("patch_sha256"):
        raise ValueError("tracked source patch does not match the manifest")

    stage: Path | None = None
    try:
        with tempfile.TemporaryDirectory(prefix=f".{destination.name}.stage-", dir=destination.parent) as temp:
            stage = Path(temp) / "candidate"
            subprocess.run(
                ["git", "clone", "--quiet", "--shared", "--no-hardlinks", "--no-checkout", str(source), str(stage)],
                check=True, capture_output=True, timeout=180,
            )
            subprocess.run(
                ["git", "-C", str(stage), "checkout", "--quiet", "--detach", str(manifest["head"])],
                check=True, capture_output=True, timeout=180,
            )
            if patch:
                subprocess.run(
                    ["git", "-C", str(stage), "apply", "--binary", "-"],
                    input=patch, check=True, capture_output=True, timeout=180,
                )
            for entry in manifest.get("untracked_business_files", []):
                _copy_untracked(source, stage, entry)

            for field in ("tracked_changes", "untracked_business_files"):
                for entry in manifest.get(field, []):
                    if entry.get("kind") == "directory_summary":
                        raise ValueError("directory summaries cannot be verified")
                    relative = _safe_relative_path(entry.get("path"))
                    if entry.get("kind") == "deleted":
                        if os.path.lexists(stage.joinpath(*relative.parts)):
                            raise ValueError(f"deleted source entry remains in candidate: {relative.as_posix()}")
                        continue
                    actual = _entry_for_path(stage, relative)
                    expected = {key: entry.get(key) for key in ("path", "kind", "mode", "target", "sha256") if key in entry}
                    if actual != expected:
                        raise ValueError(f"candidate entry differs from manifest: {relative.as_posix()}")

            shutil.rmtree(stage / ".git")
            excluded_paths = _remove_excluded_paths(stage, exclude_patterns)
            pruned_ancestors = _prune_empty_ancestors(stage)
            inventory = _tree_inventory(stage, exclude_patterns)
            inventory_sha = _inventory_digest(inventory)
            after = build_manifest(source, exclude_patterns, manifest.get("untracked_scan_mode") == "all")
            if after.get("manifest_sha256") != manifest.get("manifest_sha256"):
                raise ValueError("source changed while the candidate was being materialized")
            os.replace(stage, destination)
            stage = None
    except Exception:
        if stage is not None:
            shutil.rmtree(stage.parent, ignore_errors=True)
        raise

    return {
        "status": "PASS",
        "candidate_root": str(destination),
        "source_manifest_sha256": manifest["manifest_sha256"],
        "candidate_inventory_sha256": inventory_sha,
        "candidate_file_count": len(inventory),
        "candidate_tree_bytes": sum(
            (destination / item["path"]).stat().st_size
            for item in inventory if item["kind"] == "file"
        ),
        "excluded_paths": excluded_paths,
        "excluded_path_count": len(excluded_paths),
        "pruned_empty_ancestors": pruned_ancestors,
        "materialized_deleted_paths": [
            entry["path"] for entry in manifest.get("tracked_changes", []) if entry.get("kind") == "deleted"
        ],
        "git_metadata_removed": True,
        "source_unchanged": True,
    }

# The v3 implementation is deliberately a separate draft observation path.
# It never changes the v2 entry point or turns draft manifests into release
# evidence. Limits are applied before allocating an unbounded inventory.
_V3_MAX_ENTRIES = 100_000
_V3_MAX_BYTES = 2 * 1024**3
_V3_MAX_SCAN_SECONDS = 60
_V3_GIT_TIMEOUT_SECONDS = 180
_V3_MAX_METADATA = 16 * 1024**2
_V3_MAX_GIT_TREE_BYTES = 128 * 1024**2
_V3_MAX_GIT_BLOB_BYTES = 64 * 1024**2
_V3_MAX_HASH_BYTES = 64 * 1024**2


def _v3_hash(value: Any, *, limit: int = _V3_MAX_HASH_BYTES) -> str:
    # Bound shape before JSONEncoder creates escaped intermediate strings.
    # This library accepts an already parsed dict; callers must still enforce
    # the contract's raw input byte limit before parsing untrusted JSON.
    stack = [(value, 0)]; nodes = 0
    while stack:
        item, depth = stack.pop(); nodes += 1
        if nodes > 2_000_000 or depth > 32:
            raise ValueError("v3 canonical JSON shape exceeds budget")
        if isinstance(item, str):
            if len(item) > 4096 or len(item.encode("utf-8", "strict")) > 4096:
                raise ValueError("v3 canonical JSON string exceeds byte budget")
        elif isinstance(item, dict):
            if len(item) > _V3_MAX_ENTRIES:
                raise ValueError("v3 canonical JSON map exceeds budget")
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValueError("v3 canonical JSON key is not a string")
                stack.append((key, depth + 1)); stack.append((child, depth + 1))
        elif isinstance(item, (list, tuple)):
            if len(item) > _V3_MAX_ENTRIES:
                raise ValueError("v3 canonical JSON array exceeds budget")
            stack.extend((child, depth + 1) for child in item)
        elif item is not None and not isinstance(item, (bool, int, float)):
            raise ValueError("v3 canonical JSON contains an unsupported value")
    encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    digest = hashlib.sha256(); total = 0; deadline = time.monotonic() + _V3_MAX_SCAN_SECONDS
    for part in encoder.iterencode(value):
        if time.monotonic() > deadline:
            raise TimeoutError("v3 canonical JSON time budget exceeded")
        data = part.encode("utf-8", "strict"); total += len(data)
        if total > limit:
            raise ValueError("v3 canonical JSON exceeds byte budget")
        digest.update(data)
    return digest.hexdigest()


def _v3_open_directory(path: Path) -> tuple[Path, int]:
    """Open every path component without traversing symlinks."""
    path = Path(os.path.abspath(path))
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            old_fd, fd = fd, child
            os.close(old_fd)
        return path, fd
    except BaseException:
        os.close(fd)
        raise


def _v3_assert_source_binding(source: Path, source_fd: int) -> None:
    _, current_fd = _v3_open_directory(source)
    try:
        original = os.fstat(source_fd); current = os.fstat(current_fd)
        if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError("source root path no longer binds the pinned directory")
    finally:
        os.close(current_fd)


def _v3_parent_within_source(parent_fd: int, source_fd: int) -> bool:
    """Detect physical ancestry, including an aliasing mount, without following links."""
    source = os.fstat(source_fd)
    current = os.dup(parent_fd)
    try:
        for _ in range(256):
            info = os.fstat(current)
            if (info.st_dev,info.st_ino) == (source.st_dev,source.st_ino):
                return True
            parent = os.open('..',os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,dir_fd=current)
            try:
                prior = os.fstat(parent)
            except BaseException:
                os.close(parent)
                raise
            if (prior.st_dev,prior.st_ino) == (info.st_dev,info.st_ino):
                os.close(parent)
                return False
            old, current = current, parent
            os.close(old)
        raise ValueError('candidate parent ancestry exceeds safety budget')
    finally:
        os.close(current)


def _v3_backing_path(path: Path, mountinfo: str | None = None) -> tuple[str, str]:
    """Resolve mount-root aliases without following paths or modifying mounts."""
    import re
    absolute = os.path.abspath(path)
    table = Path('/proc/self/mountinfo').read_text(encoding='utf-8') if mountinfo is None else mountinfo
    selected = None
    for line in table.splitlines():
        left, separator, right = line.partition(' - ');fields = left.split()
        if not separator or len(fields) < 6 or not right.split():
            raise ValueError('mount table is malformed')
        decode = lambda s: re.sub(r'\\([0-7]{3})',lambda m:chr(int(m.group(1),8)),s)
        mount, fs_root = decode(fields[4]),decode(fields[3])
        if absolute == mount or absolute.startswith(mount.rstrip('/') + '/'):
            if selected is None or len(mount) > len(selected[1]):
                selected = (fields[2],mount,fs_root)
    if selected is None:
        raise ValueError('mount identity is unavailable')
    device,mount,fs_root = selected
    suffix = absolute[len(mount):].lstrip('/') if mount != '/' else absolute.lstrip('/')
    return device,posixpath.normpath(posixpath.join(fs_root,suffix))


def _v3_parent_mount_aliases_source(source: Path, parent: Path) -> bool:
    table = Path('/proc/self/mountinfo').read_text(encoding='utf-8')
    source_device,source_backing = _v3_backing_path(source,table)
    parent_device,parent_backing = _v3_backing_path(parent,table)
    return source_device == parent_device and (parent_backing == source_backing or
                                                parent_backing.startswith(source_backing.rstrip('/') + '/'))


def _v3_assert_output_parent_binding(parent: Path, parent_fd: int, *, published: bool) -> None:
    """Check the user-visible output parent still identifies the pinned inode."""
    suffix = ("after publication; candidate state is uncertain and no published content was cleaned"
              if published else "before publication; no candidate was published")
    try:
        observed_parent = os.readlink(f"/proc/self/fd/{parent_fd}")
    except OSError:
        observed_parent = "unavailable"
    suffix += f"; pinned parent at last observation: {observed_parent!r}"
    try:
        _, current_fd = _v3_open_directory(parent)
    except OSError as exc:
        raise RuntimeError(f"candidate parent path could not be verified {suffix}") from exc
    try:
        original = os.fstat(parent_fd); current = os.fstat(current_fd)
        if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
            raise RuntimeError(f"candidate parent path no longer binds the pinned directory {suffix}")
    finally:
        os.close(current_fd)


def _v3_assert_published_candidate(parent_fd: int, destination_name: str, stage_fd: int) -> None:
    """Verify the published entry is the inode we examined; never clean on uncertainty."""
    message = "published candidate path identity is uncertain; no published content was cleaned"
    try:
        current = os.stat(destination_name, dir_fd=parent_fd, follow_symlinks=False)
        expected = os.fstat(stage_fd)
    except OSError as exc:
        raise RuntimeError(message) from exc
    if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
        raise RuntimeError(message)


def _v3_path(value: Any, *, root: bool = False) -> str:
    if root and value == ".":
        return "."
    p = _safe_relative_path(value)
    if p.as_posix() != value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("non-canonical projection path")
    if len(p.parts) > 127:
        raise ValueError("projection path exceeds depth budget")
    if len(value.encode("utf-8", "strict")) > 4096:
        raise ValueError("projection path exceeds byte budget")
    return value


def _v3_expected_projection(manifest: dict[str, Any]) -> tuple[list[dict[str, str]], set[str]]:
    import re
    from datetime import datetime
    fields = {"schema_version", "source_root", "head", "worktree_state", "exclude_patterns", "untracked_scan_mode",
              "untracked_scan_roots", "tracked_changes", "untracked_business_files", "excluded_generated_files",
              "patch_sha256", "manifest_sha256", "created_at", "release_qualifiable", "inventory_complete",
              "inventory_error", "index_visibility_exceptions", "directory_projection", "projection_sha256"}
    if not isinstance(manifest, dict) or set(manifest) != fields:
        raise ValueError("v3 source manifest has missing or unknown fields")
    if manifest.get("schema_version") != "forgeflow.ecp-source-manifest.v3":
        raise ValueError("wrong v3 source manifest schema")
    if not isinstance(manifest.get("head"), str) or re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", manifest["head"]) is None:
        raise ValueError("invalid v3 source Git head")
    if manifest.get("untracked_scan_mode") not in {"all", "bounded"}:
        raise ValueError("invalid v3 source scan mode")
    try:
        stamp = manifest["created_at"]
        if not isinstance(stamp, str) or datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%dT%H:%M:%SZ") != stamp:
            raise ValueError("non-canonical timestamp")
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid v3 source timestamp") from exc
    if manifest.get("release_qualifiable") is not False or manifest.get("inventory_complete") is not True:
        raise ValueError("v3 draft is not a complete non-qualifying observation")
    if manifest.get("inventory_error") is not None or manifest.get("index_visibility_exceptions") != []:
        raise ValueError("v3 source inventory is incomplete or has hidden index entries")
    if manifest.get("worktree_state") != "CLEAN" or any(manifest.get(k) != [] for k in
            ("tracked_changes", "untracked_business_files", "excluded_generated_files")):
        raise ValueError("v3 draft materialization requires a clean projected source")
    if manifest.get("patch_sha256") != hashlib.sha256(b"").hexdigest():
        raise ValueError("v3 clean source has a non-empty patch")
    if manifest.get("exclude_patterns") != list(V3_EXCLUDES):
        raise ValueError("unregistered source exclusion policy")
    if manifest.get("manifest_sha256") != _v3_hash({k: v for k, v in manifest.items() if k not in
                                                       ("manifest_sha256", "created_at", "release_qualifiable")},
                                                      limit=16 * 1024**2):
        raise ValueError("v3 manifest digest mismatch")
    proj = manifest.get("directory_projection")
    if not isinstance(proj, dict) or set(proj) != {"version", "mode_availability", "exclusion_policy_sha256",
                                                  "directories", "excluded_directory_boundaries"}:
        raise ValueError("malformed directory projection")
    if proj["version"] != "forgeflow.ecp-directory-projection.v1" or proj["mode_availability"] != "VERIFIED":
        raise ValueError("v3 directory modes are not verified")
    if proj["exclusion_policy_sha256"] != _v3_hash(list(V3_EXCLUDES)) or manifest.get("projection_sha256") != _v3_hash(proj):
        raise ValueError("v3 policy or projection digest mismatch")
    dirs = proj["directories"]
    boundaries = proj["excluded_directory_boundaries"]
    if not isinstance(dirs, list) or not 0 < len(dirs) <= _V3_MAX_ENTRIES or not isinstance(boundaries, list) or len(boundaries) > _V3_MAX_ENTRIES:
        raise ValueError("v3 directory inventory exceeds its bounds")
    paths: set[str] = set()
    physical = []
    last = None
    deadline = time.monotonic() + _V3_MAX_SCAN_SECONDS
    for entry in dirs:
        if time.monotonic() > deadline:
            raise TimeoutError("v3 directory projection time budget exceeded")
        if not isinstance(entry, dict) or set(entry) != {"path", "kind", "mode", "origin"}:
            raise ValueError("malformed v3 directory entry")
        path = _v3_path(entry["path"], root=True)
        key = path.encode("utf-8", "strict")
        if last is not None and key <= last:
            raise ValueError("v3 directory paths are not uniquely sorted")
        last = key
        if (entry["kind"] != "directory" or not isinstance(entry["mode"], str)
                or len(entry["mode"]) != 4 or any(c not in "01234567" for c in entry["mode"])):
            raise ValueError("invalid v3 directory kind or mode")
        if (path == ".") != (entry["origin"] == "source_root") or entry["origin"] not in {"source_root", "git_ancestor", "excluded_container"}:
            raise ValueError("v3 clean projection contains an invalid directory origin")
        if path != "." and v3_excluded(path, "directory"):
            raise ValueError("excluded directory in v3 projection")
        paths.add(path)
        physical.append({"path": path, "kind": "directory", "mode": entry["mode"]})
    if "." not in paths:
        raise ValueError("v3 source root is missing")
    for path in paths - {"."}:
        parent = PurePosixPath(path).parent.as_posix()
        if parent not in paths:
            raise ValueError("v3 directory parent is missing")
    last = None
    boundary_paths = set()
    uncovered = {item["path"] for item in dirs if item["origin"] == "excluded_container"}
    for boundary in boundaries:
        if time.monotonic() > deadline:
            raise TimeoutError("v3 boundary projection time budget exceeded")
        if not isinstance(boundary, dict) or set(boundary) != {"path", "kind", "excluded_by"}:
            raise ValueError("malformed excluded directory boundary")
        path = _v3_path(boundary["path"])
        key = path.encode("utf-8", "strict")
        if last is not None and key <= last:
            raise ValueError("excluded directory boundaries are not uniquely sorted")
        last = key
        first_match = v3_excluded(path, "directory")
        if (boundary["kind"] != "directory" or boundary["excluded_by"] != first_match or first_match is None
                or path in paths or PurePosixPath(path).parent.as_posix() not in paths):
            raise ValueError("unregistered excluded directory boundary")
        boundary_paths.add(path)
        for parent in PurePosixPath(path).parents:
            uncovered.discard(parent.as_posix())
    if uncovered:
        raise ValueError("excluded container has no excluded directory boundary")
    return physical, boundary_paths


def _v3_link_target(root_fd: int, relative: str, target: str) -> None:
    """Resolve a relative symlink chain under root by anchored no-follow fds."""
    from collections import deque
    if not target or os.path.isabs(target) or "\\" in target:
        raise ValueError("absolute or empty projected symlink target")
    target.encode("utf-8", "strict")
    if len(os.fsencode(target)) > 4096:
        raise ValueError("projected symlink target exceeds byte budget")
    resolved = list(PurePosixPath(relative).parent.parts)
    # The caller already traversed the symlink whose target is supplied here.
    pending = deque(target.split("/")); links = 1; operations = 0
    deadline = time.monotonic() + _V3_MAX_SCAN_SECONDS
    while pending:
        operations += 1
        if operations > 4096 or time.monotonic() > deadline:
            raise ValueError("projected symlink resolution budget exceeded")
        part = pending.popleft()
        if part in ("", "."):
            continue
        if part == "..":
            if not resolved:
                raise ValueError("projected symlink target escapes source")
            resolved.pop()
            continue
        relative_target = "/".join([*resolved, part])
        _v3_path(relative_target)
        fd = _v3_open_relative_directory(root_fd, "/".join(resolved) or ".")
        try:
            info = os.stat(part, dir_fd=fd, follow_symlinks=False)
            kind = "symlink" if stat.S_ISLNK(info.st_mode) else ("directory" if stat.S_ISDIR(info.st_mode) else "file")
            if v3_excluded(relative_target, kind):
                raise ValueError("projected symlink enters excluded source")
            if stat.S_ISLNK(info.st_mode):
                links += 1
                if links > 40:
                    raise ValueError("projected symlink chain exceeds 40 links or has a cycle")
                nested = os.readlink(part, dir_fd=fd)
                after = os.stat(part, dir_fd=fd, follow_symlinks=False)
                signature = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_mtime_ns", "st_ctime_ns")
                if any(getattr(info, key) != getattr(after, key) for key in signature):
                    raise ValueError("projected symlink target changed during inspection")
                if not nested or os.path.isabs(nested) or "\\" in nested or len(os.fsencode(nested)) > 4096:
                    raise ValueError("nested projected symlink target escapes source")
                pending.extendleft(reversed(nested.split("/")))
                if len(pending) > 4096:
                    raise ValueError("projected symlink resolution budget exceeded")
            elif stat.S_ISDIR(info.st_mode):
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    opened = os.fstat(child)
                    if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
                        raise ValueError("projected symlink target changed during inspection")
                finally:
                    os.close(child)
                resolved.append(part)
            elif stat.S_ISREG(info.st_mode) and not pending:
                return
            else:
                raise ValueError("unsupported projected symlink target")
        except (FileNotFoundError, NotADirectoryError) as exc:
            raise ValueError("projected symlink target is missing or escapes source") from exc
        finally:
            os.close(fd)
    # Empty targets after dot/parent resolution must resolve to a real directory.
    fd = _v3_open_relative_directory(root_fd, "/".join(resolved) or ".")
    os.close(fd)


def _v3_inventory(root: Path, *, trusted_dirfd: int | None = None,
                  require_single_links: bool = False) -> tuple[list[dict[str, str]], list[dict[str, str]], int]:
    """Stream dirfd entries without following links, bounded by count/depth/time."""
    if trusted_dirfd is None:
        root, rootfd = _v3_open_directory(root)
    else:
        rootfd = os.dup(trusted_dirfd)
    dirs_out: list[dict[str, str]] = []
    files_out: list[dict[str, str]] = []
    total = 0
    count = 0
    deadline = time.monotonic() + _V3_MAX_SCAN_SECONDS
    # Each stack frame holds at most one streaming scandir iterator and its
    # anchored directory fd; never build os.walk/fwalk's unbounded name lists.
    stack: list[tuple[str, int, Any, os.stat_result]] = []
    keys = ("st_dev", "st_ino", "st_size", "st_mode", "st_nlink", "st_mtime_ns", "st_ctime_ns")
    def unchanged(a: os.stat_result, b: os.stat_result) -> bool:
        return all(getattr(a, k) == getattr(b, k) for k in keys)
    try:
        root_stat = os.fstat(rootfd)
        dirs_out.append({"path": ".", "kind": "directory", "mode": f"{stat.S_IMODE(root_stat.st_mode):04o}"})
        stack.append((".", rootfd, os.scandir(rootfd), root_stat))
        while stack:
            if time.monotonic() > deadline:
                raise TimeoutError("v3 inventory time budget exceeded")
            base, dirfd, iterator, before_dir = stack[-1]
            entry = next(iterator, None)
            if entry is None:
                if not unchanged(before_dir, os.fstat(dirfd)):
                    raise ValueError("source directory changed during inventory")
                stack.pop()
                try:
                    iterator.close()
                finally:
                    # The root is borrowed by its frame and remains owned by
                    # the enclosing function until the one final close.
                    if dirfd != rootfd:
                        os.close(dirfd)
                continue
            count += 1
            if count > _V3_MAX_ENTRIES:
                raise ValueError("v3 inventory entry budget exceeded")
            name = entry.name
            path = _v3_path((PurePosixPath(base) / name).as_posix())
            info = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)):
                raise ValueError("unsupported source entry in v3 inventory")
            kind = "symlink" if stat.S_ISLNK(info.st_mode) else ("directory" if stat.S_ISDIR(info.st_mode) else "file")
            if v3_excluded(path, kind):
                if kind == "symlink":
                    raise ValueError("excluded directory boundary is a symlink")
                continue
            if require_single_links and (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)) and info.st_nlink != 1:
                raise ValueError("candidate file or symlink has unverified hardlinks")
            mode = f"{stat.S_IMODE(info.st_mode):04o}"
            if stat.S_ISDIR(info.st_mode):
                if len(stack) >= 128:
                    raise ValueError("v3 inventory directory depth exceeded")
                childfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dirfd)
                try:
                    opened = os.fstat(childfd)
                    if not unchanged(info, opened):
                        raise ValueError("source directory changed during inventory")
                    child_iter = os.scandir(childfd)
                    try:
                        stack.append((path, childfd, child_iter, opened))
                    except BaseException:
                        child_iter.close()
                        raise
                except BaseException:
                    os.close(childfd)
                    raise
                dirs_out.append({"path": path, "kind": "directory", "mode": mode})
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(name, dir_fd=dirfd)
                _v3_link_target(rootfd, path, target)
                after = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
                if not unchanged(info, after):
                    raise ValueError("source symlink changed during inventory")
                files_out.append({"path": path, "kind": "symlink", "mode": mode, "target": target,
                                  "sha256": hashlib.sha256(os.fsencode(target)).hexdigest()})
            elif stat.S_ISREG(info.st_mode):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirfd)
                try:
                    opened = os.fstat(fd)
                    if not unchanged(info, opened) or not stat.S_ISREG(opened.st_mode):
                        raise ValueError("source file changed during inventory")
                    total += opened.st_size
                    if total > _V3_MAX_BYTES:
                        raise ValueError("v3 inventory byte budget exceeded")
                    digest = hashlib.sha256(); remaining = opened.st_size
                    while remaining:
                        if time.monotonic() > deadline:
                            raise TimeoutError("v3 inventory time budget exceeded")
                        chunk = os.read(fd, min(remaining, 1024 * 1024))
                        if not chunk:
                            raise ValueError("source file was truncated during inventory")
                        digest.update(chunk); remaining -= len(chunk)
                    if not unchanged(opened, os.fstat(fd)):
                        raise ValueError("source file changed during inventory")
                finally:
                    os.close(fd)
                files_out.append({"path": path, "kind": "file", "mode": mode, "sha256": digest.hexdigest()})
            else:
                raise ValueError("unsupported projected source entry")
    finally:
        from contextlib import ExitStack
        with ExitStack() as cleanup:
            # The root is always owned here, including when scandir creation
            # fails; every other frame owns its separate child descriptor.
            cleanup.callback(os.close, rootfd)
            for _, fd, iterator, _ in stack:
                if fd != rootfd:
                    cleanup.callback(os.close, fd)
                cleanup.callback(iterator.close)
            stack.clear()
    dirs_out.sort(key=lambda x: x["path"].encode("utf-8", "strict"))
    files_out.sort(key=lambda x: x["path"].encode("utf-8", "strict"))
    return dirs_out, files_out, total


def _v3_publish_noreplace(stage_parent_fd: int, destination_parent_fd: int, destination_name: str) -> None:
    # renameat2 enforces no-overwrite atomically. An unavailable primitive is a
    # blocker, never a reason to fall back to os.replace.
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    if rename is None:
        raise OSError(errno.ENOSYS, "atomic no-replace rename is unavailable")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(stage_parent_fd, b"candidate", destination_parent_fd, os.fsencode(destination_name), 1) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination_name)


def _v3_git_capture(command: list[str], env: dict[str, str], payload: bytes = b"", *, limit: int,
                    pass_fds: tuple[int, ...] = ()) -> bytes:
    """Capture bounded Git object data; Git stderr is deliberately unavailable."""
    if len(payload) > _V3_MAX_METADATA:
        raise ValueError("Git object request exceeds metadata budget")
    with tempfile.TemporaryFile() as input_file:
        input_file.write(payload); input_file.seek(0)
        process = subprocess.Popen(command, env=env, stdin=input_file, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, start_new_session=True, pass_fds=pass_fds)
        selector = None
        leader_reaped = False
        output = bytearray(); deadline = time.monotonic() + _V3_GIT_TIMEOUT_SECONDS
        try:
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError("Git object capture timed out; stderr unavailable")
                for key, _ in selector.select(left):
                    chunk = os.read(key.fileobj.fileno(), min(65536, limit - len(output) + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(chunk)
                        if len(output) > limit:
                            raise ValueError("Git object output exceeds byte budget; stderr unavailable")
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("Git object capture timed out; stderr unavailable")
            try:
                code = process.wait(timeout=left)
                leader_reaped = True
            except subprocess.TimeoutExpired as exc:
                raise TimeoutError("Git object capture timed out; stderr unavailable") from exc
            if code != 0:
                raise RuntimeError(f"Git object inspection exited {code}; stderr unavailable")
            return bytes(output)
        except BaseException as error:
            if not leader_reaped:
                # A wait implementation can set returncode and then raise,
                # or an asynchronous exception can occur between wait() and
                # our flag update. Its PID may then be reused: never signal it.
                if process.returncode is not None:
                    raise RuntimeError("Git object process-group termination could not be confirmed; stderr unavailable") from error
                signal_error = None
                try:
                    # Do not poll or wait before signalling: the direct child's
                    # unreaped PID anchors this invocation's process group.
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError as exc:
                    signal_error = exc
                try:
                    process.wait(timeout=5)
                    leader_reaped = True
                except (OSError, subprocess.TimeoutExpired) as exc:
                    raise RuntimeError("Git object process termination could not be confirmed; stderr unavailable") from exc
                if signal_error is not None:
                    raise RuntimeError("Git object process-group termination could not be confirmed; stderr unavailable") from signal_error
            raise
        finally:
            import sys
            pending = sys.exc_info()[1]
            close_error = None
            for handle in (selector, process.stdout):
                if handle is None:
                    continue
                try:
                    handle.close()
                except OSError as exc:
                    close_error = close_error or exc
            if close_error is not None:
                if pending is None:
                    raise close_error
                if hasattr(pending, 'add_note'):
                    pending.add_note('Git capture handle cleanup also failed: ' + type(close_error).__name__)


def _v3_git_objects_pinned(source_fd: int, sha: str) -> tuple[dict[str, tuple[str, str]], dict[str, bytes]]:
    """Read only included immutable Git blobs, with bounded metadata and bytes."""
    import re
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "file",
           "GIT_ATTR_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1",
           "GIT_NO_LAZY_FETCH": "1"}
    if "HOME" in os.environ:
        env["HOME"] = os.environ["HOME"]
    git = ["/usr/bin/git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
           "-c", "core.attributesFile=/dev/null", "-c", "core.autocrlf=false", "-C", f"/proc/self/fd/{source_fd}"]
    raw = _v3_git_capture([*git, "ls-tree", "-rz", "--full-tree", sha], env, limit=_V3_MAX_METADATA,
                          pass_fds=(source_fd,))
    if not raw.endswith(b"\0") or raw.count(b"\0") > _V3_MAX_ENTRIES:
        raise ValueError("Git tree metadata is incomplete or exceeds entry budget")
    entries: dict[str, tuple[str, str]] = {}
    oid_len = len(sha)
    deadline = time.monotonic() + _V3_MAX_SCAN_SECONDS
    for record in raw.split(b"\0"):
        if time.monotonic() >= deadline:
            raise TimeoutError("Git tree enumeration exceeded deadline")
        if not record:
            continue
        metadata, sep, name = record.partition(b"\t")
        if not sep:
            raise ValueError("malformed Git tree entry")
        fields = metadata.decode("ascii", "strict").split(" ")
        if len(fields) != 3:
            raise ValueError("malformed Git tree metadata")
        mode, kind, oid = fields
        path = _v3_path(name.decode("utf-8", "strict"))
        excluded = v3_excluded(path, "file")
        if mode == "120000" and (path == ".env" or (not excluded and v3_excluded(path, "symlink"))):
            raise ValueError("excluded Git path is a symlink, not a directory boundary")
        if excluded:
            _v3_require_boundary_directory(source_fd, excluded, deadline=deadline)
            continue
        if (mode not in {"100644", "100755", "120000"} or kind != "blob"
                or re.fullmatch(r"[a-f0-9]{%d}" % oid_len, oid) is None or path in entries):
            raise ValueError("unsupported or duplicate Git object")
        entries[path] = (mode, oid)
    if not entries:
        raise ValueError("Git tree contains no projected source files")
    oids = list(dict.fromkeys(oid for _, oid in entries.values()))
    request = "".join(oid + "\n" for oid in oids).encode("ascii")
    raw_sizes = _v3_git_capture([*git, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
                                env, request, limit=_V3_MAX_METADATA, pass_fds=(source_fd,))
    lines = raw_sizes.splitlines()
    if len(lines) != len(oids):
        raise ValueError("Git object size list is incomplete")
    sizes: dict[str, int] = {}
    for oid, line in zip(oids, lines):
        fields = line.decode("ascii", "strict").split(" ")
        if len(fields) != 3 or fields[:2] != [oid, "blob"] or not fields[2].isdigit() or len(fields[2]) > 9:
            raise ValueError("invalid Git blob size")
        size = int(fields[2])
        if size > _V3_MAX_GIT_BLOB_BYTES:
            raise ValueError("Git blob exceeds size budget")
        sizes[oid] = size
    if sum(sizes[oid] for _, oid in entries.values()) > _V3_MAX_GIT_TREE_BYTES:
        raise ValueError("projected Git tree exceeds byte budget")
    stream = _v3_git_capture([*git, "cat-file", "--batch"], env, request,
                             limit=_V3_MAX_GIT_TREE_BYTES + len(oids) * 96, pass_fds=(source_fd,))
    offset = 0; blobs: dict[str, bytes] = {}
    for oid in oids:
        end = stream.find(b"\n", offset)
        if end < 0:
            raise ValueError("incomplete Git blob header")
        fields = stream[offset:end].decode("ascii", "strict").split(" ")
        if len(fields) != 3 or fields[:2] != [oid, "blob"] or not fields[2].isdigit() or int(fields[2]) != sizes[oid]:
            raise ValueError("Git blob header differs from size probe")
        offset = end + 1; size = sizes[oid]
        if offset + size >= len(stream):
            raise ValueError("incomplete Git blob payload")
        data = stream[offset:offset + size]; offset += size
        if stream[offset:offset + 1] != b"\n":
            raise ValueError("missing Git blob separator")
        offset += 1
        algorithm = "sha1" if oid_len == 40 else "sha256"
        if hashlib.new(algorithm, b"blob " + str(size).encode("ascii") + b"\0" + data).hexdigest() != oid:
            raise ValueError("Git blob bytes do not match object identity")
        blobs[oid] = data
    if offset != len(stream):
        raise ValueError("unexpected trailing Git blob bytes")
    return entries, blobs


def _v3_git_objects(source: Path, sha: str, *, source_fd: int | None = None) -> tuple[dict[str, tuple[str, str]], dict[str, bytes]]:
    if source_fd is None:
        _, fd = _v3_open_directory(source)
    else:
        fd = os.dup(source_fd)
    try:
        return _v3_git_objects_pinned(fd, sha)
    finally:
        os.close(fd)


def _v3_write_git_objects(stagefd: int, entries: dict[str, tuple[str, str]], blobs: dict[str, bytes],
                          expected_names: set[str], *, file_modes: dict[str, int] | None = None) -> None:
    """Create only registered included Git objects under anchored directories."""
    for path in sorted(entries, key=lambda value: value.encode("utf-8", "strict")):
        relative = PurePosixPath(path)
        parent = relative.parent.as_posix()
        if parent not in expected_names:
            raise ValueError("Git file parent missing from directory projection")
        fd = _v3_open_relative_directory(stagefd, parent)
        try:
            mode, oid = entries[path]; data = blobs[oid]
            if mode == "120000":
                target = data.decode("utf-8", "strict")
                if not target or os.path.isabs(target):
                    raise ValueError("unsafe Git symlink target")
                os.symlink(target, relative.name, dir_fd=fd)
                created = os.stat(relative.name, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISLNK(created.st_mode) or created.st_nlink != 1:
                    raise ValueError("new candidate symlink has unverified hardlinks")
            else:
                mode_bits = (0o755 if mode == "100755" else 0o644) if file_modes is None else file_modes[path]
                if mode_bits & 0o7000:
                    raise ValueError("source regular file has special permission bits")
                if bool(mode_bits & 0o111) != (mode == "100755"):
                    raise ValueError("source executable bits differ from Git")
                out = os.open(relative.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600 if file_modes is None else mode_bits, dir_fd=fd)
                try:
                    created = os.fstat(out)
                    if not stat.S_ISREG(created.st_mode) or created.st_nlink != 1:
                        raise ValueError("new candidate file has unverified hardlinks")
                    if file_modes is not None and stat.S_IMODE(created.st_mode) != mode_bits:
                        raise ValueError("created file mode differs due to umask or filesystem policy")
                    remaining = memoryview(data)
                    while remaining:
                        written = os.write(out, remaining[:1024 * 1024])
                        if written <= 0:
                            raise OSError("short write while materializing Git object")
                        remaining = remaining[written:]
                    if file_modes is None:
                        os.fchmod(out, mode_bits)
                    after = os.fstat(out)
                    if (not stat.S_ISREG(after.st_mode) or after.st_nlink != 1
                            or (after.st_dev, after.st_ino) != (created.st_dev, created.st_ino)):
                        raise ValueError("candidate file acquired unverified hardlinks")
                    if stat.S_IMODE(after.st_mode) != mode_bits:
                        raise ValueError("candidate file mode changed during writing")
                finally:
                    os.close(out)
        finally:
            os.close(fd)


def _v3_file_modes_digest(source_files: list[dict[str, str]]) -> str:
    """Digest observed regular-file modes; caller must independently pin it."""
    rows = [{"path": item["path"], "mode": item["mode"]} for item in source_files if item["kind"] == "file"]
    return _v3_hash({"schema": "forgeflow.ecp-v3-file-modes.v1", "regular_files": rows})


def _v3_open_relative_directory(rootfd: int, relative: str, *, create: bool = False) -> int:
    """Create/open a stage directory by anchored, no-follow path components."""
    fd = os.dup(rootfd)
    try:
        if relative == ".":
            return fd
        for part in PurePosixPath(_v3_path(relative)).parts:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, mode=0o700, dir_fd=fd)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            old_fd, fd = fd, child
            os.close(old_fd)
        return fd
    except BaseException:
        os.close(fd)
        raise




class V3PublicationUncertain(RuntimeError):
    """A candidate may have been published; no published content was cleaned."""


def materialize_snapshot_v3(source_root: Path, manifest: dict[str, Any], candidate_root: Path, *,
                            candidate_parent_fd: int | None = None,
                            expected_file_modes_sha256: str | None = None) -> dict[str, Any]:
    """Observe a v3 draft; caller owns the parent FD and any external mode pin.

    The optional mode pin is separate from the v3 manifest and cannot prove
    when or by whom it was observed. Without it only Git's standard file
    modes are materialized, preserving the existing fail-closed behavior.
    """
    publication = {"attempted": False}
    try:
        return _materialize_snapshot_v3_impl(source_root, manifest, candidate_root, publication,
                                             candidate_parent_fd=candidate_parent_fd,
                                             expected_file_modes_sha256=expected_file_modes_sha256)
    except BaseException as exc:
        if publication["attempted"]:
            raise V3PublicationUncertain(
                f"candidate may already be published at {str(candidate_root)!r}; no published content was cleaned; {exc}"
            ) from exc
        raise


def _materialize_snapshot_v3_impl(source_root: Path, manifest: dict[str, Any], candidate_root: Path,
                                  publication: dict[str, bool], *, candidate_parent_fd: int | None = None,
                                  expected_file_modes_sha256: str | None = None) -> dict[str, Any]:
    import source_snapshot
    source, source_fd = _v3_open_directory(source_root)
    try:
        destination = Path(os.path.abspath(candidate_root.expanduser()))
        if candidate_parent_fd is None:
            parent, parent_fd = _v3_open_directory(destination.parent)
        else:
            if type(candidate_parent_fd) is not int:
                raise ValueError('candidate parent FD must be an integer')
            flags = fcntl.fcntl(candidate_parent_fd,fcntl.F_GETFL)
            info = os.fstat(candidate_parent_fd)
            if (not stat.S_ISDIR(info.st_mode) or flags & os.O_ACCMODE != os.O_RDONLY or
                    flags & getattr(os,'O_PATH',0o10000000)):
                raise ValueError('candidate parent FD must be a readable directory')
            parent = destination.parent
            parent_fd = os.dup(candidate_parent_fd)
    except BaseException:
        os.close(source_fd)
        raise
    try:
        _v3_assert_output_parent_binding(parent, parent_fd, published=False)
        if _v3_parent_within_source(parent_fd,source_fd) or _v3_parent_mount_aliases_source(source,parent):
            raise ValueError('candidate parent aliases the source tree')
        if destination == source or source in destination.parents or destination in source.parents:
            raise ValueError("candidate and source roots must be disjoint")
        if os.path.lexists(destination):
            raise FileExistsError(f"candidate destination already exists: {destination}")
        if manifest.get("source_root") != str(source):
            raise ValueError("source root does not match v3 manifest")
        expected_dirs, _ = _v3_expected_projection(manifest)
        producer = getattr(source_snapshot, "build_manifest_v3", None)
        if not callable(producer):
            raise ValueError("v3 source manifest producer is unavailable")
        scan_all = manifest.get("untracked_scan_mode") == "all"
        _v3_assert_source_binding(source, source_fd)
        before = producer(source, V3_EXCLUDES, scan_all)
        _v3_assert_source_binding(source, source_fd)
        if before.get("manifest_sha256") != manifest.get("manifest_sha256"):
            raise ValueError("source changed after v3 manifest capture")
        source_dirs, source_files, source_bytes = _v3_inventory(source, trusted_dirfd=source_fd)
        if source_dirs != expected_dirs:
            raise ValueError("source directories differ from v3 projection")
        if expected_file_modes_sha256 is not None:
            if (not isinstance(expected_file_modes_sha256, str)
                    or re.fullmatch(r"[0-9a-f]{64}", expected_file_modes_sha256) is None
                    or _v3_file_modes_digest(source_files) != expected_file_modes_sha256):
                raise ValueError("source file modes differ from independently pinned digest")
        # Inspect immutable Git objects before creating an output tree; paths
        # excluded by the registered policy are never checked out or written.
        entries, blobs = _v3_git_objects(source, manifest["head"], source_fd=source_fd)
        _v3_assert_source_binding(source, source_fd)
        if {item["path"] for item in source_files} != set(entries):
            raise ValueError("projected source files differ from included Git paths")
        for item in source_files:
            git_mode, _ = entries[item["path"]]
            if ((git_mode == "120000" and item["kind"] != "symlink") or
                    (git_mode in {"100644", "100755"} and item["kind"] != "file") or
                    git_mode not in {"100644", "100755", "120000"}):
                raise ValueError("source file type differs from Git")
            if expected_file_modes_sha256 is not None and item["kind"] == "file":
                observed_mode = int(item["mode"], 8)
                if observed_mode & 0o7000:
                    raise ValueError("source regular file has special permission bits")
                if bool(observed_mode & 0o111) != (git_mode == "100755"):
                    raise ValueError("source executable bits differ from Git")
        # Pin the output parent for the entire operation. Paths below its proc
        # fd resolve to that directory even if a concurrent rename occurs.
        pinned_parent = f"/proc/self/fd/{parent_fd}"
        with tempfile.TemporaryDirectory(prefix=f".{destination.name}.stage-", dir=pinned_parent) as temporary:
            stage_parent = Path(temporary)
            stage = stage_parent / "candidate"
            stage_parent_fd = os.open(stage_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.mkdir("candidate", mode=0o700, dir_fd=stage_parent_fd)
                stage_fd = os.open("candidate", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=stage_parent_fd)
                try:
                    expected_names = {row["path"] for row in expected_dirs}
                    for item in sorted(expected_dirs, key=lambda x: (len(PurePosixPath(x["path"]).parts), x["path"])):
                        fd = _v3_open_relative_directory(stage_fd, item["path"], create=True)
                        os.close(fd)
                    if expected_file_modes_sha256 is not None:
                        modes = {item["path"]: int(item["mode"], 8) for item in source_files if item["kind"] == "file"}
                        _v3_write_git_objects(stage_fd, entries, blobs, expected_names, file_modes=modes)
                    else:
                        _v3_write_git_objects(stage_fd, entries, blobs, expected_names)
                    for item in sorted(expected_dirs, key=lambda x: len(PurePosixPath(x["path"]).parts), reverse=True):
                        fd = _v3_open_relative_directory(stage_fd, item["path"])
                        try:
                            os.fchmod(fd, int(item["mode"], 8))
                        finally:
                            os.close(fd)
                    staged_dirs, staged_files, staged_bytes = _v3_inventory(stage, trusted_dirfd=stage_fd,
                                                                           require_single_links=True)
                    if (staged_dirs, staged_files, staged_bytes) != (source_dirs, source_files, source_bytes):
                        raise ValueError("candidate inventory differs from source projection")
                    if _v3_inventory(source, trusted_dirfd=source_fd) != (source_dirs, source_files, source_bytes):
                        raise ValueError("source inventory changed during v3 candidate materialization")
                    after = producer(source, V3_EXCLUDES, scan_all)
                    _v3_assert_source_binding(source, source_fd)
                    if after.get("manifest_sha256") != manifest.get("manifest_sha256"):
                        raise ValueError("source changed during v3 candidate materialization")
                    # Finish every fallible digest and receipt operation before
                    # rename. After the attempt, any exception is reported as
                    # potentially published and never cleans the candidate.
                    receipt = {
                        "status": "OBSERVED_NOT_GATE", "qualification": "NOT_RUN", "product_gate_effect": "NONE",
                        "release_qualifiable": False, "source_root": str(source), "candidate_root": str(destination),
                        "source_manifest_sha256": manifest["manifest_sha256"], "source_projection_sha256": manifest["projection_sha256"],
                        "candidate_inventory_v3_sha256": _v3_hash({"directories": staged_dirs, "files": staged_files}),
                        "candidate_directory_count": len(staged_dirs), "candidate_file_count": len(staged_files),
                        "candidate_tree_bytes": staged_bytes, "excluded_paths": [],
                        "source_unchanged": True, "git_metadata_removed": True,
                        "source_unchanged_scope": "producer manifest digests matched before and after; excluded content and atomicity are not established",
                        "file_comparison_scope": "one physical source scan matched candidate hashes, types and modes; candidate was built from Git blobs with object IDs rechecked",
                        "file_mode_binding_scope": "regular file modes were compared in live source scans, not bound by the v3 manifest or continuous identity",
            "candidate_parent_fd_bound": candidate_parent_fd is not None,
            "candidate_parent_binding_scope": "parent descriptor and user-visible path were compared; checks are not atomic",
                        "git_output_capture": "OBJECT_DATA_BOUNDED; STDERR_DISCARDED_UNAVAILABLE",
                        "limitations": ["non-atomic source observation and output path checks", "Git raw stderr unavailable", "Git internal resource use and descendant stop not independently constrained", "no hardlink, ACL, xattr, uid, gid, timestamp or mount equivalence", "not independent execution or release evidence"],
                    }
                    if expected_file_modes_sha256 is not None:
                        receipt["external_file_modes_sha256"] = expected_file_modes_sha256
                    _v3_assert_output_parent_binding(parent, parent_fd, published=False)
                    publication["attempted"] = True
                    try:
                        _v3_publish_noreplace(stage_parent_fd, parent_fd, destination.name)
                    except OSError as exc:
                        # renameat2 explicitly reports these errors without
                        # replacing either source or destination.
                        if exc.errno in (errno.EEXIST, errno.ENOTEMPTY):
                            publication["attempted"] = False
                        raise
                    _v3_assert_output_parent_binding(parent, parent_fd, published=True)
                    _v3_assert_published_candidate(parent_fd, destination.name, stage_fd)
                    published_inventory = _v3_inventory(destination, trusted_dirfd=stage_fd, require_single_links=True)
                    if published_inventory != (staged_dirs, staged_files, staged_bytes):
                        raise RuntimeError("candidate inventory changed after publication")
                    _v3_assert_published_candidate(parent_fd, destination.name, stage_fd)
                    _v3_assert_output_parent_binding(parent, parent_fd, published=True)
                finally:
                    os.close(stage_fd)
            finally:
                os.close(stage_parent_fd)
        return receipt
    finally:
        try:
            os.close(parent_fd)
        finally:
            os.close(source_fd)
