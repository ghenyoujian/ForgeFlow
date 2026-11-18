#!/usr/bin/env python3
"""Create a deterministic, non-mutating manifest for a ForgeFlow source tree.

This entry point identifies source bytes and filesystem entries; it does not
materialize an isolated source copy. P0-01 still needs a separate candidate
materialization step that copies the exact included files without modifying the
user worktree, then re-hashes and verifies that copy before admission.
"""
from __future__ import annotations

import argparse
from contextvars import ContextVar
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import time
from pathlib import Path, PurePosixPath
import subprocess
from typing import Iterable

SCHEMA = "forgeflow.ecp-source-manifest.v2"
# Business files under these roots must be frozen even when their parent
# directory is already tracked.  Generated trees remain excluded below.
EXPAND_UNTRACKED_PREFIXES = (
    "ops/ecp/",
    "verification/",
    "contracts/ecp/",
    "docs/ecp/",
    ".github/workflows/",
    "deploy/",
    "console/",
    "crates/",
    "migrations/",
    "benchmarks/ecp/",
)
MAX_UNTRACKED_SCAN_ENTRIES = 400_000
_V3_BOUNDED_GIT = ContextVar('forgeflow_v3_bounded_git', default=False)
_V3_TOTAL_DEADLINE = ContextVar('forgeflow_v3_total_deadline', default=None)
_V3_PINNED_ROOT = ContextVar('forgeflow_v3_pinned_root', default=None)


class P001SupervisionUnavailable(RuntimeError):
    """P001 v3 process execution has not been admitted."""

DEFAULT_EXCLUDES = (
    ".git/",
    ".local/",
    ".env",
    "target/",
    "node_modules/",
    "**/node_modules/",
    "console/node_modules/",
    "console/dist/",
    "console/test-results/",
    "console/playwright-report/",
    ".pytest_cache/",
    "evidence/",
    "audit/",
    "benchmarks/evidence/",
    "crates/executors/qualification/",
    "crates/**/evidence/",
    "verification/evidence/",
    # A legacy run wrote planning evidence inside control/docs/idea. Preserve
    # that history, but do not classify those receipts as new business source.
    "docs/idea/ForgeFlow_ECP_完整开发规划/evidence/",
    "*.log",
    "*.png",
    "*.tar.gz",
    "__pycache__/",
    "*/__pycache__/",
    "*.pyc",
)

# v3 policy version is independent of the historical v2 list. A filename
# extension alone cannot establish that a file is disposable evidence.
V3_EXCLUDES = (
    ".git/",
    ".local/",
    ".env",
    "target/",
    "node_modules/",
    "console/node_modules/",
    "console/dist/",
    "console/test-results/",
    "console/playwright-report/",
    ".pytest_cache/",
    "evidence/",
    "audit/",
    "benchmarks/evidence/",
    "crates/executors/qualification/",
    "verification/evidence/",
    "docs/idea/ForgeFlow_ECP_完整开发规划/evidence/",
    "__pycache__/",
)


def _bounded_timeout(default: float = 30.0) -> float:
    """Return the caller's bounded snapshot deadline.

    The ECP verifier runs against worktrees that may contain tens of thousands
    of generated entries.  A fixed two minute subprocess timeout made the
    offline ``doctor`` command appear hung.  Keep the normal standalone
    snapshot useful, but let the verifier impose its shorter deadline through
    the same environment variable it uses for Git status.
    """
    raw = os.environ.get("ECP_SOURCE_SNAPSHOT_TIMEOUT_SECONDS")
    if raw is None:
        raw = os.environ.get("ECP_GIT_STATUS_TIMEOUT_SECONDS")
    try:
        value = float(raw) if raw is not None else default
    except ValueError:
        value = default
    result = min(max(value, 0.1), 120.0)
    deadline = _V3_TOTAL_DEADLINE.get()
    if deadline is not None:
        result = min(result, max(0.0, deadline - time.monotonic()))
    return result


def _v3_bounded_git(root: Path, args: list[str], timeout: float) -> bytes:
    """Block v3 Git execution until supervision is verified."""
    raise P001SupervisionUnavailable("v3 Git blocked: process supervision is not verified")
    command = ["/usr/bin/git", *args]
    if timeout <= 0:
        raise subprocess.TimeoutExpired(command, timeout)
    root_fd = _v3_open_root(root)
    try:
        allowed = ("HOME", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "USER")
        environment = {key: os.environ[key] for key in allowed if key in os.environ}
        environment.update({"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                            "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_OPTIONAL_LOCKS": "0",
                            "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
                            "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "file",
                            "GIT_ATTR_NOSYSTEM": "1", "GIT_CONFIG_COUNT": "5",
                            "GIT_CONFIG_KEY_0": "core.fsmonitor", "GIT_CONFIG_VALUE_0": "false",
                            "GIT_CONFIG_KEY_1": "core.hooksPath", "GIT_CONFIG_VALUE_1": "/dev/null",
                            "GIT_CONFIG_KEY_2": "core.attributesFile", "GIT_CONFIG_VALUE_2": "/dev/null",
                            "GIT_CONFIG_KEY_3": "core.excludesFile", "GIT_CONFIG_VALUE_3": "/dev/null",
                            "GIT_CONFIG_KEY_4": "diff.external", "GIT_CONFIG_VALUE_4": ""})
        # /proc/self/fd is resolved in the child before exec; retaining the
        # opened root prevents cwd from following a swapped ancestor symlink.
        process = subprocess.Popen(command, cwd=f"/proc/self/fd/{root_fd}", pass_fds=(root_fd,), env=environment,
                                   stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    finally:
        os.close(root_fd)
    selector = None
    stdout = bytearray()
    stderr = bytearray()
    limits = {process.stdout: V3_MAX_GIT_METADATA_BYTES, process.stderr: 64 * 1024}
    streams = {process.stdout: stdout, process.stderr: stderr}
    deadline = time.monotonic() + timeout
    try:
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        selector.register(process.stderr, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            for key, _ in selector.select(remaining):
                stream = key.fileobj
                budget = limits[stream] - len(streams[stream])
                block = os.read(stream.fileno(), min(65536, budget + 1))
                if not block:
                    selector.unregister(stream)
                    continue
                if len(block) > budget:
                    raise ValueError("v3 Git output exceeds bounded stream budget")
                streams[stream].extend(block)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, timeout)
        try:
            code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise subprocess.TimeoutExpired(command, timeout) from None
        if code:
            raise subprocess.CalledProcessError(code, command, bytes(stdout), bytes(stderr))
        return bytes(stdout)
    except BaseException:
        # A PID already reaped by wait() can be reused by an unrelated group.
        # Only signal while Popen still owns the unreaped child PID.
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                # Signal failure does not prove the child stopped; always try
                # a bounded wait before classifying the termination state.
                pass
            try:
                process.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                # Never report a successful observation when termination cannot
                # be confirmed; no unrelated process group is touched.
                raise RuntimeError("v3 Git process termination could not be confirmed") from None
        raise
    finally:
        if selector is not None:
            selector.close()
        process.stdout.close()
        process.stderr.close()


def run_git(root: Path, args: list[str], timeout: float | None = None) -> bytes:
    if _V3_BOUNDED_GIT.get():
        return _v3_bounded_git(root, args, _bounded_timeout() if timeout is None else timeout)
    completed = subprocess.run(
        ["git", *args], cwd=root, capture_output=True,
        timeout=_bounded_timeout() if timeout is None else timeout, check=True,
    )
    return completed.stdout


def matches_exclude(path: str, patterns: Iterable[str]) -> str | None:
    from fnmatch import fnmatch
    for pattern in patterns:
        if pattern.endswith("/"):
            # A directory exclusion applies to its descendants as well, even
            # when the directory pattern contains a glob such as **/.
            parts = path.rstrip('/').split('/')
            if any(fnmatch('/'.join(parts[:end]), pattern[:-1]) for end in range(1, len(parts) + 1)):
                return pattern
        if fnmatch(path, pattern):
            return pattern
    return None


def v3_excluded(path: str, kind: str) -> str | None:
    """Match fixed v3 boundaries using the observed entry type.

    Git's worktree marker and the private .env file are explicit exceptions.
    A directory rule does not exclude an ordinary file with the same name.
    Callers must reject a symlink that matches a boundary at its own path.
    """
    return _v3_excluded_for_policy(path, kind, V3_EXCLUDES)


def _v3_validate_exclusion_policy(patterns: tuple[str, ...]) -> tuple[str, ...]:
    """Accept only unambiguous subsets of the registered literal boundaries.

    The manifest producer still requires the complete fixed V3_EXCLUDES list;
    private observation helpers may use a smaller explicitly ordered policy.
    """
    if not isinstance(patterns, (list, tuple)) or len(patterns) > len(V3_EXCLUDES):
        raise ValueError("unsupported v3 exclusion policy")
    policy = tuple(patterns)
    if (any(not isinstance(pattern, str) or pattern not in V3_EXCLUDES for pattern in policy)
            or len(set(policy)) != len(policy)):
        raise ValueError("unsupported v3 exclusion policy")
    return policy


def _v3_excluded_for_policy(path: str, kind: str, patterns: tuple[str, ...]) -> str | None:
    """Apply an already-validated ordered policy using observed entry type."""
    if kind not in ("file", "directory", "symlink"):
        raise ValueError("unsupported v3 entry kind")
    path = path.rstrip("/")
    for pattern in patterns:
        if pattern == ".env":
            if path == ".env" and kind != "directory":
                return pattern
        elif pattern == ".git/" and path == ".git":
            return pattern
        elif pattern.endswith("/"):
            boundary = pattern[:-1]
            if path.startswith(boundary + "/") or (path == boundary and kind != "file"):
                return pattern
    return None


def _v3_require_boundary_directory(root_fd: int, pattern: str, *, deadline: float) -> None:
    """Observe each excluded Git ancestor twice through no-follow directory FDs."""
    if not pattern.endswith("/"):
        return
    identities = []
    device = os.fstat(root_fd).st_dev
    for observation in range(2):
        fd = os.dup(root_fd)
        try:
            for index, component in enumerate(pattern[:-1].split("/")):
                if time.monotonic() >= deadline:
                    raise TimeoutError("v3 excluded directory verification exceeded deadline")
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                old_fd, fd = fd, child
                os.close(old_fd)
                if time.monotonic() >= deadline:
                    raise TimeoutError("v3 excluded directory verification exceeded deadline")
                info = os.fstat(fd)
                if info.st_dev != device:
                    raise ValueError("excluded boundary crosses a filesystem boundary")
                identity = (info.st_dev, info.st_ino)
                if observation == 0:
                    identities.append(identity)
                elif identity != identities[index]:
                    raise ValueError("excluded boundary changed between observations")
                if time.monotonic() >= deadline:
                    raise TimeoutError("v3 excluded directory verification exceeded deadline")
        finally:
            os.close(fd)


def sha256_file(path: Path) -> str | None:
    """Hash a regular file without following links; symlink bytes are its target text.

    A source manifest identifies the filesystem entry itself as well as file
    content. Following a symlink here made a link indistinguishable from a
    regular file with the same bytes and failed to bind the path it referenced.
    """
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        return hashlib.sha256(os.fsencode(os.readlink(path))).hexdigest()
    if not stat.S_ISREG(info.st_mode):
        raise OSError(f"source entry is not a regular file or symlink: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_entry(root: Path, relative: str, status: str) -> dict:
    """Return a stable identity for one source file or symlink."""
    absolute = root / relative
    if "D" in status:
        # A tracked deletion has no current filesystem entry. HEAD plus the
        # binary diff identified by patch_sha256 is the materialization input.
        return {
            "path": relative,
            "status": status,
            "kind": "deleted",
            "mode": None,
            "sha256": None,
        }
    info = absolute.lstat()
    mode = stat.S_IMODE(info.st_mode)
    if stat.S_ISLNK(info.st_mode):
        target = os.readlink(absolute)
        return {
            "path": relative,
            "status": status,
            "kind": "symlink",
            "mode": f"{mode:04o}",
            "target": target,
            "sha256": hashlib.sha256(os.fsencode(target)).hexdigest(),
        }
    if stat.S_ISDIR(info.st_mode):
        # In bounded mode, an untracked directory outside declared business
        # roots remains a summary entry. Such a manifest is DIRTY_UNFROZEN and
        # cannot qualify a release; scan-all mode expands it into file records.
        return {
            "path": relative,
            "status": status,
            "kind": "directory_summary",
            "mode": f"{mode:04o}",
            "sha256": None,
        }
    if not stat.S_ISREG(info.st_mode):
        raise OSError(f"source entry is not a regular file or symlink: {absolute}")
    return {
        "path": relative,
        "status": status,
        "kind": "file",
        "mode": f"{mode:04o}",
        "sha256": sha256_file(absolute),
    }


def status_entries(root: Path, scan_all_untracked: bool = False) -> list[tuple[str, str]]:
    mode = "all" if scan_all_untracked else "no"
    raw = run_git(root, ["status", "--porcelain=v1", "-z", f"--untracked-files={mode}"])
    entries: list[tuple[str, str]] = []
    fields = raw.decode("utf-8", errors="surrogateescape").split("\0")
    index = 0
    while index < len(fields):
        item = fields[index]
        index += 1
        if not item:
            continue
        # Porcelain v1 -z begins with exactly two status bytes, then one
        # delimiter. Splitting on the first space breaks statuses such as
        # " M" (the common worktree-only modification case) and file names
        # beginning with a space.
        if len(item) < 4 or item[2] != " ":
            raise ValueError(f"malformed git status entry: {item!r}")
        status, value = item[:2], item[3:]
        entries.append((status, value))
        # With -z, rename/copy records carry a second NUL-delimited source
        # path. The first path is the destination whose contents are current.
        if "R" in status or "C" in status:
            if index >= len(fields) or not fields[index]:
                raise ValueError(f"rename/copy status lacks source path: {item!r}")
            index += 1
    return entries


def tracked_paths(root: Path) -> set[str]:
    raw = run_git(root, ["ls-files", "-z"])
    return {value for value in raw.decode("utf-8", errors="surrogateescape").split("\0") if value}


def index_visibility(root: Path, tracked: set[str]) -> list[dict]:
    """Reject index shortcuts and gitlinks that prevent a complete source claim."""
    raw = run_git(root, ["ls-files", "-v", "-z"])
    flags: list[dict] = []
    seen: list[str] = []
    for item in raw.decode("utf-8", errors="surrogateescape").split("\0"):
        if not item:
            continue
        if len(item) < 3 or item[1] != " ":
            raise ValueError("malformed Git index visibility entry")
        tag, path = item[0], item[2:]
        seen.append(path)
        if tag.islower() or tag.upper() == "S":
            flags.append({"path": path, "assume_unchanged": tag.islower(),
                          "skip_worktree": tag.upper() == "S"})
    if len(seen) != len(tracked) or set(seen) != tracked:
        raise ValueError("incomplete or ambiguous Git index visibility listing")
    raw_stage = run_git(root, ["ls-files", "--stage", "-z"])
    stage_paths: list[str] = []
    for item in raw_stage.decode("utf-8", errors="surrogateescape").split("\0"):
        if not item:
            continue
        metadata, separator, path = item.partition("\t")
        fields = metadata.split(" ")
        if not separator or len(fields) != 3 or fields[2] != "0":
            raise ValueError("unmerged or malformed Git index stage entry")
        stage_paths.append(path)
        if fields[0] == "160000":
            flags.append({"path": path, "gitlink": True})
    if len(stage_paths) != len(tracked) or set(stage_paths) != tracked:
        raise ValueError("incomplete or ambiguous Git index stage listing")
    return flags


def ignored_paths(root: Path, paths: list[str]) -> set[str]:
    """Return paths excluded by Git ignore rules in one NUL-safe subprocess."""
    if not paths:
        return set()
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", "-z", "--stdin"],
        cwd=root,
        input="\0".join(paths).encode("utf-8", errors="surrogateescape") + b"\0",
        capture_output=True,
        check=False,
    )
    if result.returncode not in (0, 1):
        raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)
    return {
        value.decode("utf-8", errors="surrogateescape")
        for value in result.stdout.split(b"\0")
        if value
    }


def _bounded_walk(root: Path, start: Path, patterns: tuple[str, ...], counter: list[int],
                  deadline: float | None) -> Iterable[tuple[Path, bool]]:
    """Stream bounded entries, opening each directory beneath an anchored FD."""
    pending = [start.relative_to(root)]
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        while pending:
            relative_dir = pending.pop()
            directory_fd = os.dup(root_fd)
            try:
                for part in relative_dir.parts:
                    child_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
                    os.close(directory_fd)
                    directory_fd = child_fd
                with os.scandir(directory_fd) as entries:
                    for entry in entries:
                        counter[0] += 1
                        if counter[0] > MAX_UNTRACKED_SCAN_ENTRIES:
                            raise ValueError("untracked source scan entry budget exceeded")
                        if deadline is not None and time.monotonic() >= deadline:
                            raise TimeoutError("bounded source scan exceeded its deadline")
                        relative = (relative_dir / entry.name).as_posix()
                        is_directory = entry.is_dir(follow_symlinks=False)
                        if is_directory:
                            if matches_exclude(relative + '/', patterns):
                                continue
                            pending.append(relative_dir / entry.name)
                        elif matches_exclude(relative, patterns) or (entry.is_symlink() and matches_exclude(relative + '/', patterns)):
                            continue
                        yield root / relative_dir / entry.name, is_directory
            finally:
                os.close(directory_fd)
    finally:
        os.close(root_fd)


def bounded_untracked_paths(
    root: Path,
    tracked: set[str],
    patterns: Iterable[str],
    include_git_ignored: bool = True,
    deadline: float | None = None,
) -> tuple[list[tuple[str, str]], set[str]]:
    """Enumerate untracked entries across the source tree, pruning excluded trees.

    The prior scanner walked only a fixed list of roots, missing root build
    inputs and new business directories. This walk is bounded by the explicit
    exclusion contract. Git ignore rules are not source exclusions: ignored
    business/build inputs are included unless an explicit generated/private
    path exclusion prunes them.
    """
    results: list[tuple[str, str]] = []
    patterns = tuple(patterns)
    candidates: list[str] = []
    counter = [0]
    tracked_dirs = {parent.as_posix() for path in tracked for parent in PurePosixPath(path).parents} - {'.'}
    untracked_dirs: set[str] = set()
    for child, is_directory in _bounded_walk(root, root, patterns, counter, deadline):
        relative = child.relative_to(root).as_posix()
        if is_directory:
            if relative not in tracked_dirs:
                untracked_dirs.add(relative)
        elif relative not in tracked:
            candidates.append(relative)
    # Keep the legacy flag accepted for callers, but never let .gitignore or
    # global excludes silently erase source inputs from an otherwise CLEAN
    # manifest. The explicit ECP exclusion list is the sole omission policy.
    results.extend(("??", relative) for relative in candidates)
    # A directory can affect build scripts even when Git ignores it because it
    # is empty or contains only excluded artifacts. Do not qualify such input
    # as clean or pretend that a materialized file captures its existence.
    for path in candidates:
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("untracked source scan exceeded its deadline")
        for parent in PurePosixPath(path).parents:
            untracked_dirs.discard(parent.as_posix())
    unrepresented_dirs = untracked_dirs
    results.extend(("??", relative) for relative in sorted(unrepresented_dirs))
    return results, unrepresented_dirs


def expand_untracked_directories(
    root: Path,
    entries: list[tuple[str, str]],
    patterns: Iterable[str],
    deadline: float | None = None,
    preserve_directories: set[str] | None = None,
) -> list[tuple[str, str]]:
    expanded: list[tuple[str, str]] = []
    counter = [0]
    patterns = tuple(patterns)
    for status, relative in entries:
        absolute = root / relative
        if status == "??" and absolute.is_dir() and not absolute.is_symlink() and not matches_exclude(relative, patterns):
            if preserve_directories is not None and relative in preserve_directories:
                expanded.append((status, relative))
                continue
            if not any(relative == prefix.rstrip("/") or relative.startswith(prefix) for prefix in EXPAND_UNTRACKED_PREFIXES):
                expanded.append((status, relative))
                continue
            start = len(expanded)
            for child, is_directory in _bounded_walk(root, absolute, patterns, counter, deadline):
                if not is_directory:
                    expanded.append(("??", child.relative_to(root).as_posix()))
            if len(expanded) == start:
                expanded.append((status, relative))
            continue
        expanded.append((status, relative))
    return expanded


def build_manifest(root: Path, excludes: Iterable[str], scan_all_untracked: bool = False) -> dict:
    root = root.resolve()
    deadline = time.monotonic() + _bounded_timeout()
    patterns = tuple(excludes)
    head = run_git(root, ["rev-parse", "HEAD"]).decode().strip()
    tracked = tracked_paths(root)
    scan_error: str | None = None
    visibility: list[dict] = []
    unrepresented_dirs: set[str] = set()
    try:
        entries = status_entries(root, scan_all_untracked=scan_all_untracked)
        visibility = index_visibility(root, tracked)
        if visibility:
            scan_error = "index has assume-unchanged, skip-worktree, or submodule entries; source inventory is incomplete"
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as exc:
        # A large WSL worktree may not finish Git's index refresh before the
        # verifier deadline.  That is evidence of a dirty/unfrozen source, not
        # a reason to make ``doctor`` hang or to misreport the tree as clean.
        entries = []
        scan_error = f"status inventory unavailable: {exc}"
    if scan_error is None:
        try:
            extra_entries, unrepresented_dirs = bounded_untracked_paths(
                root, tracked, patterns, include_git_ignored=True, deadline=deadline
            )
            entries.extend(extra_entries)
        except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as exc:
            scan_error = f"untracked inventory unavailable: {exc}"
    entries = list({relative: status for status, relative in reversed(entries)}.items())
    entries = [(status, relative) for relative, status in entries]
    if scan_error is None:
        try:
            entries = expand_untracked_directories(root, entries, patterns, deadline=deadline,
                                                    preserve_directories=unrepresented_dirs)
        except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as exc:
            scan_error = f"untracked expansion unavailable: {exc}"
    tracked: list[dict] = []
    untracked: list[dict] = []
    excluded: list[dict] = []
    for status, relative in sorted(entries, key=lambda item: item[1]):
        reason = matches_exclude(relative, patterns)
        if reason:
            excluded.append({"path": relative, "status": status, "reason": reason})
            continue
        absolute = root / relative
        record = source_entry(root, relative, status)
        if status == "??":
            untracked.append(record)
        else:
            tracked.append(record)
    if scan_error is None:
        try:
            patch = run_git(root, ["diff", "--binary", "HEAD", "--"])
        except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as exc:
            patch = f"PATCH_UNAVAILABLE:{exc}".encode("utf-8", errors="replace")
            scan_error = f"patch unavailable: {exc}"
    else:
        patch = f"PATCH_UNAVAILABLE:{scan_error}".encode("utf-8", errors="replace")
    if scan_error is not None:
        # Preserve the conservative state even when the incomplete inventory
        # contains no individual rows.  A partial manifest is useful for
        # diagnosis but can never qualify a release.
        entries_dirty = True
    else:
        entries_dirty = bool(entries)
    core = {
        "schema_version": SCHEMA,
        "source_root": str(root),
        "head": head,
        "worktree_state": "CLEAN" if not entries_dirty else "DIRTY_UNFROZEN",
        "inventory_complete": scan_error is None,
        "inventory_error": scan_error,
        "index_visibility_exceptions": visibility,
        "exclude_patterns": list(patterns),
        "untracked_scan_mode": "all" if scan_all_untracked else "bounded",
        "untracked_scan_roots": list(EXPAND_UNTRACKED_PREFIXES),
        "tracked_changes": tracked,
        "untracked_business_files": untracked,
        "excluded_generated_files": excluded,
        "patch_sha256": hashlib.sha256(patch).hexdigest(),
    }
    canonical = json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return {
        **core,
        "manifest_sha256": hashlib.sha256(canonical).hexdigest(),
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "release_qualifiable": core["worktree_state"] == "CLEAN",
    }



V3_SCHEMA = "forgeflow.ecp-source-manifest.v3"
V3_DIRECTORY_PROJECTION = "forgeflow.ecp-directory-projection.v1"
V3_MAX_DIRECTORIES = 100_000
V3_MAX_JSON_BYTES = 16 * 1024 * 1024
V3_MAX_SCAN_IDENTITY_BYTES = 16 * 1024 * 1024
V3_MAX_TRACKED_BYTES = 512 * 1024 * 1024
V3_MAX_TRACKED_FILE_BYTES = 64 * 1024 * 1024
V3_MAX_GIT_METADATA_BYTES = 16 * 1024 * 1024


def _v3_canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8", errors="strict")


def _v3_signature(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _v3_open_root_by_path(path: Path) -> int:
    """Open an absolute root without following symlinks in any component."""
    path = Path(os.path.abspath(path))
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _v3_open_root(path: Path) -> int:
    """Duplicate the invocation's pinned root when one is active."""
    pinned = _V3_PINNED_ROOT.get()
    if pinned is None:
        return _v3_open_root_by_path(path)
    expected, fd = pinned
    if os.path.abspath(path) != expected:
        raise ValueError("v3 invocation attempted an unexpected source root")
    return os.dup(fd)


def _v3_mount_status(root: Path) -> tuple[str, tuple[str, str]]:
    """Conservatively identify mode reliability and reject nested mounts."""
    selected = ("", "", "")
    mounts = []
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        left, separator, right = line.partition(" - ")
        fields, after = left.split(), right.split()
        if not separator or len(fields) < 5 or not after:
            raise ValueError("malformed mount inventory")
        mount = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), fields[4])
        mounts.append(mount)
        if (str(root) == mount or str(root).startswith(mount.rstrip("/") + "/")) and len(mount) > len(selected[0]):
            selected = (mount, after[0], line)
    if not selected[0]:
        raise ValueError("source filesystem mount is unknown")
    pinned = _V3_PINNED_ROOT.get()
    if pinned is not None:
        expected, root_fd = pinned
        if os.path.abspath(root) != expected or os.readlink(f'/proc/self/fd/{root_fd}') != expected:
            raise ValueError("v3 source root name changed during observation")
        fdinfo = Path(f'/proc/self/fdinfo/{root_fd}').read_text(encoding='ascii')
        mount_ids = [line.split(':', 1)[1].strip() for line in fdinfo.splitlines() if line.startswith('mnt_id:')]
        if len(mount_ids) != 1 or mount_ids[0] != selected[2].split()[0]:
            raise ValueError("v3 source root mount identity is unavailable or changed")
    if any(mount.startswith(str(root).rstrip("/") + "/") for mount in mounts):
        raise ValueError("source tree contains a nested mount")
    # Retain the entire selected mountinfo entry, including mount ID, root,
    # source and options, for pre/post comparison even on the same filesystem.
    return ("VERIFIED" if selected[1] in ("ext2", "ext3", "ext4", "xfs", "btrfs", "tmpfs", "overlay", "zfs")
            else "UNAVAILABLE", (selected[1], selected[2]))


def _v3_checked_path(path: str) -> None:
    if (not path or len(path) > 4096 or path.startswith("/") or "\\" in path
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in path)
            or any(part in ("", ".", "..") for part in path.split("/"))):
        raise ValueError("unsafe projected source path")
    path.encode("utf-8", errors="strict")


def _v3_scan_projection(root: Path, tracked: set[str], patterns: tuple[str, ...],
                        mode_status: str, deadline: float) -> tuple[dict, dict]:
    """Observe non-excluded directories; never recurse into excluded trees.

    Identity observations are returned separately for two-scan comparison;
    they are not a claim of an atomic filesystem snapshot.
    """
    patterns = _v3_validate_exclusion_policy(patterns)
    root_fd = _v3_open_root(root)
    root_info = os.fstat(root_fd)
    directories = {".": _v3_signature(root_info)}
    boundaries = {}
    file_signatures = {}
    children = {".": []}
    git_dirs = set()
    for path in tracked:
        _v3_checked_path(path)
        if not _v3_excluded_for_policy(path, "file", patterns):
            git_dirs.update(parent.as_posix() for parent in PurePosixPath(path).parents if parent.as_posix() != ".")
    pending = [(".", _v3_signature(root_info))]
    visited = 0
    identity_bytes = 0
    try:
        while pending:
            relative_dir, expected = pending.pop()
            if time.monotonic() >= deadline:
                raise TimeoutError("v3 source projection scan exceeded deadline")
            fd = os.dup(root_fd)
            try:
                if relative_dir != ".":
                    for component in relative_dir.split("/"):
                        child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        os.close(fd)
                        fd = child
                if _v3_signature(os.fstat(fd)) != expected:
                    raise ValueError("projected directory changed before opening")
                with os.scandir(fd) as entries:
                    for entry in entries:
                        visited += 1
                        if visited > MAX_UNTRACKED_SCAN_ENTRIES or time.monotonic() >= deadline:
                            raise ValueError("v3 source projection scan budget exceeded")
                        path = entry.name if relative_dir == "." else relative_dir + "/" + entry.name
                        _v3_checked_path(path)
                        # Account conservatively for stored names and metadata,
                        # not merely entry count, before growing scan maps.
                        identity_bytes += len(path.encode("utf-8")) + 256
                        if identity_bytes > V3_MAX_SCAN_IDENTITY_BYTES:
                            raise ValueError("v3 source projection identity budget exceeded")
                        info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                        signature = _v3_signature(info)
                        if info.st_dev != root_info.st_dev:
                            raise ValueError("projected source crosses a filesystem boundary")
                        if stat.S_ISDIR(info.st_mode):
                            exclusion = _v3_excluded_for_policy(path, "directory", patterns)
                            if exclusion:
                                boundaries[path] = (exclusion, signature)
                                children[relative_dir].append(("boundary", path))
                            else:
                                directories[path] = signature
                                children[path] = []
                                children[relative_dir].append(("directory", path))
                                pending.append((path, signature))
                        elif stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                            exclusion = _v3_excluded_for_policy(path, "symlink" if stat.S_ISLNK(info.st_mode) else "file", patterns)
                            if stat.S_ISLNK(info.st_mode) and exclusion:
                                raise ValueError("excluded source path is a symlink, not an excluded boundary")
                            file_signatures[path] = signature
                            children[relative_dir].append(("file", path))
                        else:
                            raise ValueError("unsupported source entry in projection")
                if _v3_signature(os.fstat(fd)) != expected:
                    raise ValueError("projected directory changed during scan")
            finally:
                os.close(fd)
        if _v3_signature(os.fstat(root_fd)) != directories["."]:
            raise ValueError("source root changed during scan")
    finally:
        os.close(root_fd)
    if len(directories) > V3_MAX_DIRECTORIES or len(boundaries) > V3_MAX_DIRECTORIES:
        raise ValueError("v3 projected directory count exceeds contract budget")
    origins = {".": "source_root"}
    for path in sorted((p for p in directories if p != "."), key=lambda p: (-p.count("/"), p.encode("utf-8"))):
        if path in git_dirs:
            origins[path] = "git_ancestor"
        else:
            child_entries = children[path]
            only_containers = all(kind == "boundary" or (kind == "directory" and origins[name] == "excluded_container")
                                  for kind, name in child_entries)
            origins[path] = "excluded_container" if child_entries and only_containers else "untracked_business"
    rows = [{"path": path, "kind": "directory",
             "mode": f"{stat.S_IMODE(info[2]):04o}" if mode_status == "VERIFIED" else None,
             "origin": origins[path]}
            for path, info in sorted(directories.items(), key=lambda item: item[0].encode("utf-8"))]
    excluded = [{"path": path, "kind": "directory", "excluded_by": value[0]}
                for path, value in sorted(boundaries.items(), key=lambda item: item[0].encode("utf-8"))]
    projection = {"version": V3_DIRECTORY_PROJECTION, "mode_availability": mode_status,
                  "exclusion_policy_sha256": hashlib.sha256(_v3_canonical(list(patterns))).hexdigest(),
                  "directories": rows, "excluded_directory_boundaries": excluded}
    signatures = {"directories": directories, "boundaries": boundaries, "files": file_signatures}
    return projection, signatures


def _v3_verify_index_bytes(root: Path, tracked: set[str], patterns: tuple[str, ...],
                           mode_status: str, head: str, deadline: float,
                           expected_index: bytes | None = None, *,
                           _collect_supplement: bool = False):
    """Read included tracked files and compare raw Git blob IDs to the index.

    Git status alone can trust stat metadata even if bytes differ; transformed
    checkout/filter bytes also cannot be asserted equal to raw Git objects.
    The private optional tuple contains unbound rows for the enclosing scan;
    it is not a complete supplement or any success/qualification assertion.
    """
    patterns = _v3_validate_exclusion_policy(patterns)
    if len(head) not in (40, 64) or not re.fullmatch(r"[0-9a-f]+", head):
        raise ValueError("v3 source head is not a Git object ID")
    hasher = hashlib.sha1 if len(head) == 40 else hashlib.sha256
    raw_index = run_git(root, ["ls-files", "--stage", "-z"])
    if expected_index is not None and raw_index != expected_index:
        raise ValueError("v3 Git index changed before blob verification")
    if len(raw_index) > V3_MAX_GIT_METADATA_BYTES or raw_index.count(b"\0") > V3_MAX_DIRECTORIES:
        raise ValueError("v3 Git index exceeds verification budget")
    records = raw_index.split(b"\0")
    entries = {}
    for row in records:
        if not row:
            continue
        metadata, separator, raw_path = row.partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3 or fields[2] != b"0":
            raise ValueError("v3 source index contains malformed or unmerged records")
        path = raw_path.decode("utf-8", errors="strict")
        _v3_checked_path(path)
        mode, oid = fields[0].decode("ascii"), fields[1].decode("ascii")
        if path in entries or mode not in ("100644", "100755", "120000") or not re.fullmatch(r"[0-9a-f]{%d}" % len(head), oid):
            raise ValueError("v3 source index has an unsupported entry")
        entries[path] = (mode, oid)
    if set(entries) != tracked:
        raise ValueError("v3 source index changed during inventory")
    # A whole-tree observer must not accidentally read the private root .env
    # file, even when the caller requests zero exclusions. A tracked business
    # directory such as .env/input.txt is a different path and remains visible.
    if ".env" in entries and not _v3_excluded_for_policy(".env", "file", patterns):
        raise ValueError("private root .env cannot be verified without exclusion")
    root_fd = _v3_open_root(root)
    total = 0
    signatures = {}
    supplement = []
    try:
        for path, (mode, oid) in sorted(entries.items(), key=lambda item: item[0].encode("utf-8")):
            if time.monotonic() >= deadline:
                raise TimeoutError("v3 tracked blob verification exceeded deadline")
            excluded = _v3_excluded_for_policy(path, "file", patterns)
            if mode == "120000" and (path == ".env" or (not excluded and _v3_excluded_for_policy(path, "symlink", patterns))):
                raise ValueError("excluded source path is a symlink, not an excluded boundary")
            if excluded:
                _v3_require_boundary_directory(root_fd, excluded, deadline=deadline)
                continue
            parent = os.dup(root_fd)
            try:
                parts = path.split("/")
                for component in parts[:-1]:
                    child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    os.close(parent)
                    parent = child
                info = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                if mode == "120000":
                    if not stat.S_ISLNK(info.st_mode):
                        raise ValueError("tracked symlink is not a symlink")
                    target = os.readlink(parts[-1], dir_fd=parent)
                    content = os.fsencode(target)
                    size = len(content)
                    if _collect_supplement and (not target or target.startswith('/') or '\\' in target or
                            '\0' in target or len(content) > 4096 or
                            content.decode('utf-8', 'strict').encode('utf-8') != content):
                        raise ValueError('unsupported symlink target')
                    if _v3_signature(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)) != _v3_signature(info):
                        raise ValueError("tracked symlink changed during verification")
                    digest = hasher(b"blob " + str(size).encode() + b"\0" + content).hexdigest()
                    if _collect_supplement:
                        source_sha256 = hashlib.sha256(content).hexdigest()
                else:
                    if not stat.S_ISREG(info.st_mode) or (mode_status == "VERIFIED" and
                            (bool(info.st_mode & 0o111) != (mode == "100755") or
                             bool(info.st_mode & stat.S_IXUSR) != (mode == "100755"))):
                        raise ValueError("tracked file type or executable mode differs from index")
                    size = info.st_size
                    if size > V3_MAX_TRACKED_FILE_BYTES or total + size > V3_MAX_TRACKED_BYTES:
                        raise ValueError("v3 tracked bytes exceed verification budget")
                    fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                    try:
                        if _v3_signature(os.fstat(fd)) != _v3_signature(info):
                            raise ValueError("tracked file changed before verification")
                        digest_state = hasher(b"blob " + str(size).encode() + b"\0")
                        content_hash = hashlib.sha256() if _collect_supplement else None
                        observed = 0
                        while True:
                            if time.monotonic() >= deadline:
                                raise TimeoutError("v3 tracked blob verification exceeded deadline")
                            read_limit = (min(1024 * 1024, size - observed + 1)
                                          if _collect_supplement else 1024 * 1024)
                            block = os.read(fd, read_limit)
                            if not block:
                                break
                            observed += len(block)
                            if observed > size:
                                raise ValueError("tracked file grew during verification")
                            digest_state.update(block)
                            if content_hash is not None:
                                content_hash.update(block)
                        if observed != size or _v3_signature(os.fstat(fd)) != _v3_signature(info):
                            raise ValueError("tracked file changed during verification")
                        digest = digest_state.hexdigest()
                        if content_hash is not None:
                            source_sha256 = content_hash.hexdigest()
                    finally:
                        os.close(fd)
                total += size
                if size > V3_MAX_TRACKED_FILE_BYTES or total > V3_MAX_TRACKED_BYTES:
                    raise ValueError("v3 tracked bytes exceed verification budget")
                if digest != oid:
                    raise ValueError("tracked source bytes differ from the Git index")
                signatures[path] = _v3_signature(info)
                if _collect_supplement:
                    row = {'path': path, 'kind': 'symlink' if mode == '120000' else 'file',
                           'git_mode': mode, 'git_oid': oid, 'size': size, 'sha256': source_sha256}
                    if mode == '120000':
                        row['target'] = target
                    supplement.append(row)
            finally:
                os.close(parent)
    finally:
        os.close(root_fd)
    return (signatures, supplement) if _collect_supplement else signatures


def _v3_recheck_tracked_signatures(root: Path, signatures: dict[str, tuple[int, ...]], deadline: float) -> None:
    root_fd = _v3_open_root(root)
    try:
        for path, expected in signatures.items():
            if time.monotonic() >= deadline:
                raise TimeoutError("v3 source recheck exceeded deadline")
            parent = os.dup(root_fd)
            try:
                parts = path.split("/")
                for component in parts[:-1]:
                    child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    os.close(parent)
                    parent = child
                if _v3_signature(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)) != expected:
                    raise ValueError("tracked source changed after blob verification")
            finally:
                os.close(parent)
    finally:
        os.close(root_fd)


def _v3_head_index(root: Path) -> tuple[str, dict[str, tuple[str, str]], bytes, bytes]:
    """Use Git plumbing only; no worktree status, diff, filters or hooks."""
    if run_git(root, ["rev-parse", "--show-prefix"]).strip():
        raise ValueError("v3 source root is not the Git worktree root")
    top = run_git(root, ["rev-parse", "--show-toplevel"]).decode("utf-8", "strict")
    if not top.endswith("\n") or "\n" in top[:-1] or not os.path.isabs(top[:-1]):
        raise ValueError("v3 Git worktree path is unavailable")
    source_fd = _v3_open_root(root)
    try:
        top_fd = _v3_open_root_by_path(Path(top[:-1]))
        try:
            observed, git_root = os.fstat(source_fd), os.fstat(top_fd)
            if (observed.st_dev, observed.st_ino) != (git_root.st_dev, git_root.st_ino):
                raise ValueError("v3 Git worktree does not match source root")
        finally:
            os.close(top_fd)
    finally:
        os.close(source_fd)
    head = run_git(root, ["rev-parse", "--verify", "HEAD^{commit}"]).decode("ascii", "strict").strip()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head):
        raise ValueError("v3 source head is not a Git commit ID")
    raw_index = run_git(root, ["ls-files", "--stage", "-z"])
    flags = run_git(root, ["ls-files", "-v", "-z"])
    tree = run_git(root, ["ls-tree", "-rz", "--full-tree", head])
    index = {}
    committed = {}
    for raw, destination, is_tree in ((raw_index, index, False), (tree, committed, True)):
        if not raw.endswith(b"\0") or raw.count(b"\0") > V3_MAX_DIRECTORIES:
            raise ValueError("v3 Git index or tree is empty, malformed or exceeds its budget")
        for item in raw.split(b"\0"):
            if not item:
                continue
            metadata, separator, raw_path = item.partition(b"\t")
            fields = metadata.decode("ascii", "strict").split(" ")
            path = raw_path.decode("utf-8", "strict")
            _v3_checked_path(path)
            if not separator or len(fields) != 3 or path in destination:
                raise ValueError("v3 Git index or tree has malformed or duplicate entries")
            mode, kind, value = fields
            oid = value if is_tree else kind
            if (mode not in ("100644", "100755", "120000") or
                    not re.fullmatch(r"[0-9a-f]{%d}" % len(head), oid) or
                    (kind != "blob" if is_tree else value != "0")):
                raise ValueError("v3 Git index or tree has unsupported entries")
            destination[path] = (mode, oid)
    if not index or index != committed:
        raise ValueError("v3 Git index differs from HEAD or has no tracked files")
    flag_rows = flags.split(b"\0")
    if not flags.endswith(b"\0") or len(flag_rows) != len(index) + 1:
        raise ValueError("v3 Git visibility flags are incomplete")
    seen = []
    for item in flag_rows:
        if not item:
            continue
        if not item.startswith(b"H "):
            raise ValueError("v3 Git index has hidden or unsupported visibility flags")
        seen.append(item[2:].decode("utf-8", "strict"))
    if len(seen) != len(index) or set(seen) != set(index):
        raise ValueError("v3 Git visibility flags differ from index")
    return head, index, raw_index, flags


def _build_manifest_v3_bounded(root: Path, excludes: Iterable[str] = V3_EXCLUDES,
                               scan_all_untracked: bool = False, *,
                               _collect_supplement: bool = False):
    """Create an opt-in draft projection; two observations are not atomic.

    A v3 manifest cannot grant release qualification. Any incomplete, racy or
    unsupported observation raises; callers must treat that as inconclusive.
    The existing v2 producer and historical v1/v2 documents are unchanged.
    """
    raise P001SupervisionUnavailable("v3 source observation blocked: process supervision is not verified")
    root = Path(os.path.abspath(root))
    patterns = tuple(excludes)
    if patterns != V3_EXCLUDES:
        raise ValueError("v3 requires the registered fixed exclusion policy")
    fd = _v3_open_root(root)
    try:
        root_identity = (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
    finally:
        os.close(fd)
    mode, fs_type = _v3_mount_status(root)
    head, index, raw_index, flags = _v3_head_index(root)
    tracked = set(index)
    deadline = time.monotonic() + _bounded_timeout()
    if _collect_supplement:
        verified_signatures, supplement = _v3_verify_index_bytes(
            root, tracked, patterns, mode, head, deadline, raw_index, _collect_supplement=True)
    else:
        verified_signatures = _v3_verify_index_bytes(root, tracked, patterns, mode, head, deadline, raw_index)
    first, first_signatures = _v3_scan_projection(root, tracked, patterns, mode, deadline)
    second, second_signatures = _v3_scan_projection(root, tracked, patterns, mode, deadline)
    if any(first_signatures['files'].get(path) != sig for path, sig in verified_signatures.items()):
        raise ValueError("tracked source changed after blob verification")
    if any(path not in tracked and not v3_excluded(path, "file") for path in first_signatures['files']):
        raise ValueError("v3 source contains an untracked business file")
    if any(row["origin"] == "untracked_business" for row in first["directories"]):
        raise ValueError("v3 source contains an untracked business directory")
    after_head, after_index, after_raw_index, after_flags = _v3_head_index(root)
    if (head != after_head or index != after_index or raw_index != after_raw_index or flags != after_flags
            or first != second or first_signatures != second_signatures
            or _v3_mount_status(root) != (mode, fs_type)):
        raise ValueError("v3 source projection or Git inventory changed between observations")
    _v3_recheck_tracked_signatures(root, verified_signatures, deadline)
    fd = _v3_open_root_by_path(root)
    try:
        if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) != root_identity:
            raise ValueError("v3 source root identity changed")
    finally:
        os.close(fd)
    core = {"schema_version": V3_SCHEMA, "source_root": str(root), "head": head,
            "worktree_state": "CLEAN", "inventory_complete": True, "inventory_error": None,
            "index_visibility_exceptions": [], "exclude_patterns": list(patterns),
            "untracked_scan_mode": "all" if scan_all_untracked else "bounded",
            "untracked_scan_roots": list(EXPAND_UNTRACKED_PREFIXES), "tracked_changes": [],
            "untracked_business_files": [], "excluded_generated_files": [],
            "patch_sha256": hashlib.sha256(b"").hexdigest(), "directory_projection": first,
            "projection_sha256": hashlib.sha256(_v3_canonical(first)).hexdigest()}
    result = {**core, "manifest_sha256": hashlib.sha256(_v3_canonical(core)).hexdigest(),
              "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
              "release_qualifiable": False}
    if len((json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")) > V3_MAX_JSON_BYTES:
        raise ValueError("v3 manifest exceeds maximum raw JSON bytes")
    if _bounded_timeout() <= 0:
        raise TimeoutError("v3 source inventory exceeded its total deadline")
    # Supplemental rows are local until every source/index/root/projection
    # validation above has succeeded; no callback receives partial state.
    if _collect_supplement:
        return result, supplement, head, raw_index, flags
    return result


def build_manifest_v3(root: Path, excludes: Iterable[str] = V3_EXCLUDES,
                      scan_all_untracked: bool = False) -> dict:
    raise P001SupervisionUnavailable("v3 source observation blocked: process supervision is not verified")
    # Context-local bounded Git capture preserves the historical v2 behavior.
    root = Path(os.path.abspath(root))
    root_fd = _v3_open_root_by_path(root)
    root_token = _V3_PINNED_ROOT.set((str(root), root_fd))
    try:
        deadline = time.monotonic() + _bounded_timeout()
        token = _V3_BOUNDED_GIT.set(True)
        try:
            deadline_token = _V3_TOTAL_DEADLINE.set(deadline)
            try:
                return _build_manifest_v3_bounded(root, excludes, scan_all_untracked)
            finally:
                _V3_TOTAL_DEADLINE.reset(deadline_token)
        finally:
            _V3_BOUNDED_GIT.reset(token)
    finally:
        _V3_PINNED_ROOT.reset(root_token)
        os.close(root_fd)

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--exclude", action="append", default=[])
    parser.add_argument("--scan-all-untracked", action="store_true", help="scan every untracked path; may be slow on evidence-heavy trees")
    parser.add_argument("--manifest-version", choices=("2", "3"), default="2", help="v3 is an explicit non-qualifying draft projection")
    args = parser.parse_args(argv)
    if args.manifest_version == "3":
        print(json.dumps({"status": "BLOCKED", "qualification": "NOT_RUN",
                          "product_gate_effect": "NONE", "release_qualifiable": False,
                          "workload_invoked": False,
                          "reason": "v3 source observation blocked: process supervision is not verified"},
                         ensure_ascii=False))
        return 20
    try:
        source_root = (Path(os.path.abspath(args.source_root.expanduser())) if args.manifest_version == "3"
                       else args.source_root.expanduser().resolve())
        requested_output = args.output.expanduser().absolute()
        if os.path.lexists(requested_output):
            raise ValueError("manifest evidence already exists")
        output_path = requested_output.resolve()
        if output_path == source_root or source_root in output_path.parents:
            raise ValueError("manifest output must be outside the source root")
        producer = build_manifest_v3 if args.manifest_version == "3" else build_manifest
        policy = V3_EXCLUDES if args.manifest_version == "3" else DEFAULT_EXCLUDES
        manifest = producer(source_root, [*policy, *args.exclude], args.scan_all_untracked)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        if args.manifest_version == "3":
            result = {"status": "OBSERVED_NOT_GATE", "qualification": "NOT_RUN", "product_gate_effect": "NONE",
                      "manifest_sha256": manifest["manifest_sha256"], "release_qualifiable": False}
        else:
            result = {"status": "PASS", "manifest_sha256": manifest["manifest_sha256"],
                      "release_qualifiable": manifest["release_qualifiable"]}
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except P001SupervisionUnavailable as exc:
        print(json.dumps({"status": "BLOCKED", "qualification": "NOT_RUN",
                          "product_gate_effect": "NONE", "release_qualifiable": False,
                          "workload_invoked": None, "reason": str(exc)}, ensure_ascii=False))
        return 20
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError, RuntimeError) as exc:
        error = {"status": "FAIL", "reason": str(exc)}
        if args.manifest_version == "3":
            error.update(qualification="NOT_RUN", product_gate_effect="NONE", release_qualifiable=False)
            if isinstance(exc, RuntimeError) and str(exc) == "v3 Git process termination could not be confirmed":
                error.update(status="INCONCLUSIVE", leader_reaped=None, descendants_terminated=None,
                             git_stream_complete=False, git_stream_truncated=None,
                             git_stream_reason="termination_unconfirmed", git_stderr_raw_persisted=False)
                print(json.dumps(error, ensure_ascii=False))
                return 20
            if isinstance(exc, subprocess.CalledProcessError) and isinstance(exc.stderr, bytes):
                # A repository can cause Git to print credentials or commands;
                # do not export raw stderr even when encoded. Capture is
                # complete and bounded; retain its digest and byte count.
                error.update(git_stderr_sha256=hashlib.sha256(exc.stderr).hexdigest(),
                             git_stderr_bytes=len(exc.stderr), git_stderr_complete=True,
                             git_stderr_truncated=False, git_stderr_raw_persisted=False)
            elif isinstance(exc, subprocess.TimeoutExpired):
                error.update(git_stream_complete=False, git_stream_truncated=None,
                             git_stream_reason="timeout", git_stderr_raw_persisted=False)
            elif str(exc) == "v3 Git output exceeds bounded stream budget":
                error.update(git_stream_complete=False, git_stream_truncated=True,
                             git_stream_reason="output_limit", git_stderr_raw_persisted=False)
        print(json.dumps(error, ensure_ascii=False))
        return 10


if __name__ == "__main__":
    raise SystemExit(main())
