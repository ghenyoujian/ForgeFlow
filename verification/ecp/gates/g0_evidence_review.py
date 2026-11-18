#!/usr/bin/env python3
"""Offline G0 evidence integrity review; NEVER an execution or authorization oracle.

Inputs are an independently preregistered plan (SHA-256 pinned out of band), a
receipt, and raw logs, all below --evidence-root. Both JSON documents are
untrusted. The plan's case catalogue is caller supplied: checking its integrity
cannot prove it is complete against the task cards. This tool does not execute
suites, authenticate principals/leases, verify database facts, or issue a Gate.
Even an internally consistent all-green receipt remains INCONCLUSIVE.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import time
import types
from pathlib import Path

SUITES = frozenset(f"ECP-P0-{i:02d}" for i in range(1, 8))
STATUSES = ("PASS", "FAIL", "BLOCKED", "NOT_RUN", "INCONCLUSIVE", "SKIPPED")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}\Z")
MAX_JSON = 4 * 1024 * 1024
MAX_LOG = 128 * 1024 * 1024
SOURCE_SNAPSHOT_TOOL = Path(__file__).resolve().parents[3] / "ops/ecp/source_snapshot.py"
# Pin helper bytes in this reviewer; a modified reviewer is not authenticated.
SOURCE_SNAPSHOT_SHA256 = "7f68f70178bd3f908ae32cd2242128f8694db8613896bee07b6aac8e7c34b868"
MAX_HELPER = 1024 * 1024
MAX_G0_INDEX_DEPTH = 2048
MAX_G0_INDEX_DIRS = 100_000
MAX_G0_INDEX_DIR_BYTES = 16 * 1024 * 1024


class Invalid(ValueError):
    pass


class Incomplete(Invalid):
    """The observation could not be completed or termination is unknown."""


def require(condition, reason):
    if not condition:
        raise Invalid(reason)


def exact(obj, keys, what):
    require(isinstance(obj, dict) and set(obj) == set(keys), f"invalid {what} fields")


def unique_json(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, f"duplicate JSON key: {key}")
        obj[key] = value
    return obj


def no_symlink_root(path):
    path = os.path.abspath(path)
    parts = Path(path).parts
    fd = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[1:]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_beneath(root_fd, name, limit, inodes):
    require(isinstance(name, str) and name and not name.startswith("/") and "\0" not in name, "invalid relative path")
    parts = name.split("/")
    require(all(part not in ("", ".", "..") for part in parts), "unsafe evidence path")
    directory = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "evidence is not a bounded regular file")
            identity = (before.st_dev, before.st_ino)
            require(identity not in inodes, "duplicate evidence inode")
            inodes.add(identity)
            chunks, remaining = [], limit + 1
            while remaining:
                chunk = os.read(fd, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            after = os.fstat(fd)
            require(len(data) <= limit and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "evidence changed while reading")
            return data
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def parse_json(data):
    def bounded_int(value):
        require(len(value.lstrip("-")) <= 128, "JSON integer exceeds limit")
        return int(value)
    def finite_float(value):
        require(len(value) <= 128, "JSON float exceeds limit")
        result = float(value)
        require(math.isfinite(result), "invalid JSON number")
        return result
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique_json,
                          parse_int=bounded_int, parse_float=finite_float,
                          parse_constant=lambda _: (_ for _ in ()).throw(Invalid("invalid JSON number")))
    except Invalid:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise Invalid("invalid or excessively nested JSON") from exc


def source_snapshot_tool():
    """Load our own colocated verifier helper without writing bytecode.

    Its installation is trusted to the same extent as this reviewer; this is
    not an authenticated or independently isolated execution environment.
    """
    path = SOURCE_SNAPSHOT_TOOL
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_HELPER:
            raise Incomplete("source verifier helper is not a bounded regular file")
        chunks = []
        remaining = MAX_HELPER + 1
        while remaining:
            block = os.read(fd, min(remaining, 65536))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        data = b"".join(chunks)
        after = os.fstat(fd)
        before_sig = (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        after_sig = (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if before_sig != after_sig or len(data) != before.st_size or hashlib.sha256(data).hexdigest() != SOURCE_SNAPSHOT_SHA256:
            raise Incomplete("source verifier helper bytes do not match the pinned version")
    finally:
        os.close(fd)
    module = types.ModuleType("_ecp_g0_snapshot_helper")
    module.__file__ = str(path)
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module


def _g0_index_parent_directories(index, deadline):
    """Derive Git ancestors without trusting projected directory origins.

    Git does not track empty directories. Because the G0 source policy excludes
    only root .git metadata, every other source directory must be an ancestor
    of an indexed file. This comparison cannot discover a directory that the
    filesystem scanner never reports, and does not authenticate source.
    """
    if not isinstance(index, dict) or len(index) > MAX_G0_INDEX_DIRS:
        raise Incomplete("source index exceeds the directory derivation budget")
    expected = {"."}
    identity_bytes = len(".".encode("utf-8")) + 256
    for path in index:
        if time.monotonic() >= deadline:
            raise Incomplete("source index directory derivation exceeded deadline")
        if (not isinstance(path, str) or not path or len(path) > 4096 or path.startswith("/")
                or "\\" in path or any(ord(ch) < 32 or ord(ch) == 127 for ch in path)):
            raise Incomplete("source index path is unsupported")
        try:
            path.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise Incomplete("source index path encoding is unsupported") from exc
        parts = path.split("/")
        if len(parts) > MAX_G0_INDEX_DEPTH or any(part in ("", ".", "..") for part in parts):
            raise Incomplete("source index path depth or components are unsupported")
        parent = path.rpartition("/")[0]
        while parent and parent not in expected:
            if time.monotonic() >= deadline:
                raise Incomplete("source index directory derivation exceeded deadline")
            try:
                identity_bytes += len(parent.encode("utf-8", errors="strict")) + 256
            except UnicodeError as exc:
                raise Incomplete("source index directory encoding is unsupported") from exc
            if len(expected) >= MAX_G0_INDEX_DIRS or identity_bytes > MAX_G0_INDEX_DIR_BYTES:
                raise Incomplete("source index directory derivation exceeded identity budget")
            expected.add(parent)
            parent = parent.rpartition("/")[0]
    return expected


def actual_source(source):
    """Observe a bounded Git worktree without status, clean filters or hooks.

    All tracked paths, including normally excluded files, are checked against
    the raw index blob. Every untracked path outside .git is rejected, even
    if Git would ignore it. Each Git
    command uses the existing bounded fixed-executable runner. Observations
    and rechecks are not atomic and do not authenticate a source principal.
    """
    source = Path(os.path.abspath(source))
    try:
        root_fd = no_symlink_root(source)
    except OSError as exc:
        raise Incomplete("source root could not be opened safely") from exc
    tool = None
    token = deadline_token = None
    try:
        info = os.fstat(root_fd)
        identity = (info.st_dev, info.st_ino)
        # Reject a metadata symlink or special file before loading the helper
        # or starting Git. A linked worktree's regular .git marker remains
        # allowed, but this check does not authenticate its external gitdir.
        git_marker = os.stat(".git", dir_fd=root_fd, follow_symlinks=False)
        if not (stat.S_ISDIR(git_marker.st_mode) or stat.S_ISREG(git_marker.st_mode)):
            raise Invalid("source .git marker is not a directory or regular file")
        git_marker_sig = (git_marker.st_dev, git_marker.st_ino, git_marker.st_mode,
                          git_marker.st_size, git_marker.st_mtime_ns, git_marker.st_ctime_ns)

        def verify_git_marker():
            current = os.stat(".git", dir_fd=root_fd, follow_symlinks=False)
            signature = (current.st_dev, current.st_ino, current.st_mode, current.st_size,
                         current.st_mtime_ns, current.st_ctime_ns)
            if signature != git_marker_sig:
                raise Incomplete("source .git marker changed during observation")

        tool = source_snapshot_tool()
        # Every helper open, including each Git child's cwd, must derive from
        # the retained root descriptor. Reopening its pathname permits an
        # attacker to substitute a different tree and then restore the path.
        def pinned_root(path):
            if os.path.abspath(path) != str(source):
                raise ValueError("unexpected source root")
            return os.dup(root_fd)
        tool._v3_open_root = pinned_root
        deadline = time.monotonic() + 30.0
        token = tool._V3_BOUNDED_GIT.set(True)
        deadline_token = tool._V3_TOTAL_DEADLINE.set(deadline)
        mode, mount = tool._v3_mount_status(source)
        if mode != "VERIFIED":
            raise Incomplete("source filesystem mode availability is unverified")
        real_git = tool.run_git
        expected_stage = None
        def checked_git(root, args, *extra, **kwargs):
            verify_git_marker()
            value = real_git(root, args, *extra, **kwargs)
            verify_git_marker()
            if args == ["ls-files", "--stage", "-z"] and expected_stage is not None and value != expected_stage:
                raise Incomplete("source Git index changed during observation")
            return value
        tool.run_git = checked_git
        def verify_git_root():
            path = tool.run_git(source, ["rev-parse", "--show-toplevel"]).decode("utf-8", "strict").rstrip("\n")
            git_root_fd = no_symlink_root(path)
            try:
                git_root = os.fstat(git_root_fd)
                if (git_root.st_dev, git_root.st_ino) != identity:
                    raise Incomplete("Git worktree does not match the pinned source root")
            finally:
                os.close(git_root_fd)
        verify_git_root()
        sha, index, raw_index, flags = tool._v3_head_index(source)
        expected_stage = raw_index
        # The root .env file is private even if Git tracks it. This full-source
        # reviewer cannot authenticate its contents without reading them, so
        # it must stop before opening the worktree file or its symlink target.
        if ".env" in index:
            raise Incomplete("tracked private root .env cannot be independently observed")
        signatures = tool._v3_verify_index_bytes(source, set(index), (), mode, sha, deadline)
        if (not isinstance(signatures, dict) or set(signatures) != set(index)
                or any(not isinstance(value, tuple) or len(value) != 6
                       or any(type(item) is not int for item in value)
                       for value in signatures.values())):
            raise Incomplete("tracked source signature coverage is incomplete")
        for path, (git_mode, _) in index.items():
            if git_mode in ("100644", "100755") and bool(signatures[path][2] & stat.S_IXUSR) != (git_mode == "100755"):
                raise Invalid("source worktree executable permission differs from index")
        expected_directories = _g0_index_parent_directories(index, deadline)
        exclusions = (".git/",)
        expected_policy = hashlib.sha256(json.dumps(list(exclusions), ensure_ascii=False, sort_keys=True,
                                                   separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()
        expected_boundaries = ([{"path": ".git", "kind": "directory", "excluded_by": ".git/"}]
                               if stat.S_ISDIR(git_marker.st_mode) else [])

        def check_projection_shape(projection, observed):
            def signature(value):
                return (isinstance(value, tuple) and len(value) == 6
                        and all(type(item) is int for item in value))
            if (not isinstance(projection, dict)
                    or set(projection) != {"version", "mode_availability", "exclusion_policy_sha256",
                                           "directories", "excluded_directory_boundaries"}
                    or projection.get("version") != "forgeflow.ecp-directory-projection.v1"
                    or projection.get("mode_availability") != mode
                    or projection.get("exclusion_policy_sha256") != expected_policy
                    or projection.get("excluded_directory_boundaries") != expected_boundaries
                    or not isinstance(projection.get("directories"), list)
                    or not isinstance(observed, dict)
                    or set(observed) != {"directories", "boundaries", "files"}
                    or any(not isinstance(observed.get(key), dict) for key in observed)):
                raise Incomplete("source projection shape or exclusion policy is incomplete")
            rows = projection["directories"]
            allowed_origins = {"source_root", "git_ancestor", "excluded_container", "untracked_business"}
            if (not rows or any(not isinstance(row, dict)
                    or set(row) != {"path", "kind", "mode", "origin"}
                    or not isinstance(row.get("path"), str)
                    or row.get("kind") != "directory"
                    or not isinstance(row.get("origin"), str)
                    or row.get("origin") not in allowed_origins
                    or not isinstance(row.get("mode"), str)
                    or re.fullmatch(r"[0-7]{4}", row["mode"]) is None for row in rows)):
                raise Incomplete("source projected directories are incomplete")
            paths = [row["path"] for row in rows]
            if (len(paths) != len(set(paths)) or "." not in paths
                    or set(paths) != set(observed["directories"])
                    or any(not isinstance(path, str) or not signature(value)
                           for key in ("directories", "files") for path, value in observed[key].items())):
                raise Incomplete("source observed signatures are incomplete")
            expected_boundary_paths = {row["path"] for row in expected_boundaries}
            if (set(observed["boundaries"]) != expected_boundary_paths
                    or any(not isinstance(value, tuple) or len(value) != 2
                           or value[0] != ".git/" or not signature(value[1])
                           for value in observed["boundaries"].values())):
                raise Incomplete("source boundary signatures are incomplete")

        projection, observed = tool._v3_scan_projection(source, set(index), exclusions, mode, deadline)
        check_projection_shape(projection, observed)
        observed_directories = set(observed["directories"])
        if expected_directories - observed_directories:
            raise Incomplete("tracked source ancestor is missing from the directory projection")
        if observed_directories - expected_directories:
            raise Invalid("source worktree contains untracked directories")
        if any(row["origin"] != ("source_root" if row["path"] == "." else "git_ancestor")
               for row in projection["directories"]):
            raise Incomplete("source projected directory origin conflicts with the Git index")
        if any(path not in index and not tool.matches_exclude(path, exclusions) for path in observed["files"]):
            raise Invalid("source worktree is dirty or contains untracked inputs")
        if any(observed["files"].get(path) != signature for path, signature in signatures.items()
               if not tool.matches_exclude(path, exclusions)):
            raise Incomplete("tracked source changed between verification and projection")
        projection2, observed2 = tool._v3_scan_projection(source, set(index), exclusions, mode, deadline)
        check_projection_shape(projection2, observed2)
        if projection != projection2 or observed != observed2:
            raise Incomplete("source projection changed during observation")
        if (sha, index, raw_index, flags) != tool._v3_head_index(source):
            raise Incomplete("source Git inventory changed during observation")
        tool._v3_recheck_tracked_signatures(source, signatures, deadline)
        verify_git_root()
        verify_git_marker()
        if tool._v3_mount_status(source) != (mode, mount):
            raise Incomplete("source mount changed during observation")
        check_fd = no_symlink_root(source)
        try:
            check = os.fstat(check_fd)
            if (check.st_dev, check.st_ino) != identity:
                raise Incomplete("source root changed during observation")
        finally:
            os.close(check_fd)
        return sha
    except Incomplete:
        raise
    except Invalid:
        raise
    except (subprocess.TimeoutExpired, TimeoutError, RuntimeError, OSError) as exc:
        raise Incomplete("source observation or process termination could not be confirmed") from exc
    except ValueError as exc:
        if str(exc) == "v3 Git index has hidden or unsupported visibility flags":
            raise Invalid("source index has hidden or unsupported entry flags") from exc
        if str(exc) in ("tracked source bytes differ from the Git index", "tracked file type or executable mode differs from index"):
            raise Invalid("source worktree is dirty") from exc
        raise Incomplete("source inventory is incomplete or unsupported") from exc
    except (UnicodeError, subprocess.CalledProcessError) as exc:
        raise Incomplete("source Git inventory could not be inspected") from exc
    finally:
        if tool is not None:
            if deadline_token is not None:
                tool._V3_TOTAL_DEADLINE.reset(deadline_token)
            if token is not None:
                tool._V3_BOUNDED_GIT.reset(token)
        os.close(root_fd)


def string_id(value, label):
    require(isinstance(value, str) and IDENT.fullmatch(value) is not None, f"invalid {label}")
    return value


def suite_map(suites, label):
    require(isinstance(suites, list), f"{label} suites must be a list")
    mapped = {}
    for suite in suites:
        require(isinstance(suite, dict), f"invalid {label} suite")
        suite_id = suite.get("suite_id")
        require(isinstance(suite_id, str) and suite_id in SUITES and suite_id not in mapped, f"unknown or duplicate {label} suite")
        mapped[suite_id] = suite
    require(set(mapped) == SUITES, f"missing required {label} suite")
    return mapped


def review(source, evidence_root, plan_name, expected_plan_sha, receipt_name):
    require(isinstance(expected_plan_sha, str) and SHA256.fullmatch(expected_plan_sha), "invalid pinned plan SHA-256")
    source_sha = actual_source(source)
    root_fd = no_symlink_root(evidence_root)
    try:
        require(plan_name != receipt_name, "plan and receipt paths must differ")
        inodes = set()
        plan_bytes = read_beneath(root_fd, plan_name, MAX_JSON, inodes)
        require(hashlib.sha256(plan_bytes).hexdigest() == expected_plan_sha, "preregistered plan hash mismatch")
        plan = parse_json(plan_bytes)
        receipt = parse_json(read_beneath(root_fd, receipt_name, MAX_JSON, inodes))
        exact(plan, {"schema_version", "source_sha", "suites"}, "plan")
        exact(receipt, {"schema_version", "run_id", "source_sha", "plan_sha256", "suites"}, "receipt")
        require(plan["schema_version"] == "forgeflow.ecp-g0-review-plan.v1", "invalid plan schema")
        require(receipt["schema_version"] == "forgeflow.ecp-g0-review-input.v1", "invalid receipt schema")
        string_id(receipt["run_id"], "run ID")
        require(plan["source_sha"] == receipt["source_sha"] == source_sha, "source SHA mismatch")
        require(receipt["plan_sha256"] == expected_plan_sha, "receipt plan hash mismatch")
        planned = suite_map(plan["suites"], "plan")
        observed = suite_map(receipt["suites"], "receipt")
        paths = {plan_name, receipt_name}
        suite_counts = {}
        for suite_id in sorted(SUITES):
            spec, run = planned[suite_id], observed[suite_id]
            exact(spec, {"suite_id", "case_ids"}, "plan suite")
            exact(run, {"suite_id", "cases", "denominator", "exit_code", "logs"}, "receipt suite")
            case_ids = spec["case_ids"]
            require(isinstance(case_ids, list) and case_ids, "zero planned cases")
            for case_id in case_ids:
                string_id(case_id, "case ID")
            require(len(set(case_ids)) == len(case_ids), "duplicate planned case")
            cases = run["cases"]
            require(isinstance(cases, list) and cases, "zero observed cases")
            counts = {s: 0 for s in STATUSES}
            seen = set()
            for case in cases:
                exact(case, {"case_id", "status"}, "case")
                case_id = string_id(case["case_id"], "case ID")
                require(case_id not in seen, "duplicate observed case")
                seen.add(case_id)
                status = case["status"]
                require(isinstance(status, str) and status in counts, "unknown case status")
                counts[status] += 1
            require(seen == set(case_ids), "case list mismatch")
            denominator = run["denominator"]
            exact(denominator, {"total", *STATUSES}, "denominator")
            require(all(type(value) is int and value >= 0 for value in denominator.values()), "invalid denominator value")
            require(denominator["total"] == len(cases) and all(denominator[s] == counts[s] for s in STATUSES), "denominator inconsistent with cases")
            require(type(run["exit_code"]) is int, "invalid exit code")
            require(not (counts["PASS"] == len(cases) and run["exit_code"] != 0), "all-pass cases contradict nonzero exit")
            suite_counts[suite_id] = {"denominator": dict(denominator), "exit_code": run["exit_code"]}
            logs = run["logs"]
            exact(logs, {"stdout", "stderr"}, "logs")
            for kind in ("stdout", "stderr"):
                item = logs[kind]
                exact(item, {"path", "sha256"}, "log")
                path, digest = item["path"], item["sha256"]
                require(isinstance(path, str) and path not in paths, "duplicate evidence path")
                paths.add(path)
                require(isinstance(digest, str) and SHA256.fullmatch(digest), "invalid log digest")
                data = read_beneath(root_fd, path, MAX_LOG, inodes)
                require(hashlib.sha256(data).hexdigest() == digest, "log hash mismatch")
        require(actual_source(source) == source_sha, "source changed during review")
        failed = any(item["denominator"]["FAIL"] for item in suite_counts.values())
        return {"schema_version": "forgeflow.ecp-g0-integrity-review.v1", "status": "FAIL" if failed else "INCONCLUSIVE", "product_gate_effect": "NONE", "source_sha": source_sha, "plan_sha256": expected_plan_sha, "run_id": receipt["run_id"], "suite_counts": suite_counts, "reason": "Receipt reports at least one failed case; no Gate can be issued." if failed else "Integrity checks alone cannot authenticate execution, plan completeness, principal, lease or independent oracle; no Gate can be issued."}
    finally:
        os.close(root_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--evidence-root", required=True)
    parser.add_argument("--plan", required=True, help="relative path under evidence root")
    parser.add_argument("--plan-sha256", required=True, help="plan digest pinned independently before execution")
    parser.add_argument("--receipt", required=True, help="relative path under evidence root")
    args = parser.parse_args()
    try:
        result = review(args.source, args.evidence_root, args.plan, args.plan_sha256, args.receipt)
        code = 10 if result["status"] == "FAIL" else 20
    except Incomplete as exc:
        result = {"schema_version": "forgeflow.ecp-g0-integrity-review.v1", "status": "INCONCLUSIVE", "product_gate_effect": "NONE", "reason": str(exc)}
        code = 20
    except (Invalid, OSError, subprocess.SubprocessError, UnicodeError) as exc:
        result = {"schema_version": "forgeflow.ecp-g0-integrity-review.v1", "status": "FAIL", "product_gate_effect": "NONE", "reason": str(exc)}
        code = 10
    json.dump(result, sys.stdout, sort_keys=True)
    print()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
