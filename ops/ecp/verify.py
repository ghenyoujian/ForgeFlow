#!/usr/bin/env python3
"""Offline ECP Phase 0 verification entry point.

This command records source identity and local readiness facts without connecting
to PostgreSQL, starting services, invoking executors, or issuing product Gate
claims.  It is intentionally conservative: missing or unexecuted evidence is
reported as NOT_RUN/BLOCKED/INCONCLUSIVE rather than upgraded to PASS.
"""
from __future__ import annotations

import argparse
import fcntl
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import posixpath
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterable

from source_snapshot import DEFAULT_EXCLUDES, build_manifest

SCHEMA = "forgeflow.ecp-verification.v1"
STATUSES = ("PASS", "FAIL", "BLOCKED", "NOT_RUN", "INCONCLUSIVE")
EXIT_CODES = {"PASS": 0, "FAIL": 10, "BLOCKED": 20, "NOT_RUN": 20, "INCONCLUSIVE": 20}
P003_MAX_LOG_BYTES = 16 * 1024 * 1024
# Conservative precedence for an aggregate: any failure dominates.
STATUS_RANK = {"PASS": 0, "INCONCLUSIVE": 1, "NOT_RUN": 2, "BLOCKED": 3, "FAIL": 4}


class P001SupervisionUnavailable(RuntimeError):
    """P001 v3 process execution has not been admitted."""
SUITE_REGISTRY_RELATIVE = Path("planning") / "suite_registry.json"
SUITE_REGISTRY_EXTERNAL = (
    Path("docs") / "idea" / "ForgeFlow_ECP_完整开发规划" / "planning" / "suite_registry.json"
)


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    reason: str
    details: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "reason": self.reason,
            "details": self.details,
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def run_git(root: Path, args: list[str], *, timeout_seconds: float = 5.0) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            ["git", *args], cwd=root, text=True, capture_output=True,
            timeout=timeout_seconds, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def git_sha(root: Path) -> tuple[str | None, str | None]:
    code, out, err = run_git(root, ["rev-parse", "HEAD"])
    if code != 0 or not out:
        return None, err or "git rev-parse HEAD failed"
    return out, None


def git_status(root: Path) -> tuple[list[str] | None, str | None]:
    # Large worktrees can contain tens of thousands of ignored build/cache
    # entries.  Give the authoritative status probe a bounded but practical
    # window; a timeout remains INCONCLUSIVE rather than being treated as clean.
    try:
        timeout_seconds = float(os.environ.get("ECP_GIT_STATUS_TIMEOUT_SECONDS", "30"))
    except ValueError:
        timeout_seconds = 30.0
    timeout_seconds = min(max(timeout_seconds, 5.0), 120.0)
    code, out, err = run_git(
        root, ["status", "--porcelain=v1", "--untracked-files=normal"],
        timeout_seconds=timeout_seconds,
    )
    if code != 0:
        return None, err or "git status failed"
    return ([line for line in out.splitlines() if line], None)


def bounded_child_timeout(environment_name: str, *, fallback_name: str | None = None, default: float = 30.0) -> float:
    """Return a bounded timeout for a verifier-owned subprocess.

    ECP checks run against worktrees that may contain a large amount of
    retained evidence.  Child commands must share the same operator supplied
    deadline as the source scanner so a doctor/suite invocation cannot sit on
    a fixed two-minute timeout while the parent has a shorter probe budget.
    """
    raw = os.environ.get(environment_name)
    if raw is None and fallback_name:
        raw = os.environ.get(fallback_name)
    try:
        value = float(raw) if raw is not None else default
    except ValueError:
        value = default
    return min(max(value, 5.0), 120.0)


def tool_version(binary: str) -> str | None:
    path = shutil.which(binary)
    if not path:
        return None
    try:
        completed = subprocess.run(
            [path, "--version"], capture_output=True, text=True, timeout=5, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return path
    line = (completed.stdout or completed.stderr).strip().splitlines()
    return line[0] if line else path


def default_source_root() -> Path:
    # .../control/ops/ecp/verify.py -> .../control
    return Path(__file__).resolve().parents[2]


def resolve_source_root(value: str | None) -> Path:
    root = Path(value).expanduser() if value else default_source_root()
    return root.resolve()


def check_source_identity(root: Path) -> tuple[Check, str | None, list[str]]:
    # Use the same canonical, content-addressed source inventory as the P0-01
    # manifest command.  A second `git status` parser here used to time out on
    # evidence-heavy trees and, if relaxed independently, could disagree with
    # the manifest about which generated files count as source.
    try:
        manifest = build_manifest(root, DEFAULT_EXCLUDES)
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as exc:
        return Check(
            "source_identity", "INCONCLUSIVE", f"canonical source manifest unavailable: {exc}",
            {"source_root": str(root)},
        ), None, []
    sha = manifest.get("head")
    if not isinstance(sha, str) or not sha:
        return Check("source_identity", "FAIL", "source SHA unavailable", {"source_root": str(root)}), None, []
    tracked_paths = manifest.get("tracked_changes", [])
    untracked_paths = manifest.get("untracked_business_files", [])
    excluded_paths = manifest.get("excluded_generated_files", [])
    tracked = len(tracked_paths) if isinstance(tracked_paths, list) else 0
    untracked = len(untracked_paths) if isinstance(untracked_paths, list) else 0
    excluded = len(excluded_paths) if isinstance(excluded_paths, list) else 0
    digest = manifest.get("manifest_sha256")
    dirty = manifest.get("worktree_state") != "CLEAN"
    if dirty:
        return Check(
            "source_identity", "INCONCLUSIVE",
            "working tree is dirty; this is not a release-source qualification",
            {
                "source_root": str(root),
                "source_sha": sha,
                "source_manifest_sha256": digest,
                "dirty": True,
                "status_entries": tracked + untracked + excluded,
                "tracked_entries": tracked,
                "untracked_entries": untracked,
                "excluded_generated_entries": excluded,
            },
        ), sha, []
    return Check(
        "source_identity", "PASS", "canonical source manifest and clean working tree identified",
        {"source_root": str(root), "source_sha": sha, "source_manifest_sha256": digest, "dirty": False, "status_entries": 0},
    ), sha, []


def check_required_inputs(root: Path) -> Check:
    required = [
        "Cargo.toml",
        "Cargo.lock",
        "migrations",
        "crates/store/src/lib.rs",
        "planning/tasks.json",
        "planning/gates.json",
        "console/package.json",
    ]
    missing = [relative for relative in required if not (root / relative).exists()]
    if missing:
        return Check(
            "source_inputs", "FAIL", "required source inputs are missing",
            {"required": required, "missing": missing},
        )
    return Check(
        "source_inputs", "PASS", "required source inputs are present",
        {"required": required, "missing": []},
    )


def check_tools() -> list[Check]:
    checks: list[Check] = []
    for binary in ("cargo", "rustc", "node", "npm"):
        version = tool_version(binary)
        if version is None:
            checks.append(Check("tool." + binary, "BLOCKED", f"{binary} is unavailable", {"binary": binary}))
        else:
            checks.append(Check("tool." + binary, "PASS", f"{binary} is available", {"binary": binary, "version": version}))
    return checks


def check_database_policy() -> Check:
    # Deliberately do not inspect/connect to a URL or run psql/pg_isready.  The
    # purpose of doctor is to establish that a real probe remains outstanding.
    return Check(
        "database_probe", "NOT_RUN",
        "doctor never connects to PostgreSQL; run the isolated database suite separately",
        {"connections_attempted": 0, "database_url_present": bool(os.environ.get("DATABASE_URL"))},
    )


def find_suite_registry(root: Path) -> Path | None:
    """Find the planning registry without inventing a suite declaration.

    The source tree normally keeps the registry beside the control source's
    parent planning package.  The in-tree path is also accepted for isolated
    fixtures, which keeps the runner reproducible without relying on a caller's
    current working directory.
    """
    candidates = [root / SUITE_REGISTRY_RELATIVE, root.parent / SUITE_REGISTRY_EXTERNAL]
    configured = os.environ.get("ECP_SUITE_REGISTRY")
    if configured:
        candidates.insert(0, Path(configured).expanduser().resolve())
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None


def load_declared_suite(root: Path, suite_id: str) -> tuple[Path | None, dict[str, Any] | None, str | None]:
    registry_path = find_suite_registry(root)
    if registry_path is None:
        return None, None, "suite registry is unavailable"
    try:
        value = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return registry_path, None, f"suite registry is unreadable: {exc}"
    suites = value.get("suites") if isinstance(value, dict) else None
    if not isinstance(suites, list):
        return registry_path, None, "suite registry has no suites array"
    for entry in suites:
        if isinstance(entry, dict) and entry.get("suite_id") == suite_id:
            return registry_path, entry, None
    return registry_path, None, f"suite {suite_id} is not declared in the registry"


def validate_p003_workload(root: Path, entry: dict[str, Any]) -> tuple[list[str] | None, str | None]:
    workload = entry.get("offline_workload")
    expected = {
        "runner": "python_unittest",
        "start_directory": "ops/ecp/tests",
        "pattern": "test_p003_contract.py",
        "requires_non_skipped": True,
        "network_access": False,
        "database_access": False,
    }
    if workload != expected:
        return None, "P0-03 registry workload differs from the supported offline contract"
    start_dir = (root / workload["start_directory"]).resolve()
    if root not in start_dir.parents or not start_dir.is_dir():
        return None, "P0-03 registry test directory is missing or escapes source root"
    if not (start_dir / workload["pattern"]).is_file():
        return None, "P0-03 registry test pattern matches no checked-in test file"
    command = [sys.executable, "-m", "unittest", "discover", "-s", workload["start_directory"],
               "-p", workload["pattern"], "-v"]
    return command, None


def parse_unittest_denominator(stdout: str, stderr: str, exit_code: int) -> tuple[str, dict[str, int], str]:
    """Require a complete, internally consistent unittest terminal summary.

    This observes a process log; it cannot authenticate an independently
    authorized test execution. Unrecognized or incomplete output never passes.
    """
    # skipped, failures and errors are raw unittest event counts, not
    # additional mutually exclusive test categories: subtest events can
    # exceed the number of tests and cannot identify distinct test outcomes.
    counts = {"total": 0, "passed": 0, "failed": 0, "blocked": 0,
              "not_run": 0, "inconclusive": 0, "skipped": 0,
              "failures": 0, "errors": 0, "expected_failures": 0,
              "unexpected_successes": 0}
    run_pattern = re.compile(r"^Ran (\d{1,9}) tests? in [0-9]+(?:\.[0-9]+)?s$", re.MULTILINE)
    runs = [(stream, match) for stream in (stdout, stderr) for match in run_pattern.finditer(stream)]
    if not runs:
        return "FAIL", counts, "test command emitted no unittest denominator"
    if len(runs) != 1:
        return "FAIL", counts, "unittest denominator is ambiguous"
    stream, match = runs[0]
    total = int(match.group(1))
    counts["total"] = total
    remainder = stream[match.end():].strip()
    summary = re.fullmatch(r"(OK|FAILED)(?: \(([^\n()]*)\))?", remainder)
    if not summary:
        counts["inconclusive"] = total
        return "FAIL", counts, "unittest terminal summary is missing or incomplete"
    values = {}
    if summary.group(2):
        for entry in summary.group(2).split(", "):
            item = re.fullmatch(r"(skipped|failures|errors|expected failures|unexpected successes)=(\d{1,9})", entry)
            if not item or item.group(1) in values:
                counts["inconclusive"] = total
                return "FAIL", counts, "unittest terminal summary has unknown or duplicate fields"
            values[item.group(1)] = int(item.group(2))
    skipped = values.get("skipped", 0)
    failures = values.get("failures", 0)
    errors = values.get("errors", 0)
    expected_failures = values.get("expected failures", 0)
    unexpected_successes = values.get("unexpected successes", 0)
    unsuccessful = failures + errors + unexpected_successes
    counts.update(skipped=skipped, failures=failures, errors=errors, expected_failures=expected_failures,
                  unexpected_successes=unexpected_successes)
    if total == 0:
        return "FAIL", counts, "test command emitted no unittest denominator"
    if exit_code != 0 or summary.group(1) == "FAILED" or unsuccessful:
        # The summary counts failure events, not distinct failed tests:
        # multiple subtests can belong to the same test, and setup/teardown
        # errors may not belong to any discovered test. Keep event counts and
        # leave all individual test outcomes unclassified.
        counts["inconclusive"] = total
        return "FAIL", counts, "test command failed; original unittest failures are preserved"
    if skipped >= total:
        counts["inconclusive"] = total
        return "FAIL", counts, "all discovered tests may have been skipped; skip event counts do not identify distinct tests"
    if skipped or expected_failures:
        counts["inconclusive"] = total
        return "INCONCLUSIVE", counts, "some discovered tests were skipped or expected to fail"
    counts["passed"] = total
    return "PASS", counts, "unittest reported a nonzero executed denominator"


def run_p003_bounded(command: list[str], *, cwd: Path, env: dict[str, str],
                     stdout_path: Path, stderr_path: Path, timeout: float = 300.0,
                     log_limit: int = P003_MAX_LOG_BYTES,
                     pass_fds: tuple[int, ...] = (),
                     return_file_identities: bool = False) -> dict[str, Any]:
    """Capture capped raw bytes; terminate only this invocation's process group.

    This is a resource guard, not a sandbox: children may escape the process
    group or close their inherited streams and continue running. We never
    claim all descendant processes stopped or that network access was confined.
    """
    raise P001SupervisionUnavailable("bounded capture blocked: process supervision is not verified")
    if timeout <= 0 or log_limit < 0:
        raise ValueError("invalid P0-03 process bounds")
    result: dict[str, Any] = {
        "exit_code": None, "started": False, "timed_out": False,
        "capture_complete": False, "termination_reason": None,
        "group_signal": "NOT_SENT", "leader_reaped": False,
        "descendants_terminated": None, "log_limit_bytes_per_stream": log_limit,
        "timeout_seconds": timeout,
    }
    # Atomic exclusive creation prevents overwriting an existing evidence file.
    def open_raw(path: Path):
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
        return os.fdopen(os.open(path, flags, 0o600), "w+b")

    with open_raw(stdout_path) as stdout_file, open_raw(stderr_path) as stderr_file:
        process = None
        poller = selectors.DefaultSelector()
        deadline = time.monotonic() + timeout
        remaining = {}
        try:
            try:
                process = subprocess.Popen(command, cwd=cwd, env=env,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           start_new_session=True, close_fds=True, pass_fds=pass_fds)
                result["started"] = True
            except OSError as exc:
                result["exit_code"] = 127
                result["termination_reason"] = "process_start_failed"
                result["start_error_type"] = type(exc).__name__
                result["start_errno"] = exc.errno
            if process is not None:
                for pipe, target in ((process.stdout, stdout_file), (process.stderr, stderr_file)):
                    poller.register(pipe, selectors.EVENT_READ, target)
                    remaining[pipe] = log_limit
                while poller.get_map() and result["termination_reason"] is None:
                    left = deadline - time.monotonic()
                    if left <= 0:
                        result["termination_reason"] = "timeout"
                        result["timed_out"] = True
                        break
                    for key, _ in poller.select(left):
                        data = os.read(key.fileobj.fileno(), min(65536, remaining[key.fileobj] + 1))
                        if not data:
                            poller.unregister(key.fileobj)
                            continue
                        if len(data) > remaining[key.fileobj]:
                            key.data.write(data[:remaining[key.fileobj]])
                            result["termination_reason"] = "log_limit_exceeded"
                            result["truncated_stream"] = "stdout" if key.data is stdout_file else "stderr"
                            break
                        key.data.write(data)
                        remaining[key.fileobj] -= len(data)
                if result["termination_reason"] is None:
                    left = deadline - time.monotonic()
                    if left > 0:
                        try:
                            result["exit_code"] = process.wait(timeout=left)
                            result["leader_reaped"] = True
                            result["capture_complete"] = True
                        except subprocess.TimeoutExpired:
                            result["termination_reason"] = "timeout"
                            result["timed_out"] = True
                    else:
                        result["termination_reason"] = "timeout"
                        result["timed_out"] = True
                if result["termination_reason"] is not None:
                    # No wait/poll occurs before signalling, so the direct
                    # child's PID cannot have been reaped and reused here.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                        result["group_signal"] = "SIGKILL_SENT"
                    except ProcessLookupError:
                        result["group_signal"] = "GROUP_NOT_FOUND"
                    except OSError as exc:
                        result["group_signal"] = "SIGNAL_FAILED"
                        result["signal_errno"] = exc.errno
                    try:
                        result["exit_code"] = process.wait(timeout=5)
                        result["leader_reaped"] = True
                    except subprocess.TimeoutExpired:
                        result["leader_reaped"] = False
        except BaseException:
            if process is not None and not result["leader_reaped"]:
                if process.returncode is not None:
                    # wait() may have reaped the leader before raising; its
                    # PID can already be reused, so do not signal that group.
                    raise RuntimeError("bounded child process termination could not be confirmed") from None
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                try:
                    process.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    raise RuntimeError("bounded child process termination could not be confirmed") from None
            raise
        finally:
            poller.close()
            if process is not None:
                process.stdout.close()
                process.stderr.close()
        for key, stream in (("stdout", stdout_file), ("stderr", stderr_file)):
            stream.flush()
            before = _p001_identity(os.fstat(stream.fileno())) if return_file_identities else None
            stream.seek(0)
            value = stream.read(log_limit + 1)
            if len(value) > log_limit:
                raise OSError("P0-03 captured log exceeds bound")
            if return_file_identities:
                after = _p001_identity(os.fstat(stream.fileno()))
                if before != after:
                    raise OSError("captured log changed during hashing")
                result[key + "_identity"] = after
            result[key + "_bytes"] = value
            result[key + "_sha256"] = sha256_bytes(value)
            result[key + "_size"] = len(value)
    return result


def paths_overlap(left: Path, right: Path) -> bool:
    """Return whether two resolved file paths are equal or ancestor-related."""
    left = left.resolve()
    right = right.resolve()
    return left == right or left in right.parents or right in left.parents


def path_is_inside(path: Path, parent: Path) -> bool:
    path = path.resolve()
    parent = parent.resolve()
    return path == parent or parent in path.parents


def source_manifest_identity(root: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        return build_manifest(root, DEFAULT_EXCLUDES), None
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as exc:
        return None, str(exc)


def summarize_status(checks: Iterable[Check]) -> str:
    statuses = [check.status for check in checks]
    if any(status == "FAIL" for status in statuses):
        return "FAIL"
    if any(status == "BLOCKED" for status in statuses):
        return "BLOCKED"
    if any(status == "NOT_RUN" for status in statuses):
        return "NOT_RUN"
    if any(status == "INCONCLUSIVE" for status in statuses):
        return "INCONCLUSIVE"
    return "PASS"


def denominator(checks: list[Check]) -> dict[str, int]:
    return {
        "total": len(checks),
        "passed": sum(check.status == "PASS" for check in checks),
        "failed": sum(check.status == "FAIL" for check in checks),
        "blocked": sum(check.status == "BLOCKED" for check in checks),
        "not_run": sum(check.status == "NOT_RUN" for check in checks),
        "inconclusive": sum(check.status == "INCONCLUSIVE" for check in checks),
    }


def base_report(command: str, root: Path, source_sha: str | None) -> dict[str, Any]:
    try:
        info = os.uname()
        platform_identity = f"{info.sysname}-{info.release}-{info.machine}"
    except (AttributeError, OSError):
        platform_identity = sys.platform
    return {
        "schema_version": SCHEMA,
        "scope": "ECP_PHASE0_ONLY",
        "product_gate_effect": "NONE",
        "command": command,
        "created_at": utc_now(),
        "source_root": str(root),
        "source_sha": source_sha,
        "environment": {
            "platform": platform_identity,
            "python": platform.python_version(),
            "cwd": str(Path.cwd()),
        },
        "database_connections_attempted": 0,
        "evidence_refs": [],
    }


def doctor(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    root = resolve_source_root(args.source_root)
    identity, source_sha, _ = check_source_identity(root)
    checks = [identity, check_required_inputs(root), *check_tools(), check_database_policy()]
    status = summarize_status(checks)
    report = base_report("doctor", root, source_sha)
    report.update(
        {
            "status": status,
            "reason": "; ".join(check.reason for check in checks if check.status != "PASS") or "all offline checks passed",
            "checks": [check.as_dict() for check in checks],
            "denominator": denominator(checks),
            "evidence_refs": list(args.evidence_ref),
        }
    )
    return finish_report(report, args.output, EXIT_CODES[status])


def status_from_value(value: Any) -> str | None:
    return value if isinstance(value, str) and value in STATUSES else None


def _report_claim_text(value: Any) -> str | None:
    """Keep a bounded, UTF-8-safe text claim without inventing a value."""
    if not isinstance(value, str) or len(value) > 4096:
        return None
    try:
        value.encode('utf-8', errors='strict')
    except UnicodeError:
        return None
    return value


def _aggregate_valid_evidence_refs(value: Any) -> bool:
    """Accept only arrays of UTF-8-encodable strings; impose no size policy."""
    if not isinstance(value, list):
        return False
    for ref in value:
        if not isinstance(ref, str):
            return False
        try:
            ref.encode('utf-8', errors='strict')
        except UnicodeError:
            return False
    return True


def aggregate_reports(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    root = resolve_source_root(args.source_root)
    expected_sha = args.source_sha
    if expected_sha is None:
        expected_sha, _ = git_sha(root)
    checks: list[Check] = []
    refs: list[str] = []
    input_shas: list[str] = []
    inputs_without_sha: list[str] = []
    inputs_with_invalid_sha: list[str] = []
    for raw_path in args.input:
        path = Path(raw_path).expanduser().resolve()
        refs.append(str(path))
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            checks.append(Check(f"input:{path}", "FAIL", f"cannot read valid JSON: {exc}", {"path": str(path)}))
            continue
        if not isinstance(value, dict):
            checks.append(Check(f"input:{path}", "FAIL", "evidence must be a JSON object", {"path": str(path)}))
            continue
        status = status_from_value(value.get("status") or value.get("overall_status") or value.get("gate_status"))
        if status is None:
            checks.append(Check(f"input:{path}", "FAIL", "evidence has no recognized status", {"path": str(path)}))
            continue
        input_sha = value.get("source_sha") or value.get("source_sha256")
        if isinstance(input_sha, str) and input_sha:
            if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", input_sha):
                input_shas.append(input_sha)
            else:
                inputs_with_invalid_sha.append(str(path))
        else:
            inputs_without_sha.append(str(path))
        raw_reason = value.get("reason")
        raw_qualification = value.get("qualification")
        declared_reason = _report_claim_text(raw_reason)
        declared_qualification = _report_claim_text(raw_qualification)
        status_claims = {key: text for key in ("status", "overall_status", "gate_status")
                         if key in value and (text := _report_claim_text(value[key])) is not None}
        details = {"path": str(path), "source_sha": input_sha,
                   "declared_status": status,
                   "declared_status_fields": status_claims,
                   "declared_reason": declared_reason,
                   "declared_reason_recorded": declared_reason is not None,
                   "declared_reason_present": "reason" in value,
                   "declared_reason_type": type(raw_reason).__name__,
                   "declared_qualification": declared_qualification,
                   "declared_qualification_recorded": declared_qualification is not None,
                   "declared_qualification_present": "qualification" in value,
                   "declared_qualification_type": type(raw_qualification).__name__}
        observed_status = "INCONCLUSIVE" if status == "PASS" else status
        reason = ("input reports PASS; the claim is not independently authenticated" if status == "PASS"
                  else declared_reason if declared_reason is not None else "input evidence status")
        declared_refs = value.get("evidence_refs", [])
        if not _aggregate_valid_evidence_refs(declared_refs):
            details["evidence_refs_error"] = "expected an array of UTF-8 strings"
            observed_status = "FAIL"
            reason = "input evidence_refs must be an array of UTF-8 strings"
        else:
            refs.extend(declared_refs)
        checks.append(Check(f"input:{path}", observed_status, reason, details))
    if expected_sha and not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", expected_sha):
        checks.append(Check("source_binding", "FAIL", "expected source SHA has invalid Git object ID syntax", {}))
    if inputs_with_invalid_sha:
        checks.append(Check("source_binding", "FAIL", "some input evidence declares an invalid source SHA",
                            {"paths": inputs_with_invalid_sha}))
    if checks and not expected_sha:
        checks.append(Check("source_binding", "INCONCLUSIVE", "expected source SHA is unavailable", {}))
    if inputs_without_sha:
        checks.append(Check("source_binding", "INCONCLUSIVE", "some input evidence does not declare a source SHA",
                            {"paths": inputs_without_sha}))
    if expected_sha and input_shas:
        mismatched = sorted({value for value in input_shas if value != expected_sha})
        if mismatched:
            checks.append(Check("source_binding", "FAIL", "evidence source SHA does not match the requested source", {"expected": expected_sha, "observed": mismatched}))
    status = summarize_status(checks) if checks else "NOT_RUN"
    if status == "PASS":
        checks.append(Check("independent_evidence_authentication", "INCONCLUSIVE",
                            "input status and source claims have not been independently authenticated", {}))
        status = "INCONCLUSIVE"
    report = base_report("report", root, expected_sha)
    report.update(
        {
            "status": status,
            "reason": "; ".join(check.reason for check in checks if check.status != "PASS") or "all input evidence passed",
            "checks": [check.as_dict() for check in checks],
            "denominator": denominator(checks),
            "denominator_scope": "input_claims_and_source_binding_diagnostics",
            "input_count": len(args.input),
            "evidence_refs": sorted(dict.fromkeys(refs)),
        }
    )
    return finish_report(report, args.output, EXIT_CODES[status])


def run_phase0_offline_suite(
    args: argparse.Namespace, root: Path, source_sha: str | None, report: dict[str, Any],
) -> tuple[dict[str, Any], int]:
    """Block P0-03 until source, execution and evidence isolation are established.

    This public entry intentionally runs no child, reads no registry and writes
    no output. The separate p003_sandbox helper remains a non-qualifying
    observation for caller-preverified trusted test inputs.
    """
    reason = ("P0-03 execution is blocked: authenticated source, principal, lease, "
              "resource confinement and evidence-directory isolation are not established")
    value = {
        "schema_version": SCHEMA, "scope": "ECP_PHASE0_ONLY", "product_gate_effect": "NONE",
        "command": "suite", "created_at": utc_now(), "source_root": str(root), "source_sha": None,
        "status": "BLOCKED", "qualification": "NOT_RUN", "suite_id": "ECP-P0-03",
        "profile": args.profile, "reason": reason, "workload_invoked": False,
        "workload_confinement_verified": False, "independent_execution_authority_verified": False,
        "database_connections_attempted": None, "evidence_refs": [],
        "checks": [{"name": "execution_authority", "status": "BLOCKED", "reason": reason, "details": {}}],
        "denominator": {"total": 1, "passed": 0, "failed": 0, "blocked": 1, "not_run": 0, "inconclusive": 0},
    }
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))
    return value, EXIT_CODES["BLOCKED"]


def _blocked_p001_v3(profile: str | None) -> tuple[dict[str, Any], int]:
    """Report a pre-execution block without inspecting source or evidence paths."""
    reason = "P0-01 v3 execution is blocked: process supervision is not verified"
    checks = [
        {"name": "process_supervision", "status": "BLOCKED", "reason": reason, "details": {}},
        *[{"name": name, "status": "NOT_RUN", "reason": "execution was blocked", "details": {}}
          for name in ("source_snapshot_v3", "isolated_materialization_v3", "independent_oracle_v3")],
    ]
    report = {
        "schema_version": SCHEMA, "scope": "ECP_PHASE0_ONLY", "product_gate_effect": "NONE",
        "command": "suite", "created_at": utc_now(), "source_root": None, "source_sha": None,
        "status": "BLOCKED", "qualification": "NOT_RUN", "suite_id": "ECP-P0-01",
        "profile": profile, "reason": reason, "workload_invoked": False,
        "database_connections_attempted": None, "evidence_refs": [], "checks": checks,
        "denominator": {"total": 4, "passed": 0, "failed": 0, "blocked": 1,
                        "not_run": 3, "inconclusive": 0},
    }
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return report, EXIT_CODES["BLOCKED"]


def suite(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    """Run only explicitly bound Phase 0 workloads; preserve missing work as NOT_RUN."""
    suite_id = args.suite or (f"phase-{args.phase}" if args.phase is not None else "release-candidate")
    if suite_id == "ECP-P0-01" and args.source_manifest_version == "3":
        return _blocked_p001_v3(args.profile)
    root = resolve_source_root(args.source_root)
    # P0-03 fails closed before Git, platform detection, registry reads or writes.
    if suite_id == "ECP-P0-03":
        return run_phase0_offline_suite(args, root, None, {})
    # No child Git command can establish source provenance or safely run under
    # an untrusted PATH here. The P0-02 source identity remains unknown until
    # an independently authenticated execution boundary is available.
    if suite_id == "ECP-P0-02":
        report = base_report('suite', root, None)
        if args.source_manifest_version == '3':
            report.update(status='BLOCKED', qualification='NOT_RUN', suite_id=suite_id,
                          reason='source manifest version 3 is only supported by ECP-P0-01',
                          checks=[], denominator={'total':0,'passed':0,'failed':0,'blocked':0,'not_run':0,'inconclusive':0})
            return finish_report(report, None, EXIT_CODES['BLOCKED'])
        return run_database_suite(args, root, None, report)
    # The P0-01 v3 route returned above; other v3 routes are blocked before Git.
    # P0-02 and P0-03 intentionally retain their earlier specialized handling.
    if args.source_manifest_version == '3':
        report = base_report("suite", root, None)
        report.update(status='BLOCKED', qualification='NOT_RUN', suite_id=suite_id,
                      reason='source manifest version 3 is only supported by ECP-P0-01',
                      checks=[], denominator={'total':0,'passed':0,'failed':0,'blocked':0,'not_run':0,'inconclusive':0})
        return finish_report(report, None, EXIT_CODES['BLOCKED'])
    # Preserve invalid-binding diagnostics, then fail closed before Git: the
    # current P0-05 runner lacks bounded process-tree supervision.
    if suite_id == "ECP-P0-05":
        registry_path, entry, error = load_declared_suite(root, suite_id)
        if error or not isinstance(entry, dict) or entry.get('implementation_entrypoint') != 'control/.github/workflows/ecp-baseline.yml':
            report = base_report("suite", root, None)
            report.update(status='BLOCKED', qualification='NOT_RUN', suite_id=suite_id,
                          reason=error or 'P0-05 registry entrypoint does not match the reviewed workflow',
                          checks=[{'name':'suite_registry_binding','status':'BLOCKED'}],
                          denominator={'total':1,'passed':0,'failed':0,'blocked':1,'not_run':0,'inconclusive':0})
            return finish_report(report, None, EXIT_CODES['BLOCKED'])
        reason = "P0-05 execution is blocked: bounded process-tree supervision is unavailable"
        report = base_report("suite", root, None)
        report.update(status="BLOCKED", qualification="NOT_RUN", suite_id=suite_id,
                      profile=args.profile, reason=reason, workload_invoked=False,
                      source_review="NOT_RUN", sandbox_probe="NOT_RUN",
                      registry_path=str(registry_path) if registry_path is not None else None,
                      registry_sha256=None, registry_authentication="UNVERIFIED",
                      workloads={name: "NOT_RUN" for name in
                                 ("npm_ci", "cargo_build", "cargo_test", "npm_build")},
                      checks=[{"name": "process_supervision", "status": "BLOCKED",
                               "reason": reason, "details": {}}],
                      denominator={"total": 4, "passed": 0, "failed": 0, "blocked": 0,
                                   "not_run": 4, "inconclusive": 0, "skipped": 0},
                      denominator_scope="declared_workloads")
        return finish_report(report, None, EXIT_CODES["BLOCKED"])
    # An undeclared suite must be rejected before starting the Git subprocess.
    # Keep the current paths for P0-01/P0-05 and the v3-version guard intact.
    # Unbound registered suites also do not require a Git source claim.
    generic_registry = None
    if args.source_manifest_version != "3" and suite_id not in ("ECP-P0-01", "ECP-P0-05"):
        generic_registry = load_declared_suite(root, suite_id)
    if suite_id == "ECP-P0-01" and args.source_manifest_version == "3":
        import source_snapshot as snapshot
        try:
            raw_sha = snapshot._v3_bounded_git(root, ["rev-parse", "HEAD"],
                bounded_child_timeout("ECP_SOURCE_SNAPSHOT_TIMEOUT_SECONDS", fallback_name="ECP_GIT_STATUS_TIMEOUT_SECONDS"))
            source_sha = raw_sha.decode("ascii", "strict").strip()
        except RuntimeError:
            report = base_report("suite", root, None)
            reason = "P0-01 bounded Git process termination could not be confirmed"
            report.update(status="INCONCLUSIVE", qualification="NOT_RUN", suite_id=suite_id,
                          profile=args.profile, reason=reason, workload_invoked=None, leader_reaped=None,
                          descendants_terminated=None, database_connections_attempted=None,
                          checks=[{"name":"git_process_termination", "status":"INCONCLUSIVE", "reason":reason, "details":{}}],
                          denominator={"total":1,"passed":0,"failed":0,"blocked":0,"not_run":0,"inconclusive":1})
            return finish_report(report, None, EXIT_CODES["INCONCLUSIVE"])
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            source_sha = None
    else:
        if generic_registry is not None:
            # Generic v2 suites are returned as unbound NOT_RUN or registry
            # BLOCKED below; neither path needs an unauthenticated Git probe.
            source_sha = None
        else:
            source_sha, _ = git_sha(root)
    report = base_report("suite", root, source_sha)

    if suite_id == "ECP-P0-01":
        if args.source_manifest_version == '3':
            return run_source_snapshot_v3_suite(args, root, source_sha, report)
        return run_source_snapshot_suite(args, root, source_sha, report)
    registry_path, declared_suite, registry_error = (
        generic_registry if generic_registry is not None else load_declared_suite(root, suite_id)
    )
    if registry_error:
        reason = registry_error
        report.update({
            "status": "BLOCKED", "qualification": "NOT_RUN", "suite_id": suite_id,
            "profile": args.profile, "reason": reason,
            "checks": [{"name": "suite_registry", "status": "BLOCKED", "reason": reason,
                        "details": {"registry_path": str(registry_path) if registry_path else None}}],
            "denominator": {"total": 1, "passed": 0, "failed": 0, "blocked": 1, "not_run": 0, "inconclusive": 0},
        })
        return finish_report(report, args.output, EXIT_CODES["BLOCKED"])

    reason = "suite is registered but has no bound executable workload/oracle"
    report.update(
        {
            "status": "NOT_RUN",
            "reason": reason,
            "suite_id": suite_id,
            "profile": args.profile,
            "checks": [
                {
                    "name": suite_id,
                    "status": "NOT_RUN",
                    "reason": reason,
                    "details": {"profile": args.profile, "evidence_root": args.evidence_root},
                }
            ],
            "denominator": {
                "total": 1,
                "passed": 0,
                "failed": 0,
                "blocked": 0,
                "not_run": 1,
                "inconclusive": 0,
            },
        }
    )
    return finish_report(report, args.output, EXIT_CODES["NOT_RUN"])


def _p001_open_directory(path: Path) -> int:
    """Open an absolute directory through no-follow component FDs."""
    absolute = Path(os.path.abspath(path))
    fd = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in absolute.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            old, fd = fd, child
            os.close(old)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _p001_identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _p001_open_relative_file(rootfd: int, relative: str) -> int:
    parts = relative.split('/')
    if not parts or any(part in ('', '.', '..') for part in parts):
        raise ValueError('unsafe source tool path')
    fd = os.dup(rootfd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            old, fd = fd, child
            os.close(old)
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    finally:
        os.close(fd)


def _p001_fd_bytes(fd: int, limit: int) -> tuple[bytes, tuple[int, ...]]:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ValueError('evidence input is not a bounded regular file')
    out = bytearray()
    while len(out) < before.st_size:
        part = os.pread(fd, min(1024 * 1024, before.st_size - len(out)), len(out))
        if not part:
            break
        out.extend(part)
    after = os.fstat(fd)
    if len(out) != before.st_size or _p001_identity(before) != _p001_identity(after):
        raise ValueError('evidence or source tool changed while reading')
    return bytes(out), _p001_identity(after)


def _p001_json(data: bytes) -> dict[str, Any]:
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    def bad_constant(_):
        raise ValueError('non-finite JSON value')
    try:
        result = json.loads(data.decode('utf-8', 'strict'), object_pairs_hook=pairs,
                            parse_constant=bad_constant)
    except RecursionError as exc:
        raise ValueError('excessive JSON nesting') from exc
    if not isinstance(result, dict):
        raise ValueError('expected JSON object')
    return result


def _p001_seal_tool(data: bytes) -> int:
    """Freeze already-hashed Python tool bytes before a child executes them."""
    if sys.platform != 'linux':
        raise ValueError('immutable in-memory tool execution requires Linux')
    flags = getattr(os,'MFD_CLOEXEC',1) | getattr(os,'MFD_ALLOW_SEALING',2)
    if hasattr(os,'memfd_create'):
        fd = os.memfd_create('ecp-p001-tool',flags)
    else:
        # Some Python builds omit the wrappers even when the Linux kernel and
        # libc provide memfd_create. The Linux UAPI values below are stable.
        import ctypes
        libc = ctypes.CDLL(None,use_errno=True)
        create = getattr(libc,'memfd_create',None)
        if create is None:
            raise ValueError('immutable in-memory tool execution is unavailable')
        create.argtypes = (ctypes.c_char_p,ctypes.c_uint)
        create.restype = ctypes.c_int
        fd = create(b'ecp-p001-tool',flags)
        if fd < 0:
            error = ctypes.get_errno()
            raise OSError(error,os.strerror(error))
    try:
        view = memoryview(data)
        while view:
            size = os.write(fd,view[:1024*1024])
            if size <= 0:
                raise OSError('short write while freezing tool')
            view = view[size:]
        seals = (getattr(fcntl,'F_SEAL_WRITE',8) | getattr(fcntl,'F_SEAL_GROW',4) |
                 getattr(fcntl,'F_SEAL_SHRINK',2) | getattr(fcntl,'F_SEAL_SEAL',1))
        add_seals = getattr(fcntl,'F_ADD_SEALS',1033)
        get_seals = getattr(fcntl,'F_GET_SEALS',1034)
        fcntl.fcntl(fd,add_seals,seals)
        if (fcntl.fcntl(fd,get_seals) & seals) != seals:
            raise ValueError('tool immutability seals were not applied')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _p001_write_json(dirfd: int, name: str, value: dict[str, Any]) -> tuple[bytes, tuple[int, ...]]:
    if '/' in name or name in ('', '.', '..'):
        raise ValueError('unsafe evidence filename')
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('utf-8')
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dirfd)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        identity = _p001_identity(os.fstat(stream.fileno()))
    return data, identity


def _p001_same_directory(path: Path, pinned_fd: int) -> bool:
    observed = _p001_open_directory(path)
    try:
        a, b = os.fstat(observed), os.fstat(pinned_fd)
        return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)
    finally:
        os.close(observed)


def _p001_has_ancestor(fd: int, ancestor: os.stat_result) -> bool:
    current = os.dup(fd)
    try:
        for _ in range(256):
            info = os.fstat(current)
            if (info.st_dev, info.st_ino) == (ancestor.st_dev, ancestor.st_ino):
                return True
            parent = os.open('..', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            try:
                other = os.fstat(parent)
            except BaseException:
                os.close(parent)
                raise
            if (other.st_dev, other.st_ino) == (info.st_dev, info.st_ino):
                os.close(parent)
                return False
            old, current = current, parent
            os.close(old)
        raise ValueError('directory ancestry exceeds safety budget')
    finally:
        os.close(current)


def _p001_backing_path(path: Path, mountinfo: str | None = None) -> tuple[str, str]:
    """Map a path to its mount device and filesystem-relative path.

    The mount root field is essential: an external bind mount can expose a
    source subdirectory while its visible parents never include source_root.
    """
    absolute = os.path.abspath(path)
    table = Path('/proc/self/mountinfo').read_text(encoding='utf-8') if mountinfo is None else mountinfo
    selected = None
    for line in table.splitlines():
        left, separator, right = line.partition(' - ')
        fields = left.split()
        if not separator or len(fields) < 6 or not right.split():
            raise ValueError('mount table is malformed')
        decode = lambda s: re.sub(r'\\([0-7]{3})',lambda m:chr(int(m.group(1),8)),s)
        mount = decode(fields[4]); fs_root = decode(fields[3])
        if absolute == mount or absolute.startswith(mount.rstrip('/') + '/'):
            if selected is None or len(mount) > len(selected[1]):
                selected = (fields[2],mount,fs_root)
    if selected is None:
        raise ValueError('mount identity is unavailable')
    device,mount,fs_root = selected
    suffix = absolute[len(mount):].lstrip('/') if mount != '/' else absolute.lstrip('/')
    return device,posixpath.normpath(posixpath.join(fs_root,suffix))


def _p001_parent_aliases_source(source: Path, parent: Path) -> bool:
    table = Path('/proc/self/mountinfo').read_text(encoding='utf-8')
    source_device, source_backing = _p001_backing_path(source, table)
    parent_device, parent_backing = _p001_backing_path(parent, table)
    return source_device == parent_device and (parent_backing == source_backing or
                                                parent_backing.startswith(source_backing.rstrip('/') + '/'))


def run_source_snapshot_v3_suite(args: argparse.Namespace, root: Path, source_sha: str | None,
                                 report: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """Block the draft v3 chain until process supervision is verified."""
    return _blocked_p001_v3(getattr(args, "profile", None))
    checks = [
        {'name':'source_snapshot_v3','status':'NOT_RUN','reason':'source observation not run','details':{}},
        {'name':'isolated_materialization_v3','status':'NOT_RUN','reason':'materialization not run','details':{}},
        {'name':'independent_oracle_v3','status':'NOT_RUN','reason':'oracle not run','details':{}},
    ]
    rootfd = parentfd = evidencefd = snapshot_scriptfd = material_scriptfd = oracle_scriptfd = None
    snapshot_sealedfd = material_sealedfd = oracle_sealedfd = None
    manifestfd = receiptfd = candidate_parentfd = None
    evidence = None
    captured = []
    artifact_expected = {}
    manifest_raw = manifest_identity = receipt_raw = receipt_identity = None
    snapshot = material = oracle = None
    candidate = None
    publication_possible = False
    capture_stage = None
    failure = None
    reason = 'draft v3 observation is not a formal qualification'
    def capture_details(capture):
        return {key:capture.get(key) for key in ('started','exit_code','capture_complete','leader_reaped',
                'termination_reason','group_signal','descendants_terminated')}
    def capture_failure(capture):
        details = capture_details(capture)
        stderr = capture.get('stderr_bytes', b'')
        unknown_nested = any(marker in stderr for marker in
                             (b'process termination could not be confirmed', b'process-group termination could not be confirmed'))
        if b'GIT_TERMINATION_UNCONFIRMED' in capture.get('stdout_bytes', b''):
            unknown_nested = True
        try:
            nested = _p001_json(capture.get('stdout_bytes', b''))
        except (ValueError, UnicodeError, TypeError):
            nested = {}
        nested_inconclusive = capture.get('exit_code') == 20
        if nested.get('reason_code') == 'GIT_TERMINATION_UNCONFIRMED':
            unknown_nested = True
        if ({'leader_reaped','group_signal','descendants_terminated'} <= set(nested)
                and capture.get('exit_code') == 20 and nested.get('status') == 'INCONCLUSIVE'
                and nested.get('qualification') == 'NOT_RUN' and nested.get('product_gate_effect') == 'NONE'
                and nested.get('reason_code') == 'GIT_TERMINATION_UNCONFIRMED'
                and (nested.get('leader_reaped') is None or type(nested.get('leader_reaped')) is bool)
                and nested.get('group_signal') in ('FAILED', 'NOT_SENT_LEADER_REAPED', 'SENT', 'NO_SUCH_GROUP')
                and nested.get('descendants_terminated') is None):
            unknown_nested = True
            details['nested_leader_reaped'] = nested['leader_reaped']
            details['nested_group_signal'] = nested['group_signal']
            details['nested_descendants_terminated'] = None
            git_capture = nested.get('git_capture')
            if (isinstance(git_capture, dict) and git_capture.get('status') == 'UNKNOWN'
                    and git_capture.get('raw_output_persistence') == 'UNAVAILABLE'
                    and all(type(git_capture.get(k)) is int and 0 <= git_capture[k] <= P003_MAX_LOG_BYTES
                            for k in ('stdout_bytes','stderr_bytes'))
                    and all(isinstance(git_capture.get(k), str) and re.fullmatch(r'[0-9a-f]{64}',git_capture[k])
                            for k in ('stdout_sha256','stderr_sha256'))):
                details['nested_git_capture'] = {key:git_capture[key] for key in
                    ('status','stdout_bytes','stdout_sha256','stderr_bytes','stderr_sha256','raw_output_persistence')}
        if capture.get('started') is False:
            return 'BLOCKED', details
        if (capture.get('started') is not True or not capture.get('capture_complete') or not capture.get('leader_reaped')
                or capture.get('group_signal') not in ('NOT_SENT', 'SIGKILL_SENT', 'GROUP_NOT_FOUND')
                or unknown_nested or nested_inconclusive):
            details['nested_process_termination_unknown'] = True if unknown_nested else None
            if nested_inconclusive:
                details['nested_protocol_status'] = ('INCONCLUSIVE' if nested.get('status') == 'INCONCLUSIVE'
                                                     and nested.get('product_gate_effect') == 'NONE' else 'UNVERIFIED_EXIT_20')
            if unknown_nested or nested_inconclusive:
                for field in ('nested_leader_reaped','nested_group_signal','nested_descendants_terminated'):
                    details.setdefault(field, None)
            return 'INCONCLUSIVE', details
        return 'FAIL', details
    try:
        if args.profile != 'isolated':
            raise ValueError('v3 only supports the isolated profile')
        if not args.evidence_root:
            raise ValueError('v3 requires an explicit fresh evidence root')
        if not isinstance(source_sha, str) or not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', source_sha):
            raise ValueError('source SHA is unavailable or malformed')
        source_raw = Path(os.path.abspath(Path(args.source_root).expanduser())) if args.source_root else root
        if source_raw != root:
            raise ValueError('source path resolves through a symlink')
        evidence = Path(os.path.abspath(Path(args.evidence_root).expanduser()))
        candidate = Path(os.path.abspath(Path(args.candidate_root).expanduser())) if args.candidate_root else None
        external_output = Path(os.path.abspath(Path(args.output).expanduser())) if args.output else None
        def overlaps(a, b):
            return a == b or a in b.parents or b in a.parents
        if overlaps(root, evidence) or (candidate and (overlaps(root, candidate) or overlaps(evidence, candidate))):
            raise ValueError('source, candidate and evidence paths must be disjoint')
        if external_output is not None and external_output != evidence / 'result.json':
            raise ValueError('v3 output must be evidence-root/result.json')
        rootfd = _p001_open_directory(root)
        parentfd = _p001_open_directory(evidence.parent)
        source_info = os.fstat(rootfd)
        if _p001_has_ancestor(parentfd, source_info) or _p001_parent_aliases_source(root,evidence.parent):
            raise ValueError('evidence parent aliases the source tree')
        if candidate:
            candidate_parentfd = _p001_open_directory(candidate.parent)
            if _p001_has_ancestor(candidate_parentfd, source_info) or _p001_parent_aliases_source(root,candidate.parent):
                raise ValueError('candidate parent aliases the source tree')
            try:
                os.stat(candidate.name, dir_fd=candidate_parentfd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError('candidate destination already exists')
        snapshot_scriptfd = _p001_open_relative_file(rootfd, 'ops/ecp/source_snapshot.py')
        snapshot_script, snapshot_identity = _p001_fd_bytes(snapshot_scriptfd, 2 * 1024 * 1024)
        snapshot_sealedfd = _p001_seal_tool(snapshot_script)
        os.mkdir(evidence.name, 0o700, dir_fd=parentfd)
        evidencefd = os.open(evidence.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parentfd)
        evidence_proc = Path(f'/proc/self/fd/{evidencefd}')
        allowed = ('HOME','LANG','LANGUAGE','LC_ALL','LC_CTYPE',
                   'ECP_SOURCE_SNAPSHOT_TIMEOUT_SECONDS','ECP_GIT_STATUS_TIMEOUT_SECONDS')
        env = {key:os.environ[key] for key in allowed if key in os.environ}
        env['PATH'] = '/usr/bin:/bin'
        timeout = bounded_child_timeout('ECP_SOURCE_SNAPSHOT_TIMEOUT_SECONDS', fallback_name='ECP_GIT_STATUS_TIMEOUT_SECONDS')
        source_code = ("import importlib.machinery,json,sys; from pathlib import Path; "
                       "m=importlib.machinery.SourceFileLoader('source_snapshot',sys.argv[1]).load_module(); "
                       "v=m.build_manifest_v3(Path(sys.argv[2]),m.V3_EXCLUDES); "
                       "sys.stdout.write(json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False))")
        source_cmd = [sys.executable, '-I', '-S', '-c', source_code, f'/proc/self/fd/{snapshot_sealedfd}', str(root)]
        captured.extend(['source.stdout.log','source.stderr.log'])
        capture_stage = 'source'
        source_capture = run_p003_bounded(source_cmd, cwd=Path(f'/proc/self/fd/{rootfd}'), env=env,
            stdout_path=evidence_proc/'source.stdout.log', stderr_path=evidence_proc/'source.stderr.log',
            timeout=timeout, pass_fds=(rootfd,snapshot_sealedfd),return_file_identities=True)
        capture_stage = None
        for stream in ('stdout','stderr'):
            artifact_expected[f'source.{stream}.log'] = (source_capture[f'{stream}_sha256'],source_capture[f'{stream}_size'],source_capture[f'{stream}_identity'])
        if not source_capture['capture_complete'] or not source_capture['leader_reaped'] or source_capture['exit_code'] != 0:
            failure, details = capture_failure(source_capture)
            checks[0].update(status=failure, reason='v3 source process or bounded capture did not complete', details=details)
            raise RuntimeError(checks[0]['reason'])
        snapshot = _p001_json(source_capture['stdout_bytes'])
        core = {k:v for k,v in snapshot.items() if k not in ('manifest_sha256','created_at','release_qualifiable')}
        digest = hashlib.sha256(json.dumps(core,ensure_ascii=False,sort_keys=True,separators=(',',':'),
                                           allow_nan=False).encode('utf-8')).hexdigest()
        projection = snapshot.get('directory_projection')
        if (snapshot.get('schema_version') != 'forgeflow.ecp-source-manifest.v3' or
                snapshot.get('source_root') != str(root) or snapshot.get('head') != source_sha or
                snapshot.get('worktree_state') != 'CLEAN' or snapshot.get('inventory_complete') is not True or
                snapshot.get('release_qualifiable') is not False or snapshot.get('manifest_sha256') != digest or
                not isinstance(projection,dict) or projection.get('mode_availability') not in ('VERIFIED','UNAVAILABLE')):
            checks[0].update(status='FAIL',reason='v3 source manifest identity or draft contract is invalid')
            failure = 'FAIL'
            raise RuntimeError(checks[0]['reason'])
        if not _p001_same_directory(root,rootfd):
            checks[0].update(status='FAIL',reason='source directory identity changed')
            failure = 'FAIL'
            raise RuntimeError(checks[0]['reason'])
        current_script, current_script_identity = _p001_fd_bytes(snapshot_scriptfd,2*1024*1024)
        if (current_script,current_script_identity) != (snapshot_script,snapshot_identity):
            checks[0].update(status='FAIL',reason='source snapshot tool changed during observation')
            failure = 'FAIL'
            raise RuntimeError(checks[0]['reason'])
        captured.append('source-snapshot.json')
        manifest_serialized, serialized_identity = _p001_write_json(evidencefd,'source-snapshot.json',snapshot)
        artifact_expected['source-snapshot.json'] = (hashlib.sha256(manifest_serialized).hexdigest(),len(manifest_serialized),serialized_identity)
        manifestfd = os.open('source-snapshot.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=evidencefd)
        manifest_raw, manifest_identity = _p001_fd_bytes(manifestfd,16*1024*1024)
        if (manifest_raw,manifest_identity) != (manifest_serialized,serialized_identity):
            raise ValueError('source snapshot path was replaced after writing')
        checks[0].update(status='INCONCLUSIVE',reason='v3 source observed; draft is not release-qualified',
                         details={'manifest_sha256':digest,'mode_availability':projection['mode_availability'],
                                  'source_tool_sha256':hashlib.sha256(snapshot_script).hexdigest(),
                                  **capture_details(source_capture)})
        if candidate is None:
            reason = 'draft source observed; materialization and independent oracle were not requested'
        elif projection['mode_availability'] != 'VERIFIED':
            checks[1].update(status='BLOCKED',reason='source directory modes are unavailable; no candidate was created')
            failure = 'BLOCKED'
            reason = checks[1]['reason']
        else:
            material_scriptfd = _p001_open_relative_file(rootfd,'ops/ecp/materialize_snapshot.py')
            oracle_scriptfd = _p001_open_relative_file(rootfd,'verification/ecp/p005_snapshot_oracle.py')
            material_script, material_identity = _p001_fd_bytes(material_scriptfd, 2 * 1024 * 1024)
            oracle_script, oracle_identity = _p001_fd_bytes(oracle_scriptfd, 2 * 1024 * 1024)
            if b'--manifest-fd' not in oracle_script or b'--receipt-fd' not in oracle_script:
                checks[1].update(status='BLOCKED',reason='independent oracle does not support pinned evidence FDs')
                failure = 'BLOCKED'
                reason = checks[1]['reason']
            else:
                material_sealedfd = _p001_seal_tool(material_script)
                oracle_sealedfd = _p001_seal_tool(oracle_script)
                material_code = ("import importlib.machinery,json,os,sys; from pathlib import Path; "
                    "importlib.machinery.SourceFileLoader('source_snapshot',sys.argv[1]).load_module(); "
                    "m=importlib.machinery.SourceFileLoader('materialize_snapshot',sys.argv[2]).load_module(); "
                    "fd=int(sys.argv[3]); data=os.pread(fd,16777217,0); v=json.loads(data); "
                    "r=m.materialize_snapshot_v3(Path(sys.argv[4]),v,Path(sys.argv[5]),candidate_parent_fd=int(sys.argv[6])); "
                    "sys.stdout.write(json.dumps(r,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False))")
                material_cmd = [sys.executable,'-I','-S','-c',material_code,f'/proc/self/fd/{snapshot_sealedfd}',
                                f'/proc/self/fd/{material_sealedfd}',str(manifestfd),str(root),str(candidate),str(candidate_parentfd)]
                captured.extend(['materialization.stdout.log','materialization.stderr.log'])
                if not _p001_same_directory(candidate.parent,candidate_parentfd):
                    raise ValueError('candidate parent path no longer binds its pinned directory')
                # Once the child may start, an error cannot prove whether a
                # destination was published; never delete an uncertain tree.
                publication_possible = True
                capture_stage = 'materialization'
                material_capture = run_p003_bounded(material_cmd,cwd=Path(f'/proc/self/fd/{rootfd}'),env=env,
                    stdout_path=evidence_proc/'materialization.stdout.log',stderr_path=evidence_proc/'materialization.stderr.log',
                    timeout=120.0,pass_fds=(rootfd,snapshot_sealedfd,material_sealedfd,manifestfd,candidate_parentfd),return_file_identities=True)
                capture_stage = None
                for stream in ('stdout','stderr'):
                    artifact_expected[f'materialization.{stream}.log'] = (material_capture[f'{stream}_sha256'],material_capture[f'{stream}_size'],material_capture[f'{stream}_identity'])
                if not material_capture['capture_complete'] or not material_capture['leader_reaped'] or material_capture['exit_code'] != 0:
                    failure, details = capture_failure(material_capture)
                    details['candidate_root'] = str(candidate)
                    checks[1].update(status=failure,reason='v3 materialization or bounded capture did not complete; candidate may have been retained',
                                     details=details)
                    raise RuntimeError(checks[1]['reason'])
                material = _p001_json(material_capture['stdout_bytes'])
                candidate_digest = material.get('candidate_inventory_v3_sha256')
                if (not isinstance(candidate_digest,str) or re.fullmatch(r'[0-9a-f]{64}',candidate_digest) is None or
                        material.get('status') != 'OBSERVED_NOT_GATE' or material.get('qualification') != 'NOT_RUN' or
                        material.get('product_gate_effect') != 'NONE' or material.get('release_qualifiable') is not False or
                        material.get('source_manifest_sha256') != digest or material.get('candidate_root') != str(candidate)):
                    checks[1].update(status='FAIL',reason='materialization emitted an invalid draft receipt; candidate retained')
                    failure = 'FAIL'
                    raise RuntimeError(checks[1]['reason'])
                captured.append('materialization.json')
                receipt_serialized, serialized_identity = _p001_write_json(evidencefd,'materialization.json',material)
                artifact_expected['materialization.json'] = (hashlib.sha256(receipt_serialized).hexdigest(),len(receipt_serialized),serialized_identity)
                receiptfd = os.open('materialization.json',os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,dir_fd=evidencefd)
                receipt_raw, receipt_identity = _p001_fd_bytes(receiptfd,4*1024*1024)
                if (receipt_raw,receipt_identity) != (receipt_serialized,serialized_identity):
                    raise ValueError('materialization receipt path was replaced after writing')
                checks[1].update(status='INCONCLUSIVE',reason='v3 candidate observed; formal qualification remains unproven',
                                 details={'candidate_root':str(candidate),'candidate_inventory_v3_sha256':material.get('candidate_inventory_v3_sha256'),
                                          'materializer_sha256':hashlib.sha256(material_script).hexdigest(),
                                          **capture_details(material_capture)})
                oracle_cmd = [sys.executable,'-I','-S',f'/proc/self/fd/{oracle_sealedfd}','--manifest-version','3',
                              '--source',str(root),'--candidate',str(candidate),'--manifest-fd',str(manifestfd),
                              '--receipt-fd',str(receiptfd),'--source-sha',source_sha,'--manifest-sha256',digest]
                captured.extend(['oracle.stdout.log','oracle.stderr.log'])
                capture_stage = 'oracle'
                oracle_capture = run_p003_bounded(oracle_cmd,cwd=Path(f'/proc/self/fd/{rootfd}'),env=env,
                    stdout_path=evidence_proc/'oracle.stdout.log',stderr_path=evidence_proc/'oracle.stderr.log',
                    timeout=180.0,pass_fds=(rootfd,oracle_sealedfd,manifestfd,receiptfd),return_file_identities=True)
                capture_stage = None
                for stream in ('stdout','stderr'):
                    artifact_expected[f'oracle.{stream}.log'] = (oracle_capture[f'{stream}_sha256'],oracle_capture[f'{stream}_size'],oracle_capture[f'{stream}_identity'])
                if not oracle_capture['capture_complete'] or not oracle_capture['leader_reaped'] or oracle_capture['exit_code'] != 0:
                    failure, details = capture_failure(oracle_capture)
                    checks[2].update(status=failure,reason='independent oracle or bounded capture did not complete; candidate retained',
                                     details=details)
                    raise RuntimeError(checks[2]['reason'])
                oracle = _p001_json(oracle_capture['stdout_bytes'])
                oracle_digest = oracle.get('candidate_inventory_v3_sha256')
                if (not isinstance(oracle_digest,str) or re.fullmatch(r'[0-9a-f]{64}',oracle_digest) is None or
                        oracle.get('status') != 'OBSERVED_NOT_GATE' or oracle.get('qualification') != 'NOT_RUN' or
                        oracle.get('product_gate_effect') != 'NONE' or oracle.get('source_manifest_sha256') != digest or
                        oracle_digest != candidate_digest):
                    checks[2].update(status='FAIL',reason='independent oracle emitted an invalid observation')
                    failure = 'FAIL'
                    raise RuntimeError(checks[2]['reason'])
                for fd, raw, identity in ((manifestfd,manifest_raw,manifest_identity),(receiptfd,receipt_raw,receipt_identity),
                                          (snapshot_scriptfd,snapshot_script,snapshot_identity),
                                          (material_scriptfd,material_script,material_identity),(oracle_scriptfd,oracle_script,oracle_identity)):
                    now, now_identity = _p001_fd_bytes(fd,16*1024*1024)
                    if now != raw or now_identity != identity:
                        raise ValueError('pinned source tool or evidence changed during observation')
                if not _p001_same_directory(root,rootfd):
                    raise ValueError('source directory identity changed during observation')
                if not _p001_same_directory(candidate.parent,candidate_parentfd):
                    raise ValueError('candidate parent identity changed during observation')
                captured.append('oracle.json')
                oracle_serialized, oracle_identity_result = _p001_write_json(evidencefd,'oracle.json',oracle)
                artifact_expected['oracle.json'] = (hashlib.sha256(oracle_serialized).hexdigest(),len(oracle_serialized),oracle_identity_result)
                checks[2].update(status='INCONCLUSIVE',reason='independent algorithm observed matching candidate; execution authority not established',
                                 details={'oracle_sha256':hashlib.sha256(oracle_script).hexdigest(),
                                          'candidate_inventory_v3_sha256':oracle.get('candidate_inventory_v3_sha256'),
                                          **capture_details(oracle_capture)})
                reason = 'v3 source, materialization and independent algorithm observed; draft and authority remain unqualified'
    except (OSError, ValueError, UnicodeError, RuntimeError, RecursionError, json.JSONDecodeError) as exc:
        if failure is None:
            unknown_stop = capture_stage is not None or (isinstance(exc, RuntimeError) and str(exc) == 'bounded child process termination could not be confirmed')
            failure = 'INCONCLUSIVE' if unknown_stop else 'BLOCKED' if evidencefd is None or isinstance(exc,FileExistsError) else 'FAIL'
            first = checks[{'source':0,'materialization':1,'oracle':2}[capture_stage]] if capture_stage else next((row for row in checks if row['status'] == 'NOT_RUN'),checks[0])
            first.update(status=failure,reason=f'v3 observation unavailable: {type(exc).__name__}: {exc}')
            if unknown_stop:
                first['details'] = {'capture_stage':capture_stage, 'started':None, 'leader_reaped':None,
                                    'group_signal':None, 'descendants_terminated':None}
        reason = reason if reason != 'draft v3 observation is not a formal qualification' else str(exc)
    finally:
        artifacts = {}
        candidate_publication = None
        if publication_possible and candidate is not None:
            try:
                parent_observed = os.readlink(f'/proc/self/fd/{candidate_parentfd}')
            except OSError:
                parent_observed = 'unavailable'
            candidate_publication = {'state':'POSSIBLY_PUBLISHED_RETAINED' if failure else 'OBSERVED_NOT_GATE',
                                     'candidate_root':str(candidate),'pinned_parent_last_path':parent_observed,
                                     'cleanup_attempted':False}
        if evidencefd is not None:
            try:
                if evidence is None or not _p001_same_directory(evidence,evidencefd):
                    raise ValueError('evidence directory identity changed')
                for fd, raw, identity in ((manifestfd,manifest_raw,manifest_identity),(receiptfd,receipt_raw,receipt_identity)):
                    if fd is not None and _p001_fd_bytes(fd,16*1024*1024) != (raw,identity):
                        raise ValueError('pinned evidence changed during observation')
                for name in captured:
                    try:
                        fd = os.open(name,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,dir_fd=evidencefd)
                    except FileNotFoundError:
                        if name in artifact_expected:
                            raise ValueError('expected captured evidence is missing')
                        artifacts[name] = {'state':'NOT_CREATED'}
                        continue
                    try:
                        data, identity = _p001_fd_bytes(fd,16*1024*1024)
                    finally:
                        os.close(fd)
                    observed = (hashlib.sha256(data).hexdigest(),len(data),identity)
                    expected = artifact_expected.get(name)
                    if expected is not None and observed != expected:
                        raise ValueError('captured evidence bytes changed during observation')
                    artifacts[name] = {'sha256':observed[0],'bytes':observed[1]}
                    if expected is None:
                        artifacts[name]['capture_complete'] = False
                        artifacts[name]['state'] = 'UNATTRIBUTED_RETAINED'
            except (OSError,ValueError):
                failure = 'FAIL'; reason = 'evidence directory or captured artifact identity is unavailable; retained through its pinned FD'
                checks.append({'name':'evidence_integrity','status':'FAIL','reason':reason,'details':{}})
        statuses = [row['status'] for row in checks]
        status = 'FAIL' if failure == 'FAIL' or 'FAIL' in statuses else 'BLOCKED' if failure == 'BLOCKED' or 'BLOCKED' in statuses else 'INCONCLUSIVE'
        if failure and candidate_publication:
            candidate_publication['state'] = 'POSSIBLY_PUBLISHED_RETAINED'
            reason += '; candidate may already be published and was retained'
        report.update({'status':status,'qualification':'NOT_RUN','suite_id':'ECP-P0-01','profile':args.profile,
                       'reason':reason,'source_manifest_version':'3','product_gate_effect':'NONE',
                       'independent_execution_authority_verified':False,
                       'scope_limitations':['draft v3 is not release-qualifiable',
                           'oracle reads source and candidate by nofollow paths with before/after identity checks, not anchored FDs',
                           'source and candidate observations are not atomic',
                           'child network, database, HOME access and escaped descendants are not confined',
                           'process-group signalling assumes no external reaper; descendant termination remains unknown',
                           'no principal, lease or authenticated execution authority established'],
                       'checks':checks,'artifact_digests':artifacts,
                       'denominator':{'total':len(checks),'passed':0,'failed':statuses.count('FAIL'),
                                      'blocked':statuses.count('BLOCKED'),'not_run':statuses.count('NOT_RUN'),
                                      'inconclusive':statuses.count('INCONCLUSIVE')},
                       'source_snapshot':({'path':str(evidence/'source-snapshot.json'),
                                           'manifest_sha256':snapshot.get('manifest_sha256'),
                                           'worktree_state':snapshot.get('worktree_state'),
                                           'directory_mode':snapshot.get('directory_projection',{}).get('mode_availability')}
                                          if snapshot and evidence else None),
                       'materialization':material,'oracle':oracle,'candidate_publication':candidate_publication,
                       'evidence_refs':[str(evidence/name) for name in captured
                                        if name in artifact_expected and name in artifacts and artifacts[name].get('state') != 'NOT_CREATED'] if evidence else []})
        if evidencefd is not None:
            try:
                _p001_write_json(evidencefd,'result.json',report)
            except (OSError,ValueError,TypeError) as exc:
                reason=f'evidence report could not be written exclusively: {type(exc).__name__}'
                checks.append({'name':'evidence_report','status':'FAIL','reason':reason,'details':{}})
                report.update(status='FAIL',qualification='NOT_RUN',reason=reason,
                              denominator={'total':len(checks),'passed':0,
                                  'failed':sum(c['status']=='FAIL' for c in checks),
                                  'blocked':sum(c['status']=='BLOCKED' for c in checks),
                                  'not_run':sum(c['status']=='NOT_RUN' for c in checks),
                                  'inconclusive':sum(c['status']=='INCONCLUSIVE' for c in checks)})
        for fd in (receiptfd,manifestfd,oracle_sealedfd,material_sealedfd,snapshot_sealedfd,
                   oracle_scriptfd,material_scriptfd,snapshot_scriptfd,candidate_parentfd,evidencefd,parentfd,rootfd):
            if fd is not None:
                os.close(fd)
    return finish_report(report, None, EXIT_CODES[report['status']])


def run_source_snapshot_suite(
    args: argparse.Namespace,
    root: Path,
    source_sha: str | None,
    report: dict[str, Any],
) -> tuple[dict[str, Any], int]:
    """Capture the P0-01 source snapshot and optionally materialize a candidate."""
    suite_id = "ECP-P0-01"
    output_path = Path(args.output).expanduser().resolve() if args.output else None
    if args.output and path_is_inside(Path(args.output).expanduser(), root):
        reason = "P0-01 output path must be outside the source root"
        report.update({
            "status": "BLOCKED", "qualification": "NOT_RUN", "reason": reason,
            "suite_id": suite_id, "profile": args.profile,
            "checks": [{"name": "evidence_path_safety", "status": "BLOCKED", "reason": reason,
                        "details": {"source_root": str(root), "output_path": str(Path(args.output).expanduser().resolve())}}],
            "denominator": {"total": 1, "passed": 0, "failed": 0, "blocked": 1, "not_run": 0, "inconclusive": 0},
        })
        return finish_report(report, None, EXIT_CODES["BLOCKED"])
    if not args.evidence_root:
        reason = "P0-01 requires an explicit evidence root; no source snapshot was written"
        report.update({
            "status": "NOT_RUN",
            "qualification": "NOT_RUN",
            "reason": reason,
            "suite_id": suite_id,
            "profile": args.profile,
            "checks": [{"name": suite_id, "status": "NOT_RUN", "reason": reason,
                        "details": {"evidence_root": None, "source_snapshot_invoked": False}}],
            "denominator": {"total": 1, "passed": 0, "failed": 0, "blocked": 0, "not_run": 1, "inconclusive": 0},
        })
        return finish_report(report, args.output, EXIT_CODES["NOT_RUN"])

    evidence_root = Path(args.evidence_root).expanduser().resolve()
    snapshot_path = evidence_root / "source-snapshot.json"
    unsafe_paths = [path for path in (evidence_root, snapshot_path) if path_is_inside(path, root)]
    if unsafe_paths:
        reason = "P0-01 evidence and output paths must be outside the source root"
        report.update({
            "status": "BLOCKED", "qualification": "NOT_RUN", "reason": reason,
            "suite_id": suite_id, "profile": args.profile,
            "checks": [{"name": "evidence_path_safety", "status": "BLOCKED", "reason": reason,
                        "details": {"source_root": str(root), "unsafe_paths": [str(path) for path in unsafe_paths]}}],
            "denominator": {"total": 1, "passed": 0, "failed": 0, "blocked": 1, "not_run": 0, "inconclusive": 0},
        })
        return finish_report(report, None, EXIT_CODES["BLOCKED"])
    if output_path is not None and any(paths_overlap(output_path, path) for path in (evidence_root, snapshot_path)):
        reason = "P0-01 output path collides with the evidence directory or source snapshot"
        report.update({
            "status": "BLOCKED", "qualification": "NOT_RUN", "reason": reason,
            "suite_id": suite_id, "profile": args.profile,
            "checks": [{"name": "evidence_path_collision", "status": "BLOCKED", "reason": reason,
                        "details": {"output_path": str(output_path), "evidence_root": str(evidence_root),
                                    "snapshot_path": str(snapshot_path)}}],
            "denominator": {"total": 1, "passed": 0, "failed": 0, "blocked": 1, "not_run": 0, "inconclusive": 0},
        })
        return finish_report(report, None, EXIT_CODES["BLOCKED"])
    runner = root / "ops" / "ecp" / "source_snapshot.py"
    if not runner.is_file():
        reason = "canonical source snapshot runner is missing"
        report.update({
            "status": "FAIL", "qualification": "NOT_RUN", "reason": reason,
            "suite_id": suite_id, "profile": args.profile,
            "checks": [{"name": "source_snapshot", "status": "FAIL", "reason": reason,
                        "details": {"runner": str(runner)}}],
            "denominator": {"total": 1, "passed": 0, "failed": 1, "blocked": 0, "not_run": 0, "inconclusive": 0},
        })
        return finish_report(report, args.output, EXIT_CODES["FAIL"])
    if os.path.lexists(snapshot_path):
        reason = "evidence source-snapshot.json already exists; refusing to overwrite immutable evidence"
        report.update({
            "status": "BLOCKED", "qualification": "NOT_RUN", "reason": reason,
            "suite_id": suite_id, "profile": args.profile,
            "checks": [{"name": "source_snapshot", "status": "BLOCKED", "reason": reason,
                        "details": {"snapshot_path": str(snapshot_path)}}],
            "denominator": {"total": 1, "passed": 0, "failed": 0, "blocked": 1, "not_run": 0, "inconclusive": 0},
        })
        return finish_report(report, args.output, EXIT_CODES["BLOCKED"])
    timeout_seconds = bounded_child_timeout(
        "ECP_SOURCE_SNAPSHOT_TIMEOUT_SECONDS",
        fallback_name="ECP_GIT_STATUS_TIMEOUT_SECONDS",
    )
    try:
        evidence_root.mkdir(parents=True, exist_ok=True)
        completed = subprocess.run(
            [sys.executable, str(runner), "--source-root", str(root), "--output", str(snapshot_path)],
            cwd=root, text=True, capture_output=True, timeout=timeout_seconds, check=False,
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired as exc:
        reason = f"source snapshot command exceeded {timeout_seconds:g} seconds"
        report.update({
            "status": "INCONCLUSIVE", "qualification": "NOT_RUN", "reason": reason,
            "suite_id": suite_id, "profile": args.profile,
            "checks": [{"name": "source_snapshot", "status": "INCONCLUSIVE", "reason": reason,
                        "details": {"runner": str(runner), "timeout_seconds": timeout_seconds,
                                    "stdout": exc.stdout or "", "stderr": exc.stderr or ""}}],
            "denominator": {"total": 1, "passed": 0, "failed": 0, "blocked": 0, "not_run": 0, "inconclusive": 1},
        })
        return finish_report(report, args.output, EXIT_CODES["INCONCLUSIVE"])
    except (OSError, ValueError) as exc:
        reason = f"source snapshot command could not start: {exc}"
        report.update({
            "status": "FAIL", "qualification": "NOT_RUN", "reason": reason,
            "suite_id": suite_id, "profile": args.profile,
            "checks": [{"name": "source_snapshot", "status": "FAIL", "reason": reason,
                        "details": {"runner": str(runner)}}],
            "denominator": {"total": 1, "passed": 0, "failed": 1, "blocked": 0, "not_run": 0, "inconclusive": 0},
        })
        return finish_report(report, args.output, EXIT_CODES["FAIL"])

    raw = "\n".join(line for line in completed.stdout.splitlines() if line.strip())
    snapshot: dict[str, Any] | None = None
    if snapshot_path.is_file():
        try:
            loaded = json.loads(snapshot_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                snapshot = loaded
        except (OSError, UnicodeError, json.JSONDecodeError):
            snapshot = None
    valid = (
        snapshot is not None
        and snapshot.get("schema_version") == "forgeflow.ecp-source-manifest.v2"
        and isinstance(snapshot.get("manifest_sha256"), str)
        and len(snapshot["manifest_sha256"]) == 64
        and all(character in "0123456789abcdef" for character in snapshot["manifest_sha256"])
        and snapshot.get("source_root") == str(root)
        and (source_sha is None or snapshot.get("head") == source_sha)
    )
    if completed.returncode != 0 or not valid:
        reason = "source snapshot command failed or emitted an invalid manifest"
        report.update({
            "status": "FAIL", "qualification": "NOT_RUN", "reason": reason,
            "suite_id": suite_id, "profile": args.profile,
            "checks": [{"name": "source_snapshot", "status": "FAIL", "reason": reason,
                        "details": {"runner": str(runner), "runner_sha256": sha256_bytes(runner.read_bytes()),
                                    "exit_code": completed.returncode, "snapshot_path": str(snapshot_path),
                                    "stdout": raw, "stderr": completed.stderr, "manifest_valid": valid}}],
            "denominator": {"total": 1, "passed": 0, "failed": 1, "blocked": 0, "not_run": 0, "inconclusive": 0},
        })
        return finish_report(report, args.output, EXIT_CODES["FAIL"])

    dirty = snapshot.get("worktree_state") != "CLEAN"
    if dirty:
        source_status = "INCONCLUSIVE"
        source_reason = "source snapshot is DIRTY_UNFROZEN; dirty source cannot qualify"
    else:
        source_status = "PASS"
        source_reason = "canonical source snapshot captured for a clean tree"
    materialization: dict[str, Any] | None = None
    materialization_status = "NOT_RUN"
    if args.candidate_root:
        candidate_root = Path(args.candidate_root).expanduser().resolve()
        try:
            from materialize_snapshot import materialize_snapshot

            materialization = materialize_snapshot(root, snapshot, candidate_root)
            materialization_status = "PASS"
            materialization_reason = "isolated source candidate materialized and inventory verified"
        except FileExistsError as exc:
            materialization_reason = f"candidate destination already exists: {exc}"
            materialization_status = "BLOCKED"
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            materialization_reason = f"isolated source materialization failed: {exc}"
            materialization_status = "FAIL"
    else:
        materialization_reason = "isolated materialization was not requested; pass --candidate-root"
    report.update({
        "status": ("PASS" if source_status == "PASS" and materialization_status == "PASS" else
                   "INCONCLUSIVE" if source_status == "INCONCLUSIVE" or materialization_status == "NOT_RUN" else
                   materialization_status),
        "qualification": "OBSERVED_NOT_GATE" if source_status == "PASS" and materialization_status == "PASS" else "NOT_RUN",
        "reason": f"{source_reason}; {materialization_reason}",
        "suite_id": suite_id, "profile": args.profile,
        "checks": [
            {"name": "source_snapshot", "status": source_status, "reason": source_reason,
             "details": {"snapshot_path": str(snapshot_path), "manifest_sha256": snapshot["manifest_sha256"],
                         "source_sha": snapshot.get("head"), "worktree_state": snapshot.get("worktree_state"),
                         "runner": str(runner), "runner_sha256": sha256_bytes(runner.read_bytes()),
                         "exit_code": completed.returncode, "stdout": raw, "stderr": completed.stderr}},
            {"name": "isolated_materialization", "status": materialization_status, "reason": materialization_reason,
             "details": {"materialization_attempted": bool(args.candidate_root),
                         "candidate_root": str(candidate_root) if args.candidate_root else None,
                         "receipt": materialization}},
        ],
        "denominator": {"total": 2, "passed": int(source_status == "PASS") + int(materialization_status == "PASS"),
                         "failed": int(materialization_status == "FAIL"),
                         "blocked": int(materialization_status == "BLOCKED"),
                         "not_run": int(materialization_status == "NOT_RUN"),
                         "inconclusive": int(source_status == "INCONCLUSIVE")},
        "source_snapshot": {"path": str(snapshot_path), "sha256": sha256_bytes(snapshot_path.read_bytes()),
                             "manifest_sha256": snapshot["manifest_sha256"], "worktree_state": snapshot.get("worktree_state")},
        "materialization": materialization,
        "evidence_refs": [str(snapshot_path), *([str(Path(args.candidate_root).expanduser().resolve())] if args.candidate_root else [])],
    })
    final_status = report["status"]
    return finish_report(report, args.output, EXIT_CODES[final_status])


def run_database_suite(
    args: argparse.Namespace, root: Path, source_sha: str | None, report: dict[str, Any],
) -> tuple[dict[str, Any], int]:
    """Observe identity; never promote it into a Store migration claim."""
    import ctypes
    import stat
    import urllib.parse

    runner = root / 'ops' / 'ecp' / 'test_database.sh'
    out_fd = ev_parent = ev_fd = None
    fd = runner_fd = runner_dir = runner_sealed = None
    out_path = ev_path = None
    out_id = ev_parent_id = ev_id = None
    alias = False
    streams = {'stdout.log': b'', 'stderr.log': b'', 'database-probe.json': b''}
    evidence_identities = {}
    capture_meta: dict[str, Any] = {'workload_invoked': False, 'redaction_detected': False,
                                     'redaction_scope': 'exact complete URL echo only; not general sanitization',
                                     'explicit_disposable_guard': os.environ.get('ECP_DATABASE_DISPOSABLE') == '1'}

    def close_once(name, item):
        """A failed close has unknown ownership; never retry a possibly reused fd."""
        if item is None or item < 0:
            return
        states = capture_meta.setdefault('fd_close_states', {})
        try:
            os.close(item)
        except OSError:
            states[name] = 'UNKNOWN'
        else:
            states[name] = 'CLOSED'

    def close_runtime_fds():
        nonlocal fd, runner_sealed, runner_fd, runner_dir
        pending = (('receipt_memfd', fd), ('runner_sealed', runner_sealed),
                   ('runner_file', runner_fd), ('runner_directory', runner_dir))
        # Clear the owned slots before closing: even an uncertain close must
        # never be repeated by the outer finally or a subsequent finish.
        fd = runner_sealed = runner_fd = runner_dir = None
        for name, item in pending:
            close_once(name, item)

    def close_evidence_fds():
        nonlocal out_fd, ev_fd, ev_parent
        pending = (('output_directory', out_fd), ('evidence_directory', ev_fd),
                   ('evidence_parent', ev_parent))
        out_fd = ev_fd = ev_parent = None
        for name, item in pending:
            close_once(name, item)

    def ident(fd):
        s = os.fstat(fd)
        return s.st_dev, s.st_ino

    def open_dir(path):
        path = Path(os.path.abspath(path))
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in path.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            return fd
        except BaseException:
            os.close(fd)
            raise

    def backing_path(path, table):
        import posixpath
        absolute = os.path.abspath(path)
        selected = None
        for line in table.splitlines():
            left, separator, right = line.partition(' - ')
            fields = left.split()
            if not separator or len(fields) < 6 or not right.split():
                raise ValueError('mount table malformed')
            decode = lambda value: re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1),8)), value)
            mount, fs_root = decode(fields[4]), decode(fields[3])
            if absolute == mount or absolute.startswith(mount.rstrip('/') + '/'):
                if selected is None or len(mount) > len(selected[1]):
                    selected = fields[2], mount, fs_root
        if selected is None:
            raise ValueError('mount identity unavailable')
        device, mount, fs_root = selected
        suffix = absolute[len(mount):].lstrip('/') if mount != '/' else absolute.lstrip('/')
        return device, posixpath.normpath(posixpath.join(fs_root,suffix))

    def reject_source_alias(parent):
        table = Path('/proc/self/mountinfo').read_text(encoding='utf-8')
        src_dev, src_path = backing_path(root, table)
        dst_dev, dst_path = backing_path(parent, table)
        if src_dev == dst_dev and (src_path == dst_path or dst_path.startswith(src_path.rstrip('/')+'/')):
            raise ValueError('output aliases source backing mount')

    def outside_source(fd):
        src = open_dir(root)
        try:
            source_id = ident(src)
        finally:
            os.close(src)
        probe = os.dup(fd)
        seen = set()
        try:
            for _ in range(256):
                current = ident(probe)
                if current == source_id:
                    raise ValueError('source ancestor')
                if current in seen:
                    return
                seen.add(current)
                parent = os.open('..', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=probe)
                os.close(probe)
                probe = parent
            raise ValueError('ancestry limit')
        finally:
            os.close(probe)

    def matches(path, expected):
        fd = open_dir(path)
        try:
            return ident(fd) == expected
        finally:
            os.close(fd)

    def check_evidence_binding():
        reject_source_alias(ev_path.parent)
        return matches(ev_path.parent, ev_parent_id) and matches(ev_path, ev_id)

    def create_file(fd, name, data):
        f = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            view = memoryview(data)
            while view:
                n = os.write(f, view)
                if n <= 0:
                    raise OSError('short write')
                view = view[n:]
            os.fsync(f)
            info = os.fstat(f)
            current = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError('file binding changed')
            evidence_identities[name] = (info.st_dev,info.st_ino,info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns,sha256_bytes(data))
        finally:
            os.close(f)
        os.fsync(fd)

    def verify_artifacts():
        for name,expected in evidence_identities.items():
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=ev_fd)
            try:
                info=os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size > P003_MAX_LOG_BYTES + 1024*1024:
                    raise ValueError('evidence input invalid')
                data=os.pread(fd,info.st_size+1,0)
                after=os.fstat(fd)
                signature=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
                observed=(*signature(info),sha256_bytes(data))
                if observed != expected or signature(info)!=signature(after) or len(data)!=info.st_size:
                    raise ValueError('evidence file changed')
            finally:
                os.close(fd)

    def finish(status, reason, identity, attempted, migration='NOT_RUN', safety=None):
        nonlocal out_fd, ev_parent, ev_fd
        # The final JSON and return value must include runtime cleanup outcome;
        # a finally block after print would make those observations disagree.
        close_runtime_fds()
        checks = [
            {'name':'database_identity','status':identity,'reason':reason,'details':capture_meta},
            {'name':'store_migrations','status':migration,'reason':'requires a controlled Store migration execution','details':{}},
            {'name':'historical_migration_fixture','status':'NOT_RUN','reason':'historical fixture migration and independent readback not run','details':{}},
        ]
        if safety:
            checks.append({'name':'evidence_safety','status':safety,'reason':reason,'details':{}})
        def update():
            report.update(status=status, reason=reason, qualification='NOT_RUN', suite_id='ECP-P0-02',
                          profile=args.profile, database_connections_attempted=attempted, checks=checks,
                          denominator={'total':len(checks), **{k:sum(c['status']==v for c in checks)
                          for k,v in [('passed','PASS'),('failed','FAIL'),('blocked','BLOCKED'),('not_run','NOT_RUN'),('inconclusive','INCONCLUSIVE')]}})
        report['persisted_result_authority'] = 'PROVISIONAL_ONLY'
        report['evidence_integrity_at_return'] = 'NOT_VERIFIED'
        update()
        if ev_fd is not None:
            try:
                if not check_evidence_binding():
                    raise ValueError('evidence directory binding changed')
                hashes = {}
                for name, data in streams.items():
                    create_file(ev_fd, name, data)
                    hashes[name] = sha256_bytes(data)
                manifest = {'schema':'forgeflow.ecp-p002-evidence.v1', 'source_sha':source_sha,
                            'runner_sha256':capture_meta.get('runner_sha256'), 'stored_sha256':hashes,
                            'capture':capture_meta, 'qualification':'NOT_RUN'}
                create_file(ev_fd, 'manifest.json', (json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2)+'\n').encode())
                verify_artifacts()
                report['evidence_refs'] = sorted(set([*report.get('evidence_refs',[]), *[str(ev_path / n) for n in (*streams, 'manifest.json', 'result.json')]]))
                if out_fd is not None:
                    report['evidence_refs'] = sorted(set([*report['evidence_refs'],str(out_path)]))
                update()
                provisional = {'schema_version':report.get('schema_version'), 'suite_id':'ECP-P0-02',
                               'status':'NOT_RUN', 'qualification':'NOT_RUN', 'product_gate_effect':'NONE',
                               'result_authority':'PROVISIONAL_ONLY',
                               'reason':'This file is not the completed run result; inspect the invocation return and independently verify retained evidence.',
                               'source_sha':source_sha, 'evidence_refs':report['evidence_refs']}
                encoded = (json.dumps(provisional, ensure_ascii=False, sort_keys=True, indent=2)+'\n').encode()
                create_file(ev_fd, 'result.json', encoded)
                verify_artifacts()
                if not check_evidence_binding():
                    raise ValueError('evidence directory binding changed after write')
                report['evidence_integrity_at_return'] = 'VERIFIED_NONATOMIC'
                if out_fd is not None:
                    if not matches(out_path.parent,out_id):
                        raise ValueError('output parent changed')
                    create_file(out_fd,out_path.name,encoded)
                    if not matches(out_path.parent,out_id):
                        raise ValueError('output parent changed after write')
            except (OSError, ValueError, UnicodeError) as exc:
                status = 'FAIL'
                reason = 'P0-02 evidence could not be safely created or verified; created artifacts retained'
                checks.append({'name':'evidence_safety','status':'FAIL','reason':reason,'details':{'error_type':type(exc).__name__}})
                capture_meta['evidence_directory_retained'] = True
                report['evidence_integrity_at_return'] = 'FAILED'
                update()
        close_evidence_fds()
        unknown = sorted(name for name, state in capture_meta.get('fd_close_states', {}).items()
                         if state == 'UNKNOWN')
        if unknown:
            capture_meta['fd_cleanup_unknown'] = True
            if report['evidence_integrity_at_return'] != 'FAILED':
                report['evidence_integrity_at_return'] = 'UNKNOWN'
            checks.append({'name':'descriptor_cleanup','status':'INCONCLUSIVE',
                           'reason':'One or more descriptor close outcomes are unknown',
                           'details':{'unknown':unknown}})
            # Preserve a stronger existing status and its original reason;
            # the independent cleanup check carries the uncertainty.
            if STATUS_RANK[status] < STATUS_RANK['INCONCLUSIVE']:
                status = 'INCONCLUSIVE'
                reason = 'Descriptor cleanup could not be confirmed'
            update()
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return report, EXIT_CODES[status]

    try:
        source = Path(os.path.abspath(root))
        if getattr(args, 'evidence_root', None):
            ev_path = Path(os.path.abspath(Path(args.evidence_root).expanduser()))
            if ev_path == source or source in ev_path.parents:
                raise ValueError('evidence inside source')
        else:
            # The parent is fixed and the directory itself is still created through pinned FDs.
            ev_path = Path(tempfile.gettempdir()) / ('forgeflow-ecp-p0-02-' + os.urandom(16).hex())
        if args.output:
            out_path = Path(os.path.abspath(Path(args.output).expanduser()))
            alias = out_path == ev_path / 'result.json'
            if not alias:
                raise ValueError('output must be evidence-root/result.json')
        ev_parent = open_dir(ev_path.parent)
        ev_parent_id = ident(ev_parent)
        outside_source(ev_parent)
        reject_source_alias(ev_path.parent)
        os.mkdir(ev_path.name, 0o700, dir_fd=ev_parent)
        os.fsync(ev_parent)
        created = os.stat(ev_path.name, dir_fd=ev_parent, follow_symlinks=False)
        ev_fd = os.open(ev_path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=ev_parent)
        info = os.fstat(ev_fd)
        if (not stat.S_ISDIR(created.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
                or (created.st_dev, created.st_ino) != (info.st_dev, info.st_ino)):
            raise ValueError('new evidence directory identity or mode changed')
        ev_id = ident(ev_fd)
        capture_meta.update(evidence_directory=str(ev_path), evidence_directory_retained=True)
        if not check_evidence_binding():
            raise ValueError('evidence binding changed')
        for name in (*streams, 'manifest.json', 'result.json'):
            try:
                os.stat(name, dir_fd=ev_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise FileExistsError('evidence collision')
    except (OSError,ValueError) as exc:
        # Do not write through any path after failed preflight; preserve any created directory.
        close_evidence_fds()
        capture_meta.update(preflight_error_type=type(exc).__name__)
        return finish('BLOCKED','P0-02 evidence path is unsafe or unavailable; no workload started','NOT_RUN',0,safety='BLOCKED')

    if args.run_store_test:
        return finish('BLOCKED','Store execution requires a coordinated bounded executor; no database connection or build attempted','NOT_RUN',0,migration='BLOCKED')
    if not runner.is_file() or not os.access(runner,os.X_OK):
        return finish('FAIL','P0-02 database runner is missing or not executable','FAIL',0)

    url = os.environ.get('ECP_DATABASE_URL','')
    if url:
        try:
            parsed_url = urllib.parse.urlsplit(url)
            query = urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True, strict_parsing=True)
            if (parsed_url.scheme not in ('postgres','postgresql') or parsed_url.hostname not in ('localhost','127.0.0.1','::1')
                or parsed_url.password is not None or parsed_url.fragment or not parsed_url.username
                or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',parsed_url.username)
                or not re.fullmatch(r'/ecp_disposable_[a-z0-9_]+',parsed_url.path)
                or len(query)!=1 or query[0][0]!='host' or not query[0][1].startswith('/')
                or parsed_url.port is None):
                raise ValueError('unsafe URL')
        except (ValueError,UnicodeError):
            return finish('BLOCKED','Database URL is unsupported or contains credentials; no workload started','NOT_RUN',0,safety='BLOCKED')
    try:
        needle = url.encode('utf-8','strict') if url else b''
    except UnicodeError:
        return finish('BLOCKED','Database URL cannot be safely captured; no workload started','NOT_RUN',0,safety='BLOCKED')
    env = {name:os.environ[name] for name in ('PATH','LANG','LC_ALL','LC_CTYPE','TZ','TMPDIR',
           'ECP_DATABASE_URL','ECP_DATABASE_DISPOSABLE','ECP_DATABASE_EXPECTED_DATA_DIR') if name in os.environ}
    # Pin PATH to standard system locations; never propagate loader, Python, shell or PG hooks.
    env['PATH'] = '/usr/local/bin:/usr/bin:/bin'
    proc = None
    leader_reaped = False
    selector = None
    selector_creation_started = False
    selector_close_attempted = False
    buffers = {'stdout.log':bytearray(), 'stderr.log':bytearray()}
    receipt = None

    def retain_captured(receipt_data, *, complete):
        """Retain observed bytes even when later receipt processing fails.

        A digest refers to the captured prefix, not necessarily the complete
        process stream. Redaction covers the exact complete URL only.
        """
        raw = {'stdout.log':bytes(buffers['stdout.log']), 'stderr.log':bytes(buffers['stderr.log'])}
        if receipt_data is not None:
            raw['database-probe.json'] = receipt_data
        redacted = False
        for name, data in raw.items():
            capture_meta[name+'_original_sha256'] = sha256_bytes(data)
            capture_meta[name+'_original_bytes'] = len(data)
            if needle and needle in data:
                redacted = True
                data = data.replace(needle,b'[REDACTED COMPLETE DATABASE URL]')
            streams[name] = data
        capture_meta.update(redaction_detected=redacted,
                            raw_logs_complete_for_acceptance=complete and not redacted,
                            **{'stdout.log_capture_state':'COMPLETE' if complete else 'PARTIAL',
                               'stderr.log_capture_state':'COMPLETE' if complete else 'PARTIAL'})
        return raw, redacted

    try:
        import fcntl
        runner_dir = open_dir(runner.parent)
        runner_fd = os.open(runner.name,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,dir_fd=runner_dir)
        before_runner = os.fstat(runner_fd)
        if not stat.S_ISREG(before_runner.st_mode) or not (before_runner.st_mode & 0o111) or before_runner.st_size > 2*1024*1024:
            raise ValueError('runner is not a bounded executable regular file')
        runner_bytes = os.pread(runner_fd,before_runner.st_size+1,0)
        runner_sig = lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        if len(runner_bytes)!=before_runner.st_size or runner_sig(os.fstat(runner_fd))!=runner_sig(before_runner):
            raise ValueError('runner changed during read')
        capture_meta['runner_sha256'] = sha256_bytes(runner_bytes)
        if not runner_bytes.startswith(b'#!'):
            raise ValueError('runner needs a shebang')
        if hasattr(os,'memfd_create'):
            runner_sealed=os.memfd_create('forgeflow-p002-runner',3)
        else:
            libc=ctypes.CDLL(None,use_errno=True);create=libc.memfd_create
            create.argtypes=(ctypes.c_char_p,ctypes.c_uint);create.restype=ctypes.c_int
            runner_sealed=create(b'forgeflow-p002-runner',3)
            if runner_sealed < 0: raise OSError(ctypes.get_errno(),'memfd unavailable')
        os.fchmod(runner_sealed,0o700)
        remaining=memoryview(runner_bytes)
        while remaining:
            n=os.write(runner_sealed,remaining)
            if n<=0:raise OSError('runner memfd short write')
            remaining=remaining[n:]
        seals=1|2|4|8
        fcntl.fcntl(runner_sealed,getattr(fcntl,'F_ADD_SEALS',1033),seals)
        if fcntl.fcntl(runner_sealed,getattr(fcntl,'F_GET_SEALS',1034)) & seals != seals:
            raise ValueError('runner sealing unavailable')
        if hasattr(os,'memfd_create'):
            fd = os.memfd_create('forgeflow-p002-' + os.urandom(8).hex(), 1)
        else:
            libc = ctypes.CDLL(None, use_errno=True)
            func = libc.memfd_create
            func.argtypes = (ctypes.c_char_p, ctypes.c_uint)
            func.restype = ctypes.c_int
            fd = func(('forgeflow-p002-' + os.urandom(8).hex()).encode(), 1)
            if fd < 0:
                raise OSError(ctypes.get_errno(), 'memfd unavailable')
        os.fchmod(fd,0o600)
        proc = subprocess.Popen([f'/proc/self/fd/{runner_sealed}','--output-fd',str(fd)], cwd=root, env=env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, pass_fds=(fd,runner_sealed))
        capture_meta.update(workload_invoked=True)
        selector_creation_started = True
        selector = selectors.DefaultSelector()
        for name, pipe in [('stdout.log',proc.stdout),('stderr.log',proc.stderr)]:
            os.set_blocking(pipe.fileno(),False)
            selector.register(pipe,selectors.EVENT_READ,name)
        deadline = time.monotonic() + bounded_child_timeout('ECP_P002_TIMEOUT_SECONDS',default=120)
        termination = None
        while selector.get_map():
            if time.monotonic() >= deadline:
                termination = 'timeout'
                break
            for key,_ in selector.select(timeout=min(0.2,max(0,deadline-time.monotonic()))):
                try:
                    data = os.read(key.fileobj.fileno(),65536)
                except BlockingIOError:
                    continue
                if not data:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                elif len(buffers[key.data]) + len(data) > P003_MAX_LOG_BYTES:
                    buffers[key.data].extend(data[:max(0,P003_MAX_LOG_BYTES-len(buffers[key.data]))])
                    termination = 'stream_limit'
                    break
                else:
                    buffers[key.data].extend(data)
            if termination:
                break
        if termination:
            # Never poll or wait before signalling: the unreaped leader keeps
            # its PID reserved even if it exited while descendants held pipes.
            try:
                os.killpg(proc.pid,signal.SIGKILL)
                capture_meta['group_signal'] = 'SIGKILL_SENT'
            except ProcessLookupError:
                capture_meta['group_signal'] = 'GROUP_NOT_FOUND'
            except OSError:
                capture_meta['group_signal'] = 'SIGNAL_FAILED'
        for key in list(selector.get_map().values()):
            selector.unregister(key.fileobj)
            key.fileobj.close()
        selector_close_attempted = True
        selector.close()
        selector = None
        capture_meta['selector_close_state'] = 'CLOSED'
        try:
            code = proc.wait(timeout=5)
            reaped = True
            leader_reaped = True
        except subprocess.TimeoutExpired:
            code = None
            reaped = False
            termination = termination or 'leader_not_reaped'
        # Preserve lifecycle facts even if receipt or evidence inspection fails.
        capture_meta.update(leader_reaped=reaped, termination_reason=termination)
        before = os.fstat(fd)
        receipt = os.pread(fd,65538,0)
        after = os.fstat(fd)
        signature = lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mode,x.st_mtime_ns,x.st_ctime_ns)
        receipt_ok = (stat.S_ISREG(before.st_mode) and before.st_nlink==0 and before.st_size<=65537
                      and len(receipt)==before.st_size and signature(before)==signature(after))
        raw, redacted = retain_captured(receipt, complete=termination is None and reaped)
        capture_meta['receipt_capture_state'] = 'OBSERVED' if receipt_ok else 'UNKNOWN'
        capture_meta.update(exit_code=code, capture_complete=termination is None and reaped, termination_reason=termination,
                            leader_reaped=reaped, descendants_terminated=None, workload_confinement_verified=False,
                            redaction_detected=redacted,
                            raw_logs_complete_for_acceptance=not redacted and termination is None and reaped and receipt_ok)
        if not reaped or capture_meta.get('group_signal') == 'SIGNAL_FAILED':
            return finish('INCONCLUSIVE','Database runner termination could not be confirmed','INCONCLUSIVE',None)
        if redacted or termination or not reaped or not receipt_ok:
            return finish('FAIL','Database evidence is incomplete, unsafe or contains an exact URL echo','FAIL',None)
        current_runner=os.stat(runner.name,dir_fd=runner_dir,follow_symlinks=False)
        if (runner_sig(os.fstat(runner_fd)) != runner_sig(before_runner)
                or runner_sig(current_runner) != runner_sig(before_runner)
                or not matches(runner.parent,ident(runner_dir))):
            raise ValueError('runner or its source path changed')
        text = raw['stdout.log'].decode('utf-8','strict')
        if raw['database-probe.json'] != raw['stdout.log'] or len(text.splitlines()) != 1 or len(raw['stdout.log']) > 65537:
            raise ValueError('receipt mismatch')
        def pairs(rows):
            result = {}
            for key,value in rows:
                if key in result:
                    raise ValueError('duplicate field')
                result[key]=value
            return result
        def no_constant(value):
            raise ValueError('nonfinite JSON')
        result=json.loads(text, object_pairs_hook=pairs, parse_constant=no_constant)
        if not isinstance(result,dict):
            raise ValueError('invalid result')
        child_status=result.get('status')
        if child_status not in ('PASS','FAIL','BLOCKED','INCONCLUSIVE') or code != {'PASS':0,'FAIL':10,'BLOCKED':20,'INCONCLUSIVE':20}[child_status]:
            raise ValueError('status and exit disagree')
        if 'connections_attempted' not in result:
            raise ValueError('connection claim missing')
        attempted=result['connections_attempted']
        if attempted is not None and (type(attempted) is not int or attempted not in (0,1)):
            raise ValueError('invalid connection count')
        if child_status=='PASS':
            expected_dir=os.environ.get('ECP_DATABASE_EXPECTED_DATA_DIR','')
            if (attempted != 1 or result.get('store_migration_test') != 'NOT_RUN'
                    or os.environ.get('ECP_DATABASE_DISPOSABLE') != '1' or not url
                    or not expected_dir or not os.path.isabs(expected_dir)
                    or result.get('database') != parsed_url.path[1:] or result.get('user') != parsed_url.username
                    or not isinstance(result.get('server_version_num'),str)
                    or not re.fullmatch(r'[0-9]{5,6}',result['server_version_num'])):
                raise ValueError('invalid migration or identity claim')
        if child_status == 'BLOCKED' and attempted not in (0, None):
            raise ValueError('blocked connection claim contradicts the child protocol')
        # The runner is not independently confined or authenticated. Even a
        # BLOCKED/FAIL receipt may follow an unobserved database connection;
        # neither its count nor a client's identity claim is an observed fact.
        capture_meta['child_reported_connections_attempted'] = attempted
        capture_meta['child_connection_claim_authority'] = 'UNVERIFIED'
        if child_status=='PASS':
            return finish('INCONCLUSIVE','Runner reported PostgreSQL identity but client and server are not independently authenticated','INCONCLUSIVE',None)
        if child_status=='INCONCLUSIVE':
            return finish('INCONCLUSIVE','Runner did not establish authenticated PostgreSQL identity','INCONCLUSIVE',None)
        if child_status=='BLOCKED':
            return finish('BLOCKED','Runner reported the database identity guard blocked; connection count is unverified','BLOCKED',None)
        return finish('FAIL','Runner reported the database identity guard failed; connection count is unverified','FAIL',None)
    except (OSError,ValueError,UnicodeError,TypeError,KeyError,AttributeError,RecursionError) as exc:
        termination_unknown = capture_meta.get('group_signal') == 'SIGNAL_FAILED'
        selector_close_unknown = False
        if selector is not None:
            if selector_close_attempted:
                # A close that raised may already have consumed the descriptor;
                # retrying an uncertain close could affect a reused descriptor.
                selector_close_unknown = True
            else:
                selector_close_attempted = True
                try:
                    selector.close()
                except (OSError, ValueError):
                    selector_close_unknown = True
                else:
                    capture_meta['selector_close_state'] = 'CLOSED'
            selector = None
        elif selector_creation_started and not selector_close_attempted:
            # The constructor may have failed after allocating resources.
            selector_close_unknown = True
        if selector_close_unknown:
            capture_meta['selector_close_state'] = 'UNKNOWN'
        if proc is not None and not leader_reaped:
            if proc.returncode is not None:
                # wait() can reap the leader before raising. Never signal a
                # now-reusable PID; its process group remains unverified.
                leader_reaped = True
                termination_unknown = True
                capture_meta['group_signal'] = 'NOT_SENT_LEADER_REAPED'
            else:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                    capture_meta['group_signal'] = 'SIGKILL_SENT'
                except ProcessLookupError:
                    capture_meta['group_signal'] = 'GROUP_NOT_FOUND'
                except OSError:
                    capture_meta['group_signal'] = 'SIGNAL_FAILED'
                    termination_unknown = True
                try:
                    proc.wait(timeout=5)
                    leader_reaped = True
                except (OSError, subprocess.TimeoutExpired):
                    leader_reaped = proc.returncode is not None
                    termination_unknown = True
            capture_meta['leader_reaped'] = leader_reaped
        if proc is not None:
            capture_meta['leader_reaped'] = leader_reaped
            for pipe in (proc.stdout, proc.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:
                        capture_meta['stream_close_failed'] = True
                        termination_unknown = True
            capture_meta['descendants_terminated'] = None
            capture_meta['workload_confinement_verified'] = False
            retain_captured(receipt, complete=False)
            capture_meta.update(capture_complete=False, receipt_capture_state='UNKNOWN')
        capture_meta['validation_error_type']=type(exc).__name__
        if proc is None:
            return finish('BLOCKED','Database runner could not be safely fixed and started','NOT_RUN',0,safety='BLOCKED')
        if termination_unknown:
            return finish('INCONCLUSIVE','Database runner termination could not be confirmed','INCONCLUSIVE',None)
        if selector_close_unknown:
            return finish('INCONCLUSIVE','Database capture selector cleanup could not be confirmed','INCONCLUSIVE',None)
        return finish('FAIL','Database runner evidence is incomplete or contradictory','FAIL',None)
    finally:
        # Normally finish has already cleared these slots. This covers an
        # unexpected exception without retrying a descriptor whose close failed.
        close_runtime_fds()

class ReportOutputUnavailable(Exception):
    """Output publication failed; report and any partial output must be retained."""
    def __init__(self, reason: str, output_state: str):
        super().__init__(reason)
        self.output_state = output_state


def _open_report_parent(destination: str) -> tuple[int, str, str]:
    """Open existing parent components without following symlinks.

    This does not authenticate the directory, prevent renames, or prove the
    destination is outside an alias of source/evidence under concurrent actors.
    """
    required = ('O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC')
    if not all(hasattr(os, name) for name in required):
        raise ReportOutputUnavailable('OUTPUT_FLAGS_UNAVAILABLE', 'NOT_CREATED_BY_THIS_CALL')
    try:
        raw = os.path.expanduser(destination)
        if not raw or raw.endswith('/') or '\0' in raw or '..' in raw.split('/') or raw.split('/')[-1] == '.':
            raise ValueError('invalid output path')
        absolute = os.path.abspath(raw)
        parts = absolute.split('/')
        leaf = parts[-1]
        if not leaf or leaf in ('.', '..'):
            raise ValueError('invalid output name')
    except (OSError, ValueError, TypeError) as exc:
        raise ReportOutputUnavailable('OUTPUT_PATH_INVALID', 'NOT_CREATED_BY_THIS_CALL') from exc
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = None
    try:
        parent = os.open('/', flags)
        for part in (p for p in parts[1:-1] if p and p != '.'):
            child = os.open(part, flags, dir_fd=parent)
            previous, parent = parent, None
            try:
                os.close(previous)
            except OSError:
                try:
                    os.close(child)
                except OSError:
                    pass
                raise
            parent = child
        return parent, leaf, absolute
    except OSError as exc:
        if parent is not None:
            try:
                os.close(parent)
            except OSError:
                pass
        raise ReportOutputUnavailable('OUTPUT_PARENT_UNAVAILABLE', 'NOT_CREATED_BY_THIS_CALL') from exc


def write_report(report: dict[str, Any], output: str | None) -> dict[str, Any]:
    """Print a report; when requested, create a new file without replacement.

    A new output may remain after a failed write, fsync or close. Neither
    exclusive creation nor nofollow parent traversal authenticates the writer,
    output directory, runtime, later file identity or durable directory entry.
    """
    if not output:
        print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))
        return report
    parent, leaf, destination = _open_report_parent(output)
    persisted_report = dict(report)
    try:
        persisted_report['evidence_refs'] = sorted(dict.fromkeys([*report.get('evidence_refs', []), destination]))
        data = (json.dumps(persisted_report, ensure_ascii=True, indent=2, sort_keys=True) + '\n').encode('utf-8')
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        try:
            os.close(parent)
        except OSError:
            pass
        raise ReportOutputUnavailable('OUTPUT_ENCODING_INVALID', 'NOT_CREATED_BY_THIS_CALL') from exc
    fd = None
    try:
        fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
    except OSError as exc:
        try:
            os.close(parent)
        except OSError:
            pass
        if isinstance(exc, FileExistsError):
            raise ReportOutputUnavailable('OUTPUT_ALREADY_EXISTS', 'NOT_CREATED_BY_THIS_CALL') from exc
        raise ReportOutputUnavailable('OUTPUT_CREATE_UNKNOWN', 'CREATE_OUTCOME_UNKNOWN') from exc
    error = None
    try:
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0 or written > len(data) - offset:
                raise OSError('invalid output write count')
            offset += written
        os.fsync(fd)
    except OSError as exc:
        error = exc
    finally:
        try:
            os.close(fd)
        except OSError as exc:
            if error is None:
                error = exc
        try:
            os.close(parent)
        except OSError as exc:
            if error is None:
                error = exc
    if error is not None:
        raise ReportOutputUnavailable('OUTPUT_WRITE_OR_CLOSE_UNKNOWN', 'UNKNOWN_PARTIAL') from error
    report['evidence_refs'] = persisted_report['evidence_refs']
    print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))
    return report


def finish_report(report: dict[str, Any], output: str | None, result_code: int) -> tuple[dict[str, Any], int]:
    """Never emit a success report when requested output could not be confirmed."""
    try:
        return write_report(report, output), result_code
    except ReportOutputUnavailable as exc:
        status = 'FAIL' if report.get('status') == 'FAIL' else 'BLOCKED'
        diagnostic = {'status': status, 'product_gate_effect': 'NONE', 'reason': str(exc),
                      'output_status': exc.output_state, 'evidence_report': report}
        try:
            rendered = json.dumps(diagnostic, ensure_ascii=True, sort_keys=True)
        except (TypeError, ValueError, UnicodeError, RecursionError):
            # The caller still holds the original report in memory. It cannot
            # be preserved as JSON here; record that loss rather than emit a
            # fabricated or partial representation as if it were complete.
            original_status = report.get('status')
            diagnostic = {'status': status, 'product_gate_effect': 'NONE',
                          'reason': str(exc), 'output_status': exc.output_state,
                          'evidence_report': None, 'evidence_report_state': 'UNSERIALIZABLE',
                          'original_status': original_status if type(original_status) is str else None}
            rendered = json.dumps(diagnostic, ensure_ascii=True, sort_keys=True)
        print(rendered, file=sys.stderr)
        return diagnostic, 10 if status == 'FAIL' else 20


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Offline ForgeFlow ECP Phase 0 verifier")
    sub = root.add_subparsers(dest="command", required=True)
    for name in ("doctor", "report"):
        command = sub.add_parser(name, help=f"run {name}")
        command.add_argument("--source-root", help="control source root; defaults to this repository")
        command.add_argument("--output", help="write the same JSON report to this path")
    doctor_parser = sub.choices["doctor"]
    doctor_parser.add_argument("--evidence-ref", action="append", default=[], help="immutable evidence reference to include")
    report_parser = sub.choices["report"]
    report_parser.add_argument("--input", action="append", required=True, help="JSON evidence report to aggregate")
    report_parser.add_argument("--source-sha", help="expected source SHA; defaults to current HEAD")
    suite_parser = sub.add_parser("suite", help="record a suite run or explicit NOT_RUN result")
    suite_group = suite_parser.add_mutually_exclusive_group(required=True)
    suite_group.add_argument("--suite", help="task/suite identifier")
    suite_group.add_argument("--phase", type=int, help="phase identifier")
    suite_group.add_argument("--release-candidate", action="store_true", help="release qualification suite")
    suite_parser.add_argument("--profile", default="isolated", help="declared execution profile")
    suite_parser.add_argument("--evidence-root", help="declared evidence directory")
    suite_parser.add_argument(
        "--candidate-root",
        help="explicit disposable destination for P0-01 source materialization",
    )
    suite_parser.add_argument(
        "--run-store-test",
        action="store_true",
        help="after the guarded identity probe, run the disposable Store migration test",
    )
    suite_parser.add_argument('--source-manifest-version', choices=('2','3'), default='2',
                              help='select P0-01 historical v2 or draft v3 observation')
    suite_parser.add_argument("--source-root", help="control source root; defaults to this repository")
    suite_parser.add_argument("--output", help="write the report; v3 requires evidence-root/result.json")
    suite_parser.add_argument('--p005-manifest', help='pinned P0-01 source manifest for P0-05')
    suite_parser.add_argument('--p005-receipt', help='P0-01 materialization receipt for P0-05')
    suite_parser.add_argument('--p005-manifest-sha256', help='independently pinned P0-01 manifest digest')
    return root


def main(argv: list[str] | None = None) -> int:
    normalized = list(sys.argv[1:] if argv is None else argv)
    if normalized and normalized[0].startswith("--"):
        normalized.insert(0, "suite")
    args = parser().parse_args(normalized)
    if args.command == "doctor":
        _, code = doctor(args)
        return code
    if args.command == "report":
        _, code = aggregate_reports(args)
        return code
    if args.command == "suite":
        _, code = suite(args)
        return code
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
