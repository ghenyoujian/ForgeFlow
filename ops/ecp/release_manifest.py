#!/usr/bin/env python3
"""Create a fail-closed, reproducible release-candidate identity manifest.

This tool only identifies candidate inputs. It never approves or publishes a
release; the independent release replay and authorized approval remain separate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import importlib.util
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "forgeflow.ecp-release-manifest.v1"


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_inventory(root: Path) -> list[dict[str, Any]]:
    """Hash sorted paths, bytes, permission bits, and symlink targets."""
    root = root.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"inventory root is not a directory: {root}")
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink():
            target = os.readlink(path)
            resolved_target = (path.parent / target).resolve(strict=False)
            if Path(target).is_absolute() or not resolved_target.is_relative_to(root):
                raise ValueError(f"symlink target escapes inventory root: {relative}")
            entries.append({"path": relative, "kind": "symlink", "mode": f"{mode:04o}", "target": target})
        elif path.is_file():
            entries.append({"path": relative, "kind": "file", "mode": f"{mode:04o}", "sha256": sha_file(path)})
    return entries


def inventory_digest(entries: list[dict[str, Any]]) -> str:
    return sha_bytes(canonical_json(entries))


def created_at() -> str:
    """Use SOURCE_DATE_EPOCH when supplied so preview manifests can reproduce."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch is not None:
        return datetime.fromtimestamp(int(epoch), timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def git_identity(root: Path) -> tuple[str, list[str]]:
    # Use the same bounded, environment-cleared Git launcher as the independent
    # oracle; a caller-controlled GIT_DIR or hung Git must not produce a PASS.
    oracle = _load_independent_source_oracle()
    head = oracle.run_git(root, ["rev-parse", "HEAD"]).decode("ascii").strip()
    status = oracle.run_git(root, ["status", "--porcelain=v1", "--untracked-files=all"]).decode("utf-8", "strict").splitlines()
    return head, status


SOURCE_V1 = "forgeflow.ecp-source-manifest.v1"
SOURCE_V2 = "forgeflow.ecp-source-manifest.v2"
_SOURCE_FIELDS = frozenset({
    "schema_version", "source_root", "head", "worktree_state", "exclude_patterns",
    "untracked_scan_mode", "untracked_scan_roots", "tracked_changes",
    "untracked_business_files", "excluded_generated_files", "patch_sha256",
    "manifest_sha256", "created_at", "release_qualifiable", "inventory_complete",
    "inventory_error", "index_visibility_exceptions",
})


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _source_v2_error(manifest: dict[str, Any]) -> str | None:
    """Validate the release-relevant v2 shape without optional dependencies.

    JSON Schema is the portable contract; this independent standard-library
    implementation is deliberately fail-closed and is checked against it.
    """
    def text(value: Any) -> bool:
        return isinstance(value, str) and bool(value)
    def sha(value: Any) -> bool:
        return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None
    def strings(value: Any) -> bool:
        return isinstance(value, list) and all(isinstance(v, str) for v in value)
    def entry(value: Any) -> bool:
        if not isinstance(value, dict):
            return False
        kind = value.get("kind")
        keys = {"path", "status", "kind", "mode", "sha256"} | ({"target"} if kind == "symlink" else set())
        if set(value) != keys or not text(value.get("path")) or not isinstance(value.get("status"), str) or len(value["status"]) != 2:
            return False
        if kind == "deleted":
            return value["mode"] is None and value["sha256"] is None
        if kind == "directory_summary":
            return (isinstance(value["mode"], str)
                    and re.fullmatch(r"[0-7]{4}", value["mode"]) is not None
                    and value["sha256"] is None)
        if kind not in ("file", "symlink") or not isinstance(value["mode"], str) or re.fullmatch(r"[0-7]{4}", value["mode"]) is None or not sha(value["sha256"]):
            return False
        return kind != "symlink" or text(value["target"])
    def excluded(value: Any) -> bool:
        return (isinstance(value, dict) and set(value) == {"path", "status", "reason"}
                and text(value["path"]) and isinstance(value["status"], str)
                and len(value["status"]) == 2 and text(value["reason"]))
    def visibility(value: Any) -> bool:
        if not isinstance(value, dict) or not text(value.get("path")):
            return False
        if set(value) == {"path", "gitlink"}:
            return value["gitlink"] is True
        if set(value) == {"path", "assume_unchanged", "skip_worktree"}:
            a, b = value["assume_unchanged"], value["skip_worktree"]
            return type(a) is bool and type(b) is bool and (a or b)
        return False
    if set(manifest) != _SOURCE_FIELDS or manifest.get("schema_version") != SOURCE_V2:
        return "unexpected or missing v2 fields"
    if not text(manifest["source_root"]) or not isinstance(manifest["head"], str) or re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", manifest["head"]) is None:
        return "invalid source root or head"
    if manifest["worktree_state"] not in ("CLEAN", "DIRTY_UNFROZEN") or manifest["untracked_scan_mode"] not in ("all", "bounded"):
        return "invalid source state or scan mode"
    if not strings(manifest["exclude_patterns"]) or not strings(manifest["untracked_scan_roots"]):
        return "invalid source scan lists"
    for field in ("tracked_changes", "untracked_business_files"):
        if not isinstance(manifest[field], list) or not all(entry(v) for v in manifest[field]):
            return "invalid source entries"
    if not isinstance(manifest["excluded_generated_files"], list) or not all(excluded(v) for v in manifest["excluded_generated_files"]):
        return "invalid excluded entries"
    if not sha(manifest["patch_sha256"]) or not sha(manifest["manifest_sha256"]):
        return "invalid source digest"
    try:
        stamp = manifest["created_at"]
        if not isinstance(stamp, str) or datetime.fromisoformat(stamp.replace("Z", "+00:00")).utcoffset() is None:
            return "invalid creation timestamp"
    except (TypeError, ValueError, OverflowError):
        return "invalid creation timestamp"
    complete, error, exceptions = manifest["inventory_complete"], manifest["inventory_error"], manifest["index_visibility_exceptions"]
    if type(complete) is not bool or type(manifest["release_qualifiable"]) is not bool or not isinstance(exceptions, list) or not all(visibility(v) for v in exceptions):
        return "invalid inventory metadata"
    if complete:
        if error is not None or exceptions:
            return "complete inventory contains an error or visibility exception"
    elif not text(error) or manifest["worktree_state"] != "DIRTY_UNFROZEN" or manifest["release_qualifiable"]:
        return "incomplete inventory cannot qualify"
    if manifest["worktree_state"] == "CLEAN":
        if not complete or not manifest["release_qualifiable"] or any(manifest[k] for k in ("tracked_changes", "untracked_business_files", "excluded_generated_files")):
            return "clean source metadata is contradictory"
    elif manifest["release_qualifiable"]:
        return "dirty source cannot qualify"
    return None


def _current_source_snapshot(source_root: Path, scan_all: bool) -> dict[str, Any]:
    # Use the producer installed beside this consumer, not an untrusted module
    # imported from the inspected source or the caller's Python path.
    path = Path(__file__).resolve().with_name("source_snapshot.py")
    spec = importlib.util.spec_from_file_location("_forgeflow_release_source_snapshot", path)
    if spec is None or spec.loader is None:
        raise ValueError("source snapshot producer unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_manifest(source_root, module.DEFAULT_EXCLUDES, scan_all)


def _load_independent_source_oracle():
    # This is an independently implemented audit algorithm, executed in this
    # process. Its presence or PASS cannot authenticate the build or a Gate.
    path = Path(__file__).resolve().parents[2] / "verification/ecp/p005_snapshot_oracle.py"
    spec = importlib.util.spec_from_file_location("_forgeflow_release_independent_source", path)
    if spec is None or spec.loader is None:
        raise OSError("independent source oracle unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _independent_begin(root: Path, sha: str, policy: list[str] | None = None):
    try:
        oracle = _load_independent_source_oracle()
        if policy is not None and policy != list(oracle.EXCLUDES):
            return None, "INCONCLUSIVE", {"reason": "independent source exclusion policy differs"}
        checked_root = oracle.no_symlink_directory(root)
        state = oracle.source_clean_begin(checked_root, sha)
        if state["source_execution_mode"] != "VERIFIED":
            return None, "INCONCLUSIVE", {"reason": "source executable mode is unavailable",
                                          "source_execution_mode": state["source_execution_mode"],
                                          "source_filesystem_type": state["source_filesystem_type"]}
        if state["source_untracked_directories"]:
            return None, "INCONCLUSIVE", {"reason": "source has untracked directories",
                                          "source_untracked_directories": state["source_untracked_directories"]}
        return (oracle, checked_root, state), None, {}
    except Exception as exc:
        # Invalid/missing/timeout/budget cases all prevent qualification. Keep
        # the exception class and text so an operator can distinguish them.
        return None, "INCONCLUSIVE", {"reason": "independent source audit could not establish source integrity",
                                      "error_type": type(exc).__name__, "error": str(exc)}


def _independent_end(observation, sha: str):
    oracle, root, state = observation
    try:
        oracle.source_clean_end(root, sha, state)
        mode, filesystem = oracle.source_mode_availability(root)
        if mode != "VERIFIED" or filesystem != state["source_filesystem_type"]:
            return "INCONCLUSIVE", {"reason": "source filesystem identity or executable mode changed"}
        return None, {"independent_source_algorithm": "p005_source_clean_begin_end",
                      "source_execution_mode": mode, "source_filesystem_type": filesystem,
                      "source_tracked_count": state["source_tracked_count"],
                      "source_tracked_bytes": state["source_tracked_bytes"],
                      "source_tracked_budget_bytes": oracle.MAX_SOURCE_BYTES,
                      "source_untracked_directories": state["source_untracked_directories"],
                      "independent_scope": "source bytes/index observation, not atomic snapshot or build provenance"}
    except Exception as exc:
        return "INCONCLUSIVE", {"reason": "independent source recheck could not establish source integrity",
                                 "error_type": type(exc).__name__, "error": str(exc)}


def inspect_source_manifest(path: Path, source_root: Path, source_sha: str, dirty_entries: list[str]) -> tuple[str, str | None, dict[str, Any]]:
    if not path.is_file():
        return "BLOCKED", None, {"reason": "source manifest is missing"}
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON constant")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return "REJECTED", None, {"reason": f"source manifest cannot be parsed: {exc}"}
    if not isinstance(manifest, dict):
        return "REJECTED", None, {"reason": "source manifest must be an object"}
    declared = manifest.get("manifest_sha256")
    core = {key: value for key, value in manifest.items() if key not in {"manifest_sha256", "created_at", "release_qualifiable"}}
    actual = sha_bytes(canonical_json(core))
    if not isinstance(declared, str) or declared != actual:
        return "REJECTED", actual, {"reason": "source manifest digest does not match canonical contents"}
    version = manifest.get("schema_version")
    if version == SOURCE_V1:
        # Keep every historical byte and digest untouched; missing safety fields
        # and previously emitted nonconforming v1 records cannot qualify now.
        legacy_fields = _SOURCE_FIELDS - {"inventory_complete", "inventory_error", "index_visibility_exceptions"}
        if set(manifest) != legacy_fields:
            return "INCONCLUSIVE", actual, {"reason": "nonconforming legacy v1 evidence is retained but not eligible for new qualification"}
        return "INCONCLUSIVE", actual, {"reason": "legacy v1 source evidence is not eligible for new qualification"}
    if version != SOURCE_V2:
        return "REJECTED", actual, {"reason": "unsupported source manifest version"}
    shape_error = _source_v2_error(manifest)
    if shape_error:
        return "REJECTED", actual, {"reason": shape_error}
    if manifest["head"] != source_sha:
        return "REJECTED", actual, {"reason": "source manifest HEAD does not match current Git HEAD"}
    try:
        manifest_root = Path(manifest["source_root"]).expanduser().resolve(strict=True)
    except (OSError, TypeError):
        return "REJECTED", actual, {"reason": "source manifest root is missing or invalid"}
    if manifest_root != source_root:
        return "REJECTED", actual, {"reason": "source manifest root does not match the requested source root"}
    if (manifest["worktree_state"] != "CLEAN" or not manifest["inventory_complete"]
            or not manifest["release_qualifiable"] or dirty_entries):
        return "INCONCLUSIVE", actual, {"reason": "source snapshot or current Git worktree is dirty/unfrozen"}
    observation, failure, detail = _independent_begin(source_root, source_sha, manifest["exclude_patterns"])
    if failure:
        return failure, actual, detail
    try:
        first = _current_source_snapshot(source_root, manifest["untracked_scan_mode"] == "all")
        second = _current_source_snapshot(source_root, manifest["untracked_scan_mode"] == "all")
    except (OSError, subprocess.SubprocessError, ValueError, ImportError) as exc:
        return "BLOCKED", actual, {"reason": f"independent source inventory unavailable: {exc}"}
    if (first.get("manifest_sha256") != second.get("manifest_sha256")
            or first.get("inventory_complete") is not True or first.get("worktree_state") != "CLEAN"):
        return "INCONCLUSIVE", actual, {"reason": "independent source inventory changed or is incomplete"}
    # Compare actual source facts, with only the draft version label changed in
    # memory. This does not rewrite, admit, or upgrade any historical evidence.
    independently_observed = {key: value for key, value in first.items() if key not in {"manifest_sha256", "created_at", "release_qualifiable"}}
    independently_observed["schema_version"] = SOURCE_V2
    if canonical_json(independently_observed) != canonical_json(core):
        return "INCONCLUSIVE", actual, {"reason": "source manifest differs from freshly produced inventory"}
    failure, detail = _independent_end(observation, source_sha)
    if failure:
        return failure, actual, detail
    return "PASS", actual, {"worktree_state": "CLEAN", "head": source_sha,
                            "inventory_verified": True, **detail}


def binary_inventory(paths: list[Path]) -> tuple[list[dict[str, Any]], str | None]:
    entries: list[dict[str, Any]] = []
    names: set[str] = set()
    for raw in paths:
        path = raw.expanduser()
        if not path.is_file() or path.is_symlink():
            return [], f"binary input is missing, not a regular file, or a symlink: {path}"
        name = path.name
        if name in names:
            return [], f"binary basenames must be unique: {name}"
        names.add(name)
        entries.append({"name": name, "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}", "sha256": sha_file(path)})
    entries.sort(key=lambda item: item["name"])
    if not entries:
        return [], "at least one binary input is required"
    return entries, None


def load_gate_snapshot(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.is_file():
        return None, f"gate snapshot is missing: {path}"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"gate snapshot cannot be parsed: {exc}"
    if not isinstance(data, dict):
        return None, "gate snapshot must contain a JSON object"
    return {"sha256": sha_bytes(canonical_json(data)), "data": data}, None


def add_tree_check(name: str, root: Path) -> tuple[dict[str, Any], list[dict[str, Any]], str | None]:
    if not root.is_dir():
        return {"name": name, "status": "BLOCKED", "reason": f"directory is missing: {root}"}, [], None
    try:
        entries = file_inventory(root)
    except (OSError, ValueError) as exc:
        return {"name": name, "status": "REJECTED", "reason": str(exc)}, [], None
    if not entries:
        return {"name": name, "status": "BLOCKED", "reason": "inventory is empty"}, [], None
    return {"name": name, "status": "PASS", "files": len(entries)}, entries, inventory_digest(entries)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--binary", type=Path, action="append", default=[])
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--profile-root", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--gate-snapshot", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    output_path = args.output.expanduser().resolve(strict=False)
    for input_root in (args.source_root, args.schema_root, args.profile_root, args.evidence_root):
        resolved_root = input_root.expanduser().resolve(strict=False)
        if output_path == resolved_root or resolved_root in output_path.parents:
            parser.error(f"--output must be outside input tree {resolved_root}")

    checks: list[dict[str, Any]] = []
    source_observation = None
    source_sha = ""
    dirty_entries: list[str] = []
    try:
        oracle = _load_independent_source_oracle()
        # Validate the user-supplied path before resolving it so a symlinked
        # ancestor cannot disappear from the source identity evidence.
        source_root = oracle.no_symlink_directory(args.source_root.expanduser())
        source_sha, dirty_entries = git_identity(source_root)
        source_status, source_digest, source_details = inspect_source_manifest(args.source_manifest, source_root, source_sha, dirty_entries)
        if source_status == "PASS":
            source_observation, failure, detail = _independent_begin(source_root, source_sha)
            if failure:
                source_status, source_details = failure, detail
        checks.append({"name": "source_identity", "status": source_status, **source_details})
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        source_status, source_digest = "BLOCKED", None
        checks.append({"name": "source_identity", "status": source_status, "reason": str(exc)})

    binaries, binary_error = binary_inventory(args.binary)
    binary_digest = inventory_digest(binaries) if binaries else None
    checks.append({"name": "binary_inputs", "status": "PASS" if binary_error is None else "BLOCKED", "reason": binary_error, "files": len(binaries)})

    schema_check, schema_entries, schema_digest = add_tree_check("schema_inputs", args.schema_root.expanduser())
    checks.append(schema_check)
    profile_check, profile_entries, profile_digest = add_tree_check("profile_inputs", args.profile_root.expanduser())
    checks.append(profile_check)
    evidence_check, evidence_entries, evidence_digest = add_tree_check("evidence_inputs", args.evidence_root.expanduser())
    checks.append(evidence_check)

    gate_snapshot, gate_error = load_gate_snapshot(args.gate_snapshot.expanduser())
    checks.append({"name": "gate_snapshot", "status": "PASS" if gate_error is None else "BLOCKED", "reason": gate_error})

    if source_observation is not None:
        failure, detail = _independent_end(source_observation, source_sha)
        if failure:
            source_check = next(item for item in checks if item["name"] == "source_identity")
            source_check.clear()
            source_check.update({"name": "source_identity", "status": failure, **detail})

    rejected = any(check["status"] == "REJECTED" for check in checks)
    blocking = any(check["status"] == "BLOCKED" for check in checks)
    inconclusive = any(check["status"] == "INCONCLUSIVE" for check in checks)
    status_value = "REJECTED" if rejected else "BLOCKED" if blocking else "INCONCLUSIVE" if inconclusive else "CANDIDATE"
    identity = {
        "source_sha": source_sha or None,
        "source_manifest_sha256": source_digest,
        "binary_manifest_sha256": binary_digest,
        "schema_manifest_sha256": schema_digest,
        "profile_manifest_sha256": profile_digest,
        "evidence_manifest_sha256": evidence_digest,
        "gate_snapshot": gate_snapshot,
    }
    candidate_digest = sha_bytes(canonical_json(identity))
    report = {
        "schema_version": SCHEMA_VERSION,
        "product_gate_effect": "NONE",
        "qualification": "NOT_RUN",
        "status": status_value,
        "candidate_id": f"candidate-{candidate_digest[:16]}",
        **identity,
        "worktree_dirty_entries": len(dirty_entries),
        "binary_files": binaries,
        "schema_manifest": schema_entries,
        "profile_manifest": profile_entries,
        "evidence_manifest": evidence_entries,
        "checks": checks,
        "created_at": created_at(),
        "release_approval": False,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": status_value, "product_gate_effect": "NONE", "release_approval": False}))
    return 0 if status_value == "CANDIDATE" else 20


if __name__ == "__main__":
    raise SystemExit(main())
