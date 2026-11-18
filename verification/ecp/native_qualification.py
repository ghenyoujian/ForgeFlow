#!/usr/bin/env python3
"""Independent, fail-closed checker for Phase 5 native evidence.

The checker validates the evidence envelope and rejects fixture or historical
receipts for capabilities that require a current real-model run. It never
launches a provider and never changes a Gate status.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
import subprocess
from typing import Any

REQUIRED = {
    "managed_leaf",
    "subagent",
    "native_team",
    "workflow",
    "bot",
    "session_resume",
    "cancel",
    "structured_events",
    "child_supervision",
    "write_isolation",
    "cost_enforcement",
}
REAL_MODEL = {"subagent", "native_team", "workflow", "bot", "child_supervision"}
SUPPORT_STATUSES = {"SUPPORTED", "UNSUPPORTED", "UNKNOWN", "NOT_RUN"}
EVIDENCE_STATUSES = {"VERIFIED", "FAILED", "INCONCLUSIVE", "NOT_RUN", "BLOCKED"}
PROVIDERS = {"DSH", "CLAUDE"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def _git_head(source_root: Path) -> tuple[str | None, str | None]:
    """Read the live source HEAD without turning a missing checkout into PASS."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, str(exc)
    if completed.returncode != 0:
        return None, completed.stderr.strip() or f"git exited {completed.returncode}"
    value = completed.stdout.strip()
    return (value, None) if SHA1_RE.fullmatch(value) else (None, "git returned an invalid HEAD")


def check(
    root: Path,
    *,
    source_root: Path | None = None,
    source_manifest: Path | None = None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    manifest = root / "manifest.json"
    if not manifest.exists():
        return {
            "schema_version": "forgeflow.ecp-native-qualification.v1",
            "scope": "ECP_PHASE5_NATIVE_QUALIFICATION",
            "status": "NOT_RUN",
            "qualification": "NOT_RUN",
            "product_gate_effect": "NONE",
            "reason": "evidence manifest is absent",
            "denominator": {"total": 0, "passed": 0, "failed": 0},
            "checks": [],
        }
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "schema_version": "forgeflow.ecp-native-qualification.v1",
            "scope": "ECP_PHASE5_NATIVE_QUALIFICATION",
            "status": "INCONCLUSIVE",
            "qualification": "INCONCLUSIVE",
            "product_gate_effect": "NONE",
            "reason": f"manifest unreadable: {exc}",
            "denominator": {"total": 0, "passed": 0, "failed": 0},
            "checks": [],
        }
    capabilities = payload.get("capabilities")
    source_sha = payload.get("source_sha256")
    profile_sha = payload.get("profile_sha256")
    source_manifest_sha = payload.get("source_manifest_sha256")
    checks.append({"name": "manifest schema is pinned", "passed": payload.get("schema_version") == "forgeflow.ecp-native-evidence-manifest.v1"})
    checks.append({"name": "provider is an admitted native provider", "passed": payload.get("provider") in PROVIDERS})
    checks.append({"name": "qualification state is fail-closed", "passed": payload.get("qualification") in {"NOT_RUN", "VERIFIED", "FAILED", "INCONCLUSIVE", "BLOCKED"}})
    checks.append({"name": "manifest declares current source snapshot", "passed": isinstance(source_sha, str) and bool(SHA1_RE.fullmatch(source_sha))})
    checks.append({"name": "manifest declares immutable profile", "passed": isinstance(profile_sha, str) and bool(SHA256_RE.fullmatch(profile_sha))})
    if source_manifest_sha is not None:
        checks.append({"name": "manifest source snapshot digest is canonical", "passed": isinstance(source_manifest_sha, str) and bool(SHA256_RE.fullmatch(source_manifest_sha))})
    checks.append({"name": "capability rows are an array", "passed": isinstance(capabilities, list)})
    if source_root is not None:
        live_head, error = _git_head(source_root.resolve())
        checks.append({
            "name": "manifest source snapshot matches live checkout",
            "passed": live_head is not None and source_sha == live_head,
            "observed_source_sha": live_head,
            "manifest_source_sha": source_sha,
            "source_root": str(source_root.resolve()),
            "error": error,
        })
    if source_manifest is not None:
        manifest_digest = None
        manifest_error = None
        try:
            manifest_payload = json.loads(source_manifest.resolve().read_text(encoding="utf-8"))
            manifest_digest = manifest_payload.get("manifest_sha256")
        except (OSError, json.JSONDecodeError) as exc:
            manifest_error = str(exc)
        checks.append({
            "name": "manifest source content digest matches pinned source manifest",
            "passed": (
                isinstance(source_manifest_sha, str)
                and bool(SHA256_RE.fullmatch(source_manifest_sha))
                and source_manifest_sha == manifest_digest
            ),
            "observed_source_manifest_sha256": manifest_digest,
            "manifest_source_manifest_sha256": source_manifest_sha,
            "source_manifest": str(source_manifest.resolve()),
            "error": manifest_error,
        })
    rows = {row.get("name"): row for row in capabilities or [] if isinstance(row, dict)}
    checks.append({"name": "all required capability names are present", "passed": set(rows) == REQUIRED})
    for name in sorted(REQUIRED):
        row = rows.get(name, {})
        evidence = row.get("evidence")
        support = row.get("support")
        refs = row.get("evidence_refs") or []
        passed = evidence in EVIDENCE_STATUSES and support in SUPPORT_STATUSES
        refs_are_safe = isinstance(refs, list) and all(
            isinstance(ref, str)
            and not Path(ref).is_absolute()
            and ".." not in Path(ref).parts
            and (root / ref).is_file()
            for ref in refs
        )
        if refs:
            passed = passed and refs_are_safe
        if name in REAL_MODEL and evidence == "VERIFIED":
            passed = bool(payload.get("evidence_class") == "REAL_MODEL" and refs)
            passed = passed and refs_are_safe
        if evidence == "VERIFIED":
            passed = passed and support == "SUPPORTED"
        if support == "UNSUPPORTED":
            passed = passed and evidence != "VERIFIED"
        if evidence == "NOT_RUN":
            passed = passed and support in {"UNKNOWN", "NOT_RUN"}
        if support == "SUPPORTED" and not refs:
            passed = False
        checks.append({"name": f"capability {name} has non-forged evidence semantics", "passed": passed})
    passed = sum(bool(c["passed"]) for c in checks)
    total = len(checks)
    status = "PASS" if total and passed == total else ("INCONCLUSIVE" if passed else "BLOCKED")
    return {
        "schema_version": "forgeflow.ecp-native-qualification.v1",
        "scope": "ECP_PHASE5_NATIVE_QUALIFICATION",
        "status": status,
        "qualification": "OBSERVED_NOT_GATE" if status == "PASS" else status,
        "product_gate_effect": "NONE",
        "source_sha256": payload.get("source_sha256"),
        "profile_sha256": payload.get("profile_sha256"),
        "evidence_class": payload.get("evidence_class"),
        "checks": checks,
        "denominator": {"total": total, "passed": passed, "failed": total - passed},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--source-root",
        type=Path,
        help="optional live checkout to which the evidence source SHA must bind",
    )
    parser.add_argument(
        "--source-manifest",
        type=Path,
        help="optional canonical source manifest whose digest must match the evidence pin",
    )
    args = parser.parse_args()
    report = check(args.evidence_root, source_root=args.source_root, source_manifest=args.source_manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["status"] == "PASS" else (20 if report["status"] in {"NOT_RUN", "BLOCKED", "INCONCLUSIVE"} else 10)


if __name__ == "__main__":
    raise SystemExit(main())
