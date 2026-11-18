#!/usr/bin/env python3
"""Static Phase 7 UI/SSE contract check; never claims browser qualification."""
from __future__ import annotations
import argparse, hashlib, json, subprocess
from pathlib import Path

REQUIRED = {
    "api_context_headers": ["X-ForgeFlow-Workspace", "Idempotency-Key", "If-Match", "REQUEST_CONTEXT_CHANGED"],
    "workspace_namespace": ["forgeflow.auth-scope", "setWorkspace", "forgeflow.workspace-role"],
    "sse_cursor": ["Last-Event-ID", "SNAPSHOT_REQUIRED", "EVENT_SEQUENCE_GAP", "forgeflow-resync"],
    "truthful_states": ["accepted", "processing", "UNSUPPORTED", "UNKNOWN"],
    "agent_registry_ui": ["AgentRegistryPage", "EcpProfile", "qualification", "discovery_only"],
}


def git_sha(root: Path) -> str | None:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=30, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.source_root.resolve()
    if not (root / "console/src/app/api.ts").exists() and (root.parent / "console/src/app/api.ts").exists():
        root = root.parent
    sources = {
        "api": root / "console/src/app/api.ts",
        "events": root / "console/src/app/events.ts",
        "contract": root / "docs/ecp/ui-contract.md",
        "fixtures": root / "console/tests/ecp/README.md",
    }
    checks = []
    for name, markers in REQUIRED.items():
        paths = [sources["api"], sources["events"]]
        if name == "truthful_states": paths += [sources["contract"], sources["fixtures"]]
        if name == "agent_registry_ui": paths += [root / "console/src/features/agents/EcpRegistry.tsx", root / "console/src/features/agents/EcpProfile.tsx"]
        haystack = "\n".join(path.read_text(encoding="utf-8") for path in paths if path.exists())
        missing = [marker for marker in markers if marker not in haystack]
        checks.append({"name": name, "status": "PASS" if not missing else "FAIL", "missing": missing})
    checks.append({"name": "browser_runner", "status": "NOT_RUN", "reason": "no Playwright/browser runner is bound by this static check"})
    status = "FAIL" if any(check["status"] == "FAIL" for check in checks) else "NOT_RUN"
    report = {
        "schema_version": "forgeflow.ecp-ui-contract.v1",
        "product_gate_effect": "NONE",
        "status": status,
        "qualification": "NOT_RUN",
        "source_root": str(root),
        "source_sha": git_sha(root),
        "checks": checks,
        "denominator": {"static_checks": len(REQUIRED), "browser_journeys": 0},
        "browser_evidence": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))
    return 10 if status == "FAIL" else 20


if __name__ == "__main__":
    raise SystemExit(main())
