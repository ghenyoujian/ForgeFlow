#!/usr/bin/env python3
"""Report that the unadmitted standalone test runner is blocked.

This temporary transition preserves CLI option parsing but executes no suite.
Formal P0-03 still requires authenticated source, principal, lease, resource
confinement, protected raw evidence, actual test outcomes and an independent
oracle. The diagnostic check count is not a test denominator.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse normally echoes rejected values and unknown options, which
        # can contain a path, credentials or an unbounded user-controlled blob.
        self.exit(2, f"{self.prog}: invalid command-line arguments\n")


def main() -> int:
    parser = _SafeArgumentParser(prog="ecp-runner", description=__doc__)
    parser.add_argument("--suite-id", required=True)
    parser.add_argument("--source-root")
    parser.add_argument("--command-json")
    parser.add_argument("--allow-execution", action="store_true")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    reason = ("Execution is blocked: source, principal, lease, resource confinement and evidence "
              "isolation are not authenticated. The denominator counts diagnostic checks only; "
              "no test was executed.")
    report = {
        "schema_version": "forgeflow.ecp-verification.v1",
        "scope": "ECP_PHASE0_ONLY",
        "product_gate_effect": "NONE",
        "qualification": "NOT_RUN",
        "command": "suite",
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source_root": None,
        "source_sha": None,
        "status": "BLOCKED",
        "suite_id": "ECP-P0-03" if args.suite_id == "ECP-P0-03" else None,
        "reason": reason,
        "workload_invoked": False,
        "workload_confinement_verified": False,
        "independent_execution_authority_verified": False,
        "database_connections_attempted": None,
        "evidence_refs": [],
        "checks": [{"name": "execution_authority", "status": "BLOCKED", "reason": reason, "details": {}}],
        "denominator": {"total": 1, "passed": 0, "failed": 0, "blocked": 1, "not_run": 0, "inconclusive": 0},
    }
    print(json.dumps(report, ensure_ascii=True, sort_keys=True))
    return 20


if __name__ == "__main__":
    raise SystemExit(main())
