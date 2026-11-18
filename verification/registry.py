#!/usr/bin/env python3
"""Conservative evidence index: each obligation must point to inspected evidence."""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def registry(contracts_path, evidence_dir):
    contract = json.loads(Path(contracts_path).read_text())
    entries = []
    for group in ("product", "phase"):
        for gate, obligations in contract[group].items():
            proof_path = Path(evidence_dir) / f"{group}-{gate}.json"
            proof = json.loads(proof_path.read_text()) if proof_path.exists() else {}
            claims = proof.get("obligations", {})
            rows = []
            for obligation in obligations:
                claim = claims.get(obligation, {})
                artifacts = []
                for item in claim.get("artifacts", []):
                    path = Path(item["path"])
                    if not path.is_absolute():
                        path = proof_path.parent / path
                    valid = path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == item.get("sha256")
                    artifacts.append({**item, "hash_verified": valid})
                # This validates provenance only. An independent reviewer records a
                # scope_match decision after inspecting actual artifact contents.
                status = claim.get("status", "INCONCLUSIVE")
                if status == "PASS" and (not claim.get("scope_match_reviewed") or not artifacts or not all(a["hash_verified"] for a in artifacts)):
                    status = "INCONCLUSIVE"
                rows.append({"obligation": obligation, "status": status, "artifacts": artifacts,
                             "reason": claim.get("reason", "No independent scope-matched evidence")})
            status = "PASS" if rows and all(r["status"] == "PASS" for r in rows) else "FAIL" if any(r["status"] == "FAIL" for r in rows) else "BLOCKED" if any(r["status"] == "BLOCKED" for r in rows) else "INCONCLUSIVE"
            entries.append({"group": group, "gate_id": gate, "status": status, "obligations": rows})
    return {"schema_version": "forgeflow.verification.registry.v1", "at": datetime.now(timezone.utc).isoformat(), "gates": entries}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--contracts", default=str(Path(__file__).with_name("gate_contracts.json")))
    parser.add_argument("--evidence-dir", default=str(Path(__file__).with_name("evidence")))
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    result = registry(args.contracts, args.evidence_dir)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"gates": len(result["gates"]), "statuses": {s: sum(g["status"] == s for g in result["gates"]) for s in ("PASS", "FAIL", "BLOCKED", "INCONCLUSIVE")}}))
