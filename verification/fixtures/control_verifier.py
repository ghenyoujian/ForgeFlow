#!/usr/bin/env python3
"""Finite controlled-output consumer; never reports DSH/industrial qualification."""
import json
import os
from pathlib import Path

ORACLE = "a10-controlled-output-contract.v1"
CASES = {
    "author": [("controlled_output_json", "positive"), ("controlled_seed_identity", "positive")],
    "consumer": [("controlled_output_consumer", "positive"), ("controlled_invalid_kind_rejected", "negative")],
    "independent": [("controlled_exact_reference", "positive"), ("controlled_extra_fields_rejected", "negative"),
                    ("controlled_seed_type_rejected", "negative"), ("controlled_empty_output_rejected", "negative")],
}


def consume(value, seed):
    if not isinstance(value, dict) or set(value) != {"kind", "seed"} or value["kind"] != "CONTROL_LOAD" or type(value["seed"]) is not int or value["seed"] != seed:
        raise ValueError("controlled output identity/schema invalid")
    return value


def rejects(value, seed):
    try:
        consume(value, seed)
    except ValueError:
        return True
    return False


def main():
    role = os.environ["FORGEFLOW_VERIFICATION_ROLE"]
    seed = int(os.environ["FORGEFLOW_EXPECTED_SEED"])
    relative = Path(os.environ["FORGEFLOW_OUTPUT_PATH"])
    if relative.is_absolute() or any(part in {".", ".."} for part in relative.parts):
        raise ValueError("output path must stay in controlled worktree")
    path = Path.cwd() / relative
    raw = path.read_bytes()
    value = json.loads(raw)
    outcomes = {name: False for name, _ in CASES[role]}
    if role == "author":
        outcomes["controlled_output_json"] = isinstance(value, dict) and bool(raw)
        outcomes["controlled_seed_identity"] = consume(value, seed)["seed"] == seed
    elif role == "consumer":
        outcomes["controlled_output_consumer"] = consume(value, seed) == {"kind": "CONTROL_LOAD", "seed": seed}
        outcomes["controlled_invalid_kind_rejected"] = rejects({**value, "kind": "REAL_DSH"}, seed)
    else:
        outcomes["controlled_exact_reference"] = value == {"kind": "CONTROL_LOAD", "seed": seed}
        outcomes["controlled_extra_fields_rejected"] = rejects({**value, "qualified_g20": True}, seed)
        outcomes["controlled_seed_type_rejected"] = rejects({**value, "seed": str(seed)}, seed)
        outcomes["controlled_empty_output_rejected"] = rejects({}, seed)
    report = {"binding": json.loads(os.environ["FORGEFLOW_EVIDENCE_BINDING"]), "oracle_id": ORACLE,
              "cases": [{"name": name, "kind": kind, "outcome": "passed" if outcomes[name] else "failed"} for name, kind in CASES[role]]}
    Path(os.environ["FORGEFLOW_REPORT_PATH"]).write_text(json.dumps(report) + "\n")
    print(json.dumps({"scope": "CONTROL_LOAD output contract only", "role": role, "executed": len(outcomes), "failed": sum(not v for v in outcomes.values())}))
    return 0 if all(outcomes.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
