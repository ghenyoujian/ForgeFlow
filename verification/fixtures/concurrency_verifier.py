#!/usr/bin/env python3
"""Independent finite artifact oracle. It never asserts session concurrency or G20."""
import json
import os
from pathlib import Path

ORACLE = "forgeflow.concurrency-artifact.v1"
CASES = {
    "author": [("valid_json", "positive"), ("exact_identity", "positive")],
    "consumer": [("computed_value", "positive"), ("extra_fields_rejected", "negative")],
    "independent": [("independent_sum", "positive"), ("wrong_task_rejected", "negative"),
        ("wrong_value_rejected", "negative"), ("boolean_value_rejected", "negative")],
}


def consume(value, campaign, task, n):
    if (not isinstance(value, dict) or set(value) != {"schema_version", "campaign_id", "task_id", "value"}
            or value["schema_version"] != "forgeflow.concurrency-artifact.v1"
            or value["campaign_id"] != campaign or value["task_id"] != task
            or type(value["value"]) is not int or value["value"] != sum(range(n + 1))):
        raise ValueError("finite artifact contract rejected")
    return value


def main():
    role = os.environ["FORGEFLOW_VERIFICATION_ROLE"]
    campaign, task = os.environ["FORGEFLOW_CAMPAIGN_ID"], os.environ["FORGEFLOW_TASK_ID"]
    n = int(os.environ["FORGEFLOW_SUM_N"])
    path = Path("outputs") / (task + ".json")
    value = json.loads(path.read_text())
    def rejected(candidate):
        try: consume(candidate, campaign, task, n)
        except ValueError: return True
        return False
    outcomes = {"valid_json": isinstance(value, dict), "exact_identity": value.get("task_id") == task,
        "computed_value": consume(value, campaign, task, n)["value"] == n * (n + 1) // 2,
        "extra_fields_rejected": rejected({**value, "g20": "PASS"}),
        "independent_sum": consume(value, campaign, task, n)["value"] == sum(range(n + 1)),
        "wrong_task_rejected": rejected({**value, "task_id": task + "-other"}),
        "wrong_value_rejected": rejected({**value, "value": -1}),
        "boolean_value_rejected": rejected({**value, "value": True})}
    cases = [{"name": name, "kind": kind, "outcome": "passed" if outcomes[name] else "failed"}
        for name, kind in CASES[role]]
    report = {"binding": json.loads(os.environ["FORGEFLOW_EVIDENCE_BINDING"]), "oracle_id": ORACLE, "cases": cases}
    Path(os.environ["FORGEFLOW_REPORT_PATH"]).write_text(json.dumps(report) + "\n")
    return 0 if all(c["outcome"] == "passed" for c in cases) else 1


if __name__ == "__main__":
    raise SystemExit(main())
