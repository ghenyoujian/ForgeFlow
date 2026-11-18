#!/usr/bin/env python3
"""Independent source-bound DraftBundle oracle; no production imports."""
import copy
import hashlib
import json
import os
from pathlib import Path

ORACLE = "a10-source-bound-flow-draft.v1"
CASES = {
    "author": [("native_final_artifact", "positive"), ("draft_schema_and_request_binding", "positive")],
    "consumer": [("finite_dag_consumer", "positive"), ("cycle_rejected", "negative")],
    "independent": [("original_source_preserved", "positive"), ("source_tamper_rejected", "negative"),
                    ("authority_tamper_rejected", "negative"), ("strict_duplicate_keys_rejected", "negative")],
}
TASK_FIELDS = {"project_id", "task_id", "task_revision", "flow_revision", "title", "owner_id", "team_id", "requirement_ids", "read_set", "write_set", "dependencies", "state", "input_digest", "resource_request", "envelope", "revision"}
FLOW_FIELDS = {"project_id", "flow_revision", "parent_revision", "state", "tasks", "input_digest", "approved_by", "revision"}
RESOURCE_FIELDS = {"active_slot", "coding_slot", "cpu_units", "memory_bytes", "build_permit", "gpu_permit", "provider_inflight"}


def strict_load(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def constant(value):
        raise ValueError("nonfinite JSON number:" + value)
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def path_valid(path):
    return isinstance(path, str) and bool(path) and not path.startswith("/") and "\\" not in path and ":" not in path and "\0" not in path and all(part not in {"", ".", ".."} for part in path.rstrip("/").split("/"))


def covered(path, scope):
    return path_valid(path) and path_valid(scope) and (path == scope or scope.endswith("/") and path.startswith(scope))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(bundle, request):
    require(isinstance(bundle, dict) and set(bundle) == {"generation_method", "flow", "context"}, "DraftBundle fields")
    require(bundle["generation_method"] == "dsh_model_assisted", "generation provenance")
    flow = bundle["flow"]
    require(isinstance(flow, dict) and set(flow) == FLOW_FIELDS, "Flow schema")
    require(flow["project_id"] == request["project_id"] and flow["flow_revision"] == request["flow_revision"], "project/version scope")
    require(flow["state"] == "DRAFT" and flow["approved_by"] is None, "model cannot approve Flow")
    tasks = flow["tasks"]
    require(isinstance(tasks, list) and 1 <= len(tasks) <= 10000, "finite nonempty tasks")
    context = bundle["context"]
    require(isinstance(context, dict), "context object")
    require(context["source_revision"] == request["source"]["raw_sha256"], "immutable original source identity")
    originals = {r["requirement_id"]: r for r in request["source"]["requirements"]}
    actual = context["requirements"]
    require(len(actual) == len(originals) and len({r["requirement_id"] for r in actual}) == len(actual), "source requirement count")
    require(all(r == originals.get(r["requirement_id"]) for r in actual), "source anchors/acceptance/priority preserved")
    require(set(context["task_specs"]) == {t["task_id"] for t in tasks}, "task specification identities")
    require(len({t["task_id"] for t in tasks}) == len(tasks), "unique task identities")
    pending = {}
    covered_requirements = set()
    for task in tasks:
        require(set(task) == TASK_FIELDS, "canonical task schema")
        require(task["project_id"] == request["project_id"] and task["flow_revision"] == request["flow_revision"], "task project/version")
        require(task["owner_id"] == request["owner_id"] and task["team_id"] == request["team_id"], "task authority")
        require(task["state"] in {"PLANNED", "NEEDS_REVIEW"} and task["envelope"] is None, "no execution authority in draft")
        require(task["title"].strip() and type(task["task_revision"]) is int and task["task_revision"] >= 1, "finite task identity/outcome")
        require(set(task["requirement_ids"]) <= set(originals) and task["requirement_ids"], "task requirement references")
        covered_requirements.update(task["requirement_ids"])
        require(all(path_valid(path) for path in task["read_set"] + task["write_set"]), "normalized read/write paths")
        require(all(any(covered(path, scope) for scope in request["write_set"]) for path in task["write_set"]), "no expanded writes")
        resources = task["resource_request"]
        require(set(resources) == RESOURCE_FIELDS and all(type(v) is int and 0 <= v < 2**64 for v in resources.values()), "bounded resource vector")
        spec = context["task_specs"][task["task_id"]]
        require(spec["outcome"].strip() and spec["rollback_plan"].strip() and spec["verification_plan"].strip(), "semantic finite task and verification")
        require(type(spec["verification_case_count"]) is int and spec["verification_case_count"] > 0, "nonzero declared case denominator")
        require(spec["execution_profile"] == request["execution_profile"] and spec["verification_plan"] == request["verification_plan"], "approved executor/verification identities")
        for requirement_id in task["requirement_ids"]:
            r = originals[requirement_id]
            require(r["source_document"] + "#" + r["anchor"] in spec["design_anchors"], "original requirement anchor")
        require(len(task["dependencies"]) == len(set(task["dependencies"])), "duplicate dependencies")
        pending[task["task_id"]] = set(task["dependencies"])
    require(all(deps <= set(pending) for deps in pending.values()), "missing DAG predecessor")
    # Repeated elimination is independent of production DFS/Kahn internals.
    while pending:
        ready = {key for key, deps in pending.items() if not deps}
        require(bool(ready), "dependency cycle")
        pending = {key: deps - ready for key, deps in pending.items() if key not in ready}
    require(all(rid in covered_requirements or r.get("deferred_reason") for rid, r in originals.items()), "complete source coverage")
    return True


def rejected(bundle, request):
    try:
        validate(bundle, request)
    except (ValueError, KeyError, TypeError, AttributeError):
        return True
    return False


def main():
    role = os.environ["FORGEFLOW_VERIFICATION_ROLE"]
    binding = strict_load(os.environ["FORGEFLOW_EVIDENCE_BINDING"])
    request = strict_load(Path(os.environ["FORGEFLOW_DRAFT_REQUEST_PATH"]).read_text())
    raw = Path(os.environ["FORGEFLOW_ARTIFACT_PATH"]).read_bytes()
    result = {name: False for name, _ in CASES[role]}
    errors = []
    try:
        require(hashlib.sha256(raw).hexdigest() == binding["artifact_hash"], "artifact bytes match immutable binding")
        final = strict_load(raw.decode("utf-8"))
        require(isinstance(final, dict) and final.get("type") == "final" and isinstance(final.get("text"), str), "native terminal artifact")
        bundle = strict_load(final["text"])
        validate(bundle, request)
        if role == "author":
            result["native_final_artifact"] = True
            result["draft_schema_and_request_binding"] = True
        elif role == "consumer":
            result["finite_dag_consumer"] = True
            changed = copy.deepcopy(bundle)
            changed["flow"]["tasks"][0]["dependencies"] = [changed["flow"]["tasks"][0]["task_id"]]
            result["cycle_rejected"] = rejected(changed, request)
        else:
            result["original_source_preserved"] = True
            changed = copy.deepcopy(bundle)
            changed["context"]["requirements"][0]["acceptance"] += " silently lowered"
            result["source_tamper_rejected"] = rejected(changed, request)
            changed = copy.deepcopy(bundle)
            changed["flow"]["tasks"][0]["write_set"] = ["../outside-root"]
            changed["flow"]["tasks"][0]["owner_id"] = "unauthorized-owner"
            result["authority_tamper_rejected"] = rejected(changed, request)
            try:
                strict_load('{"flow":{},"flow":{"state":"COMMITTED"}}')
            except ValueError:
                result["strict_duplicate_keys_rejected"] = True
    except Exception as exc:
        errors.append(type(exc).__name__ + ":" + str(exc))
    report = {"binding": binding, "oracle_id": ORACLE,
              "cases": [{"name": name, "kind": kind, "outcome": "passed" if result[name] else "failed"} for name, kind in CASES[role]]}
    report_path = Path(os.environ["FORGEFLOW_REPORT_PATH"])
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False) + "\n")
    print(json.dumps({"role": role, "executed": len(result), "failed": sum(not v for v in result.values()), "errors": errors}))
    return 0 if all(result.values()) and not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
