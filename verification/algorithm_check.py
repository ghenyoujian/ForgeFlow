#!/usr/bin/env python3
"""Independent JSON fixtures into actual Rust production algorithm probe."""
import argparse
import copy
import hashlib
import json
import random
import subprocess
from pathlib import Path

from oracle import NEXT, dag_order, covers, overlap

DIMENSIONS = ("active_slot", "coding_slot", "cpu_units", "memory_bytes", "build_permit", "gpu_permit", "provider_inflight")
DIGEST_PROFILE = "task-v2-flow-version-external"


def vector(active=0):
    return {key: active if key == "active_slot" else 0 for key in DIMENSIONS}


def requirement_digest(requirement):
    """Independent encoding of the published full-meaning requirement contract."""
    identity = ["forgeflow.requirement.semantic.v1"] + [requirement[key] for key in
        ("project_id", "requirement_id", "source_anchor", "outcome", "scope", "acceptance",
         "priority", "weight", "deferred_reason")]
    return hashlib.sha256(json.dumps(identity, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def make_compile(count=3):
    tasks, specs = [], {}
    meaning = requirement_digest({"project_id": "p", "requirement_id": "R01", "source_anchor": "fixture#R01",
        "outcome": "check actual output", "scope": "imported requirement; refine before admission",
        "acceptance": ["check actual output"], "priority": 1, "weight": 1, "deferred_reason": None})
    for index in range(count):
        task_id = f"t{index:05d}"
        dependencies = [f"t{index - 1:05d}"] if index and count < 100 else []
        spec = {"outcome": "independently specified finite artifact",
                **({"requirement_digest_refs": {"R01": meaning}} if DIGEST_PROFILE != "task-v1-flow-version-included" else {}),
                "design_anchors": ["fixture#R01"],
                "inputs": [{"path": "input.json", "sha256": "a" * 64, "producer_task_id": None}],
                "mandatory_paths": ["input.json"],
                "dependency_refs": [{"task_id": dep, "project_id": "p", "kind": "integrated", "binding_id": "receipt-" + dep} for dep in dependencies],
                "contract_produces": [], "contract_consumes": [], "execution_profile": "CONTROL_LOAD",
                "verification_plan": "fixture-check", "verification_case_count": 2,
                "rollback_plan": "retain candidate", "known_unknowns": [], "not_proven": ["not real DSH"], "isolated_contract_probe": False}
        digest = hashlib.sha256(json.dumps(spec, separators=(",", ":")).encode()).hexdigest()
        specs[task_id] = spec
        tasks.append({"project_id": "p", "task_id": task_id, "task_revision": 1, "flow_revision": 1,
                      "title": task_id, "owner_id": "o", "team_id": "team", "requirement_ids": ["R01"],
                      "read_set": ["input.json"], "write_set": [f"outputs/{task_id}.json"], "dependencies": dependencies,
                      "state": "PLANNED", "input_digest": digest, "resource_request": vector(1), "envelope": None, "revision": 1})
        refresh_digest(tasks[-1], spec)
    return {"operation": "compile", "flow": {"project_id": "p", "flow_revision": 1, "parent_revision": None,
            "state": "DRAFT", "tasks": tasks, "input_digest": "b" * 64, "approved_by": None, "revision": 1},
            "context": {"requirements": [{"requirement_id": "R01", "source_document": "fixture", "anchor": "R01",
            "acceptance": "check actual output", "priority": 1, "deferred_reason": None}],
            **({"requirement_semantic_digests": {"R01": meaning}} if DIGEST_PROFILE != "task-v1-flow-version-included" else {}),
            "owners": [{"owner_id": "o", **({"root_team_id": "team"} if DIGEST_PROFILE != "task-v1-flow-version-included" else {}), "include": ["outputs/"], "exclude": []}], "task_specs": specs,
            "current_inputs": {"input.json": "a" * 64}, "resolved_paths": {}, "contracts": [],
            "source_revision": "c" * 40, "observed_at": "2026-10-09T00:00:00Z"}}


def refresh_digest(task, spec):
    immutable = [task["project_id"], task["task_id"], task["task_revision"],
                 task["owner_id"], task["team_id"], task["requirement_ids"], task["read_set"], task["write_set"],
                 task["dependencies"], task["resource_request"], spec]
    if DIGEST_PROFILE == "task-v1-flow-version-included":
        immutable.insert(3, task["flow_revision"])
    else:
        immutable.insert(0, "forgeflow.task.input.v2")
    task["input_digest"] = hashlib.sha256(json.dumps(immutable, separators=(",", ":")).encode()).hexdigest()


def compiler_cases():
    cases = []
    def add(name, mutate, expected_rule=None):
        value = make_compile()
        mutate(value)
        for task in value["flow"]["tasks"]:
            refresh_digest(task, value["context"]["task_specs"][task["task_id"]])
        cases.append((name, value, expected_rule))
    add("valid_three_task_chain", lambda v: None)
    add("dangling_dependency", lambda v: v["flow"]["tasks"][2]["dependencies"].append("missing"), "DANGLING_DEPENDENCY")
    add("dependency_cycle", lambda v: v["flow"]["tasks"][0]["dependencies"].append("t00002"), "DEPENDENCY_CYCLE")
    add("owner_escape", lambda v: v["flow"]["tasks"][0].update(write_set=["secret.txt"]), "OWNER_TERRITORY")
    add("stale_input", lambda v: v["context"]["current_inputs"].update({"input.json": "d" * 64}), "INPUT_HASH_DRIFT")
    def alias(value):
        value["flow"]["tasks"][1]["dependencies"] = []
        value["context"]["owners"][0]["include"].append("alias/")
        value["flow"]["tasks"][0]["write_set"] = ["alias/file"]
        value["flow"]["tasks"][1]["write_set"] = ["outputs/shared"]
        value["context"]["resolved_paths"]["alias/file"] = "outputs/shared"
    add("canonical_alias_conflict", alias, "WRITE_SCOPE_CONFLICT")
    def contract(value):
        spec = value["context"]["task_specs"]["t00000"]
        spec["contract_consumes"] = [{"contract_id": "missing", "version": 1, "spec_sha256": "a" * 64}]
        value["flow"]["tasks"][0]["input_digest"] = hashlib.sha256(json.dumps(spec, separators=(",", ":")).encode()).hexdigest()
    add("unfrozen_contract", contract, "CONTRACT_NOT_FROZEN")
    if DIGEST_PROFILE != "task-v1-flow-version-included":
        add("requirement_full_meaning_missing", lambda v: v["context"]["requirement_semantic_digests"].clear(), "REQUIREMENT_SEMANTICS_UNQUALIFIED")
        add("unchanged_requirement_id_changed_meaning", lambda v: v["context"]["task_specs"]["t00000"]["requirement_digest_refs"].update(R01="e" * 64), "REQUIREMENT_SEMANTIC_BINDING")
    return cases


def scheduler_case(seed, size=40):
    rng = random.Random(seed)
    base = make_compile(size)
    tasks = base["flow"]["tasks"]
    teams = [{"project_id": "p", "team_id": f"team{i}", "parent_team_id": f"team{i-1}" if i else None,
              "name": f"level{i}", "paused": False, "revision": 1} for i in range(4)]
    capacities = {"global": 7, "project": 6, "worker": 6, "team0": 6, "team1": 5, "team2": 4, "team3": 3}
    scopes = []
    for key, limit in capacities.items():
        scopes.append({"policy": {"scope_id": key, "parent_scope_id": "global" if key != "global" else None,
                                  "worker_id": "fixture-worker" if key == "worker" else None,
                                  "project_id": "p" if key not in {"global", "worker"} else None,
                                  "team_id": key if key.startswith("team") else None,
                                  "limits": vector(limit), "revision": 1, "paused": False}, "allocated": vector(rng.randrange(0, 2))})
    candidates = []
    receipts = []
    for index, task in enumerate(tasks):
        task["state"] = "READY_FOR_ADMISSION"
        task["team_id"] = "team3"
        task["dependencies"] = []
        task["owner_id"] = f"owner{index % 3}"
        candidates.append({"project_id": "p", "root_team_id": "team0", "task_id": task["task_id"], "priority": rng.randrange(-5, 30), "enqueued_at_ms": index,
                           "enqueue_sequence": index, "scope_ids": ["team3"], "worker_scope_id": "worker", "worker_id": "fixture-worker",
                           "has_open_attempt": rng.random() < .15, "immutable_inputs_valid": rng.random() >= .1,
                           "executor_capable": rng.random() >= .1, "retry_not_before_ms": None})
    return {"operation": "schedule", "input": {"tasks": tasks, "teams": teams, "scopes": scopes,
            "candidates": candidates, "dependency_receipts": receipts, "active_writes": [],
            "committed_flows": {"p": 1}, "project_weights": {"p": 1},
            "cursor": {"project_index": 0, "remaining_project_turns": 0, "owner_indices": {}},
            "now_ms": 500, "aging_interval_ms": 100, "candidate_window": size,
            "maximum_selections": 128}}


def composite_scheduler_cases():
    """Two real project identities deliberately reuse local task and team IDs."""
    request = scheduler_case(12, 1)
    value = request["input"]
    for scope in value["scopes"]:
        scope["allocated"] = vector()
        scope["policy"]["limits"] = vector(10)
    value["candidates"][0].update(has_open_attempt=False, immutable_inputs_valid=True, executor_capable=True)
    value["tasks"][0]["owner_id"] = "owner"
    second_task = copy.deepcopy(value["tasks"][0])
    second_task["project_id"] = "q"
    value["tasks"].append(second_task)
    value["teams"].extend({**copy.deepcopy(t), "project_id": "q"} for t in list(value["teams"]))
    copied = []
    for scope in value["scopes"]:
        policy = scope["policy"]
        if policy["project_id"] == "p":
            extra = copy.deepcopy(scope)
            extra["policy"].update(project_id="q", scope_id="q-" + policy["scope_id"])
            copied.append(extra)
    value["scopes"].extend(copied)
    second_candidate = copy.deepcopy(value["candidates"][0])
    second_candidate.update(project_id="q", scope_ids=["q-team3"])
    value["candidates"].append(second_candidate)
    value["committed_flows"]["q"] = 1
    value["project_weights"]["q"] = 1
    value["candidate_window"] = 16
    request["expected_selection"] = [["p", "t00000"], ["q", "t00000"]]
    cases = [("composite_identical_local_ids", copy.deepcopy(request), None)]
    draft = copy.deepcopy(request)
    draft["input"]["committed_flows"].pop("q")
    draft["expected_selection"] = [["p", "t00000"]]
    cases.append(("uncommitted_other_project_does_not_abort", draft, None))
    legacy = copy.deepcopy(request)
    legacy["input"]["candidates"][0]["project_id"] = ""
    legacy["expected_selection"] = [["q", "t00000"]]
    cases.append(("ambiguous_legacy_candidate_blocks_only_itself", legacy, None))
    return cases


def schedule_errors(request, data):
    """Brute-force sums independent of production fairness policy implementation."""
    value = request["input"]
    tasks = {(t["project_id"], t["task_id"]): t for t in value["tasks"]}
    candidates = {(c["project_id"], c["task_id"]): c for c in value["candidates"]}
    selected = [(t["project_id"], t["task_id"]) for t in data["selected_tasks"]] if "selected_tasks" in data else [("p", tid) for tid in data["selected_task_ids"]]
    failures = []
    if len(selected) != len(set(selected)):
        failures.append("duplicate_selection")
    for tid in selected:
        candidate = candidates[tid]
        if candidate["has_open_attempt"] or not candidate["immutable_inputs_valid"] or not candidate["executor_capable"]:
            failures.append("illegal_candidate_selected")
    for scope in value["scopes"]:
        for dimension in DIMENSIONS:
            total = scope["allocated"][dimension] + sum(tasks[t]["resource_request"][dimension] for t in selected)
            if total > scope["policy"]["limits"][dimension]:
                failures.append("ancestor_overflow:" + scope["policy"]["scope_id"] + ":" + dimension)
    eligible = [c for c in value["candidates"] if not c["has_open_attempt"] and c["immutable_inputs_valid"] and c["executor_capable"]]
    expected_count = min(len(eligible), min(s["policy"]["limits"]["active_slot"] - s["allocated"]["active_slot"] for s in value["scopes"]))
    if len(selected) != expected_count:
        failures.append(f"eligible_frontier_size:{len(selected)}!={expected_count}")
    return failures


def run(args):
    cases = [("state_144_pairs", {"operation": "state_pairs"}, None)] + compiler_cases()
    cases.extend((f"scheduler-seed-{seed}", scheduler_case(seed), None) for seed in range(args.seed, args.seed + args.scheduler_samples))
    if DIGEST_PROFILE != "task-v1-flow-version-included":
        cases.extend(composite_scheduler_cases())
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    requests = "".join(json.dumps(value, separators=(",", ":")) + "\n" for _, value, _ in cases)
    (output / "requests.jsonl").write_text(requests)
    result = subprocess.run([args.probe], input=requests, text=True, capture_output=True, timeout=300)
    (output / "responses.jsonl").write_text(result.stdout)
    (output / "stderr.txt").write_text(result.stderr)
    rows = []
    replies = result.stdout.splitlines()
    for index, (name, request, expected_rule) in enumerate(cases):
        errors = []
        reply = json.loads(replies[index]) if index < len(replies) else {"error": "missing_probe_response"}
        data = reply.get("data")
        assertions = 0
        if data is None:
            errors.append(reply.get("error", "missing_data"))
        elif request["operation"] == "state_pairs":
            assertions = len(data)
            for pair in data:
                expected = pair["to"] in NEXT[pair["from"]]
                if pair["allowed"] != expected:
                    errors.append(f"{pair['from']}->{pair['to']} actual {pair['allowed']} expected {expected}")
        elif request["operation"] == "compile":
            assertions = 2
            rules = {f["rule_id"] for f in data["findings"]}
            if expected_rule and (expected_rule not in rules or data["passed"]):
                errors.append("negative_not_rejected:" + expected_rule)
            elif expected_rule is None:
                if not data["passed"]:
                    errors.append("valid_fixture_rejected:" + str(sorted(rules)))
                normalized = [{"task_id": t["task_id"], "depends_on": t["dependencies"]} for t in request["flow"]["tasks"]]
                if not valid_topology(normalized, data["topological_order"]):
                    errors.append("topological_order_mismatch")
            if expected_rule:
                matching = [f for f in data["findings"] if f["rule_id"] == expected_rule]
                if not matching or not all(f["subject_ref"] and f["blocked_tasks"] for f in matching):
                    errors.append("negative_not_located")
                assertions += 1
            if expected_rule == "DEPENDENCY_CYCLE":
                edges = {t["task_id"]: t["dependencies"] for t in request["flow"]["tasks"]}
                actual_paths = [f["evidence_refs"] for f in data["findings"] if f["rule_id"] == expected_rule]
                if not any(len(path) > 1 and path[0] == path[-1] and all(b in edges.get(a, []) for a, b in zip(path, path[1:])) for path in actual_paths):
                    errors.append("cycle_evidence_not_actual_closed_dependency_path")
                assertions += 1
        else:
            if "expected_selection" in request:
                actual = [(t["project_id"], t["task_id"]) for t in data.get("selected_tasks", [])]
                expected = {tuple(t) for t in request["expected_selection"]}
                if set(actual) != expected or len(actual) != len(set(actual)):
                    errors.append("scoped_selection_mismatch:" + str(actual))
            else:
                errors = schedule_errors(request, data)
            assertions = len(request["input"]["scopes"]) * len(DIMENSIONS) + 2 + len(data.get("selected_tasks", data.get("selected_task_ids", [])))
        rows.append({"case": name, "assertions": assertions, "status": "FAIL" if errors else "PASS", "errors": errors, "actual_elapsed_ns": reply.get("elapsed_ns")})
    report = {"scope": "real Rust ordinary state table, finite compiler counterexamples, hierarchical scheduler independent recomputation",
              "digest_profile": DIGEST_PROFILE,
              "source_revision": args.source_revision, "probe_sha256": hashlib.sha256(Path(args.probe).read_bytes()).hexdigest(),
              "seed": args.seed, "attempted": len(cases), "failed": sum(r["status"] == "FAIL" for r in rows),
              "assertions": sum(r["assertions"] for r in rows), "cases": rows,
              "status": "FAIL" if result.returncode or any(r["status"] == "FAIL" for r in rows) else "PASS",
              "not_proven": ["PostgreSQL transaction authority", "real filesystem isolation", "full G04/G05/G06", "128 real control capacity"],
              "reproduce": f"python3 verification/algorithm_check.py --probe {args.probe} --source-revision {args.source_revision} --output {args.output} --seed {args.seed} --scheduler-samples {args.scheduler_samples} --digest-profile {DIGEST_PROFILE}"}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("status", "attempted", "failed", "assertions")}))


def valid_topology(tasks, order):
    # Multiple topological orders are legal; compare facts, not one algorithm's
    # tie-breaking sequence, after independently proving the DAG itself valid.
    dag_order(tasks)
    if len(order) != len(tasks) or set(order) != {t["task_id"] for t in tasks}:
        return False
    positions = {task: index for index, task in enumerate(order)}
    return all(positions[dep] < positions[task["task_id"]] for task in tasks for dep in task.get("depends_on", []))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--seed", type=int, default=20261009)
    parser.add_argument("--scheduler-samples", type=int, default=40)
    parser.add_argument("--digest-profile", choices=["task-v1-flow-version-included", "task-v2-flow-version-external"], default=DIGEST_PROFILE)
    args = parser.parse_args()
    DIGEST_PROFILE = args.digest_profile
    run(args)
