#!/usr/bin/env python3
"""Register a finite independent campaign while paused; no lease, Worker or model launch.

Consumes already reviewed/pinned DSH Worker, resource and model-route inputs.
The generated artifact workload is a prequalification fixture; choose a real
sustained workload before the production campaign. No success is predeclared.
"""
from __future__ import annotations
import argparse
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "verification"))


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


C = module("campaign_prepare", Path(__file__).with_name("concurrency-readiness.py"))
A = module("campaign_fixture", ROOT / "verification/algorithm_check.py")
V = module("campaign_oracle", ROOT / "verification/fixtures/concurrency_verifier.py")


def prepare(plan, resource_reference, route_reference, output):
    C.validate(plan); C.isolated_server(plan)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    client = C.Client(plan, output)
    project, campaign = plan["project_id"], plan["campaign_id"]
    state = C.snapshot(client, project)
    C.require(state["project"]["paused"] and not state["tasks"] and not state["attempts"], "empty paused dedicated project required")
    resource = C.read_json(C.pin(resource_reference))
    route = C.read_json(C.pin(route_reference))
    C.require(route["id"] == plan["model_route_id"] and resource.get("physical_limits", {}).get("required"), "reviewed physical resource and exact model route required")
    workers = [C.worker_config(ref) for ref in plan["worker_configs"]]
    C.require(workers and sum(w["max_active_attempts"] for w in workers) >= plan["active_limit"], "reviewed Worker fleet must cover selected active limit")
    C.require(all(w["project_id"] == project and C.origin(w["control_url"]) == C.origin(plan["api_url"])
        and w.get("managed_dsh") for w in workers), "project-scoped managed DSH Worker templates required")
    for w in workers:
        for reference in w["profile"]["artifact_pins"]: C.pin(reference)
    profile = {**workers[0]["profile"], "kind": "DSH_MANAGED", "native_mode": workers[0]["managed_dsh"]}
    C.require(all(w["profile"] == workers[0]["profile"] and w["managed_dsh"] == workers[0]["managed_dsh"] for w in workers), "one immutable shared DSH profile per campaign required")
    mode_path = Path(profile["native_mode"]["mode_manifest"])
    catalog_path = mode_path.parent / "agent-roles.json"
    catalog, catalog_hash = C.read_json(catalog_path), C.digest(catalog_path)
    C.require(catalog["project_id"] == project and catalog["positions"] == plan["context_count"], "matching project roster and persistent context count required")
    pins = {p["path"]: p["sha256"] for p in profile["artifact_pins"]}
    C.require(pins.get(str(catalog_path)) == catalog_hash, "roster is outside pinned native profile")
    command = lambda method, path, body, key: client.request(method, "/api/v1" + path, body, campaign + "-" + key)
    document = lambda collection, identity, value: command("POST", f"/projects/{project}/documents/{collection}",
        {"id": identity, "value": value}, collection + "-" + identity)
    roles = catalog["roster"]
    # Teams and owner territories are declared from the supplied roster, never
    # a fixed customer project or an inferred runtime agent count.
    teams = sorted({r["owner_team_id"] for r in roles})
    for team in teams:
        command("POST", f"/projects/{project}/teams", {"project_id": project, "team_id": team,
            "parent_team_id": None, "name": team, "paused": False, "revision": 0}, "team-" + team)
    owners = sorted({(r["owner_id"], r["owner_team_id"]) for r in roles})
    C.require(len({o for o, _ in owners}) == len(owners), "one unambiguous team root per fixture Owner required")
    for owner, team in owners:
        if owner != team:
            command("POST", f"/projects/{project}/teams", {"project_id": project, "team_id": owner,
                "parent_team_id": team, "name": owner, "paused": False, "revision": 0}, "owner-node-" + owner)
        command("POST", f"/projects/{project}/owners", {"id": owner,
            "value": {"owner_id": owner, "root_team_id": team, "include": ["outputs/"], "exclude": []}}, "owner-" + owner)
    requirement = command("POST", f"/projects/{project}/requirements", {"project_id": project,
        "requirement_id": "R01", "title": "Independent native session workload", "source_anchor": "campaign#R01",
        "outcome": "Produce exact finite artifacts with real pinned DSH execution", "scope": "Campaign artifact protocol only",
        "acceptance": ["Independent author, consumer and oracle receipts; real session continuity measured separately"],
        "priority": 1, "weight": 1, "deferred_reason": None, "revision": 0}, "requirement")
    meaning = A.requirement_digest(requirement)
    for collection, identity, value in [("executor_profiles", profile["id"], profile),
            ("resource_profiles", resource["id"], resource), ("model_routes", route["id"], route)]:
        document(collection, identity, value)
    # Explicit finite policy scopes. Physical per-attempt limits remain enforced
    # by the supplied resource profile and delegated Worker, not these counters.
    request = resource.get("campaign_root_resources")
    C.require(isinstance(request, dict) and request.get("active_slot") == 1
        and request.get("coding_slot", 0) >= 1 and request.get("memory_bytes", 0) > 0, "complete reviewed campaign_root_resources required")
    dimensions = ("active_slot", "coding_slot", "cpu_units", "memory_bytes", "build_permit", "gpu_permit", "provider_inflight")
    C.require(set(request) == set(dimensions) and all(type(v) is int and v >= 0 for v in request.values()), "exact nonnegative resource vector required")
    child_policy = resource.get("native_child_policy", {})
    C.require(not child_policy.get("enabled"), "root-session campaign requires separate child qualification; child pool must be disabled")
    scopes = [("campaign-global", None, None, None, plan["active_limit"]), ("campaign-project", project, None, None, plan["active_limit"])]
    scopes += [("campaign-team-" + t, project, t, None, plan["active_limit"]) for t in teams]
    scopes += [("campaign-worker-" + w["worker_id"], None, None, w["worker_id"], w["max_active_attempts"]) for w in workers]
    for scope, project_scope, team, worker, n in scopes:
        command("POST", "/resource-policies", {"policy": {"scope_id": scope, "parent_scope_id": None,
            "project_id": project_scope, "team_id": team, "worker_id": worker, "limits": {d: request[d] * n for d in dimensions},
            "paused": False, "revision": 0}}, "scope-" + scope)
    plan["worker_scopes"] = {w["worker_id"]: "campaign-worker-" + w["worker_id"] for w in workers}
    slots = [w["worker_id"] for w in workers for _ in range(w["max_active_attempts"])]
    task_ids = [t for stage in plan["stages"] for t in stage["task_ids"]]
    case = A.make_compile(len(task_ids)); flow, context = case["flow"], case["context"]
    flow.update(project_id=project)
    context.update(owners=[{"owner_id": o, "root_team_id": t, "include": ["outputs/"], "exclude": []} for o, t in owners],
        current_inputs={}, requirement_semantic_digests={"R01": meaning},
        requirements=[{"requirement_id": "R01", "source_document": "campaign", "anchor": "R01",
            "acceptance": "\n".join(requirement["acceptance"]), "priority": 1, "deferred_reason": None}])
    old_specs = list(context["task_specs"].values()); context["task_specs"] = {}
    plan["task_workers"] = {}
    for stage in plan["stages"]:
        for i, identity in enumerate(stage["task_ids"]): plan["task_workers"][identity] = slots[i]
    base = C.read_json(C.pin(plan["server_identity"], private=True), private=True)
    import subprocess
    head = subprocess.check_output(["git", "-C", state["project"]["root_path"], "rev-parse", "refs/heads/main"], text=True).strip()
    context["source_revision"] = head
    now = datetime.now(timezone.utc); deadline = now + timedelta(hours=4)
    verifier = ROOT / "verification/fixtures/concurrency_verifier.py"
    python = Path("/usr/bin/python3").resolve()
    imported = []
    for index, task in enumerate(flow["tasks"]):
        identity, role = task_ids[index], roles[index]
        context_id = plan["contexts"][index]["context_id"]
        logical_path = "agent-contexts/" + context_id + ".json"
        seed = command("POST", f"/projects/{project}/artifacts", {"content_utf8": json.dumps({
            "schema_version": "forgeflow.agent-context-seed.v1", "project_id": project, "context_id": context_id,
            "position_id": role["position_id"], "history": [], "instruction": "Keep this logical context independent; write only the declared task artifact."}),
            "kind": "AGENT_CONTEXT_INPUT"}, "seed-" + context_id)
        seed_ref = {k: seed[k] for k in ("artifact_id", "sha256")}
        manifest_text = json.dumps({"files": [], "mandatory_paths": [logical_path],
            "artifact_inputs": [{"logical_path": logical_path, "artifact": seed_ref}]}, separators=(",", ":"))
        manifest = command("POST", f"/projects/{project}/artifacts", {"content_utf8": manifest_text, "kind": "CONTEXT_MANIFEST"}, "manifest-" + context_id)
        document("input_snapshots", logical_path, {"path": logical_path, "relative_path": logical_path, "sha256": seed["sha256"], "artifact": seed_ref, "source_kind": "CONTROLLED_ARTIFACT"})
        context["current_inputs"][logical_path] = seed["sha256"]
        spec = old_specs[index]
        plan_id, output_path = "verify-" + identity, "outputs/" + identity + ".json"
        spec.update(outcome="Exact native-produced finite campaign artifact", inputs=[{"path": logical_path, "sha256": seed["sha256"], "producer_task_id": None}], mandatory_paths=[logical_path], dependency_refs=[],
            execution_profile=profile["id"], verification_plan=plan_id, verification_case_count=8,
            design_anchors=["campaign#R01", f"forgeflow:native-root:v1:{role['position_id']}:{catalog_hash}"],
            requirement_digest_refs={"R01": meaning}, not_proven=["G20", "Production workload representativeness"])
        task.update(project_id=project, task_id=identity, owner_id=role["owner_id"], team_id=role["owner_team_id"],
            read_set=[logical_path], write_set=[output_path], dependencies=[], resource_request=copy.deepcopy(request))
        A.refresh_digest(task, spec); context["task_specs"][identity] = spec
        n = index + 100
        prompt = command("POST", f"/projects/{project}/artifacts", {"content_utf8":
            f"Execute the finite campaign task {identity}. Compute the sum of integers from 0 through {n}. "
            f"Write only {output_path}, containing a JSON object with exactly schema_version='forgeflow.concurrency-artifact.v1', "
            f"campaign_id='{campaign}', task_id='{identity}', value=the computed integer. Do not claim concurrency or G20. "
            "Use only admitted tools and model route. Stop when the artifact is complete.", "kind": "PROMPT"}, "prompt-" + identity)
        saved_context = document("agent_contexts", context_id, {"schema_version": "forgeflow.agent-context.v1", "project_id": project,
            "context_id": context_id, "position_id": role["position_id"], "model_route_id": route["id"],
            "input_manifest_ref": {k: manifest[k] for k in ("artifact_id", "sha256")},
            "prompt_ref": {k: prompt[k] for k in ("artifact_id", "sha256")}, "history_refs": []})
        plan["contexts"][index]["revision"] = saved_context["revision"]
        commands = [{"role": role_name, "program": str(python), "args": ["-I", "-B", str(verifier)],
            "env": {"FORGEFLOW_VERIFICATION_ROLE": role_name, "FORGEFLOW_CAMPAIGN_ID": campaign,
                "FORGEFLOW_TASK_ID": identity, "FORGEFLOW_SUM_N": str(n)}, "executable_hash": C.digest(python),
            "bound_inputs": [{"path": str(verifier), "sha256": C.digest(verifier)}], "report_path": role_name + ".json",
            "expected_cases": [{"name": name, "kind": kind} for name, kind in V.CASES[role_name]], "timeout_seconds": 30}
            for role_name in ("author", "consumer", "independent")]
        verification = {"plan_id": plan_id, "task_revision": 1, "contract_version": "forgeflow.concurrency-artifact.v1",
            "input_hash": task["input_digest"], "environment_profile": "PINNED_NATIVE_FIXTURE", "oracle_id": V.ORACLE,
            "verifier_id": "independent-concurrency-oracle", "author_id": "native-campaign-author", "commands": commands}
        document("verification_plans", plan_id, verification)
        # Financial coverage must be supplied and independently verified. This
        # tool preserves the actual profile verdict rather than upgrading it.
        enforcement = resource.get("campaign_enforcement")
        C.require(isinstance(enforcement, dict), "reviewed campaign_enforcement required")
        task["envelope"] = {"schema_version": "forgeflow.execution.v1", "operation_id": "template-" + identity,
            "project_id": project, "task_id": identity, "task_revision": 1, "attempt_id": "template-" + identity,
            "lease_id": "template-" + identity, "generation": 1, "worker_id": plan["task_workers"][identity],
            "workspace_root": state["project"]["root_path"], "base_sha": head,
            "context_manifest": {"artifact_id": manifest["artifact_id"], "sha256": manifest["sha256"], "mandatory_paths": [],
                "rendered_utf8_bytes": len(manifest_text.encode()) + 4096, "token_estimate": None, "tokenizer_id": None},
            "write_set": task["write_set"], "prompt_artifact": {"artifact_id": prompt["artifact_id"], "sha256": prompt["sha256"]},
            "model_route_id": route["id"], "executor_profile_id": profile["id"], "resource_profile_id": resource["id"],
            "verification_plan_id": plan_id, "allowed_effects": ["READ_WORKSPACE", "WRITE_DECLARED_PATHS", "REQUEST_APPROVED_MODEL", "RUN_APPROVED_COMMANDS"],
            "issued_at": now.isoformat(), "expires_at": (now + timedelta(seconds=30)).isoformat(), "deadline_at": deadline.isoformat(),
            "artifact_prefix": str(Path(plan["data_root"]) / "artifacts" / identity), "secret_refs": [], "idempotency_key": "template-" + identity,
            "trace_id": campaign + "-" + identity, "enforcement": enforcement, "session_purpose": "EXECUTION",
            "max_model_requests": plan["max_model_requests"] // len(task_ids), "resume_session_id": None, "command": None}
        source_card = {"task_id": identity, "role_id": role["position_id"], "owner_id": role["owner_id"]}
        encoded = json.dumps(source_card, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
        import hashlib
        imported.append((identity, {"schema_version": "forgeflow.planning.card.v1", "planning_only": True,
            "project_id": project, "task_id": identity, "catalog_id": "project-plan", "source_revision": head,
            "task": copy.deepcopy(task), "spec": spec, "metadata": {"role_id": role["position_id"],
                "source_card": source_card, "source_card_sha256": hashlib.sha256(encoded).hexdigest()}}))
    requirement_fields = ("project_id", "requirement_id", "title", "source_anchor", "outcome", "scope", "acceptance", "priority", "weight", "deferred_reason", "revision")
    import hashlib
    requirement_source = hashlib.sha256(json.dumps([{k: requirement[k] for k in requirement_fields}],
        ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    planning_cards = []
    for _, record in imported:
        planning_task = copy.deepcopy(record["task"])
        planning_task.update(state="NEEDS_REVIEW", envelope=None)
        planning_cards.append({"task": planning_task, "spec": record["spec"], "metadata": record["metadata"]})
    planning_catalog = {"schema_version": "forgeflow.planning.catalog.v1", "catalog_id": "project-plan",
        "source_revision": requirement_source, "expected_card_count": len(task_ids), "expected_role_count": len(roles),
        "expected_edge_count": 0, "parents": [], "cards": planning_cards,
        "roster": [{"agent_id": r["position_id"], "owner_id": r["owner_id"], "team_id": r["owner_team_id"],
            "state": "PLANNED", "runtime_pid": None, "lease_id": None,
            "parent_agent_id": r.get("organizational_parent_position_id")} for r in roles],
        "metadata": {"development_entrypoint": "CANONICAL_CAMPAIGN_API"}}
    document("planning_catalogs", "project-plan", planning_catalog)
    document("delivery_settings", "default", {"planning_catalog_id": "project-plan", "expected_positions": len(roles),
        "expected_card_count": len(task_ids), "context_count": plan["context_count"], "active_limit": plan["active_limit"], "model_display": plan["model"], "source_refs": {}})
    C.write_json(output / "flow-proposal.json", {"flow": flow, "context": context})
    saved = command("POST", f"/projects/{project}/flow-revisions", {"flow": flow, "context": context}, "flow")
    committed = command("POST", f"/flows/{project}:1/commit", {"expected_revision": saved["revision"]}, "commit")
    C.require(committed["state"] == "COMMITTED" and len(committed["tasks"]) == len(task_ids), "finite Flow commit mismatch")
    C.write_json(output / "campaign-prepared.json", plan)
    report = {"status": "PREPARED_PAUSED_NO_DISPATCH", "project_id": project, "tasks": len(task_ids),
        "positions": len(roles), "persistent_contexts": plan["context_count"], "active_limit": plan["active_limit"], "flow_revision": 1, "models_started": 0, "workers_started": 0,
        "g20": "NOT_RUN", "workload_scope": "Artifact protocol fixture; sustained production qualification requires representative workload"}
    C.write_json(output / "report.json", report)
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", required=True, type=Path)
    p.add_argument("--resource-profile", required=True, type=Path)
    p.add_argument("--resource-profile-sha256", required=True)
    p.add_argument("--model-route", required=True, type=Path)
    p.add_argument("--model-route-sha256", required=True)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    try:
        result = prepare(C.read_json(a.manifest), {"path": str(a.resource_profile.absolute()), "sha256": a.resource_profile_sha256},
            {"path": str(a.model_route.absolute()), "sha256": a.model_route_sha256}, a.output)
        print(json.dumps(result)); return 0
    except Exception as error:
        result = {"status": "BLOCKED", "error_type": type(error).__name__,
            "reason": str(error) if isinstance(error, C.Blocked) else "Private preparation evidence retained", "g20": "NOT_RUN"}
        if a.output.is_dir() and not (a.output / "blocked.json").exists(): C.write_json(a.output / "blocked.json", result)
        print(json.dumps(result)); return 2


if __name__ == "__main__":
    sys.exit(main())
