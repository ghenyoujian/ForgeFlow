#!/usr/bin/env python3
"""Prepare/start/stop only the reviewed delegated Worker fleet of an isolated campaign."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
import urllib.request
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("fleet_campaign", Path(__file__).with_name("concurrency-readiness.py"))
C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)
LAUNCHER = Path(__file__).with_name("run-delegated-worker.py")


def file_pin(path):
    return {"path": str(path.absolute()), "sha256": C.digest(path)}


def invoke(argv):
    result = subprocess.run(argv, capture_output=True, timeout=90)
    C.require(result.returncode == 0, "delegated Worker preparation/start failed; private evidence retained")
    return json.loads(result.stdout)


def prepare(a):
    state = C.read_json(a.environment, private=True); C.isolated_server(state)
    profile = C.read_json(a.profile, private=True); managed = C.read_json(a.managed, private=True)
    resources = C.read_json(a.resource_profile)
    C.require(resources.get("sandbox") and resources.get("physical_limits", {}).get("required"), "reviewed strong sandbox and finite physical policy required")
    C.require(a.workers * a.capacity >= a.active_limit and 1 <= a.workers <= 128 and 1 <= a.capacity <= 64, "explicit bounded Worker fleet must cover selected active limit")
    campaign_template = C.read_json(Path(state["root"]) / "campaign-template.json")
    C.require(campaign_template["active_limit"] == a.active_limit, "fleet and campaign active limits must match")
    program = C.pin({"path": str(a.worker.absolute()), "sha256": a.worker_sha256})
    root = a.output.absolute(); root.mkdir(mode=0o700, parents=True, exist_ok=False)
    config_refs, plans = [], []
    fleet_id = uuid.uuid4().hex[:12]
    for i in range(a.workers):
        worker = f"{state['project_id'][:70]}-{fleet_id}-worker-{i + 1:02d}"
        config = {"control_url": state["api_url"], "project_id": state["project_id"], "worker_id": worker,
            "data_root": str(Path(state["data_root"]) / "workers" / worker),
            "profile_ref": file_pin(a.profile), "managed_dsh_ref": file_pin(a.managed),
            "model_route_id": profile["model_route_id"], "max_active_attempts": a.capacity,
            "max_log_bytes": 1048576, "poll_seconds": 1, "secret_files": {}, "controlled_workload_programs": {},
            "sandbox": resources["sandbox"], "strict_resource_handoff": True}
        config_path = root / (worker + ".json"); C.write_json(config_path, config)
        config_refs.append(file_pin(config_path))
        plan_root = root / (worker + "-service")
        invoke([sys.executable, str(LAUNCHER), "prepare", "--kind", "worker", "--program", str(program),
            "--program-sha256", a.worker_sha256, "--config", str(config_path),
            "--env-file", str(Path(state["root"]) / "worker-env.json"), "--output", str(plan_root)])
        plans.append({"plan": file_pin(plan_root / "launch-plan.json"),
            "preparation": file_pin(plan_root / "preparation.json")})
    plan = C.read_json(Path(state["root"]) / "campaign-template.json")
    plan.update({k:state[k] for k in ("api_url","server_identity","server_binary","owner_credential")})
    plan.update(worker_configs=config_refs, model=a.model, model_route_id=profile["model_route_id"])
    C.write_json(root / "campaign-prepared-workers.json", plan)
    fleet = {"schema_version": "forgeflow.concurrency-workers.v1", "fleet_id":fleet_id, "environment": file_pin(a.environment),
        "launcher": file_pin(LAUNCHER), "worker": file_pin(program), "plans": plans,
        "campaign": file_pin(root / "campaign-prepared-workers.json"), "capacity": a.workers * a.capacity,
        "profile": file_pin(a.profile), "managed": file_pin(a.managed)}
    C.write_json(root / "fleet.json", fleet)
    return {"status": "FLEET_PREPARED_NOT_STARTED", "workers": a.workers, "capacity": fleet["capacity"],
        "worker_config_bytes": sum(Path(r["path"]).stat().st_size for r in config_refs),
        "shared_profile_bytes": a.profile.stat().st_size, "models_started": 0, "g20": "NOT_RUN"}


def unit_properties(unit):
    C.require(re.fullmatch(r"forgeflow-worker-[0-9a-f]{32}\.service", unit), "unexpected Worker service identity")
    result = subprocess.run(["systemctl", "--user", "show", unit, "-p", "MainPID", "-p", "ActiveState"],
        capture_output=True, text=True, timeout=10)
    C.require(result.returncode == 0, "Worker service status unavailable")
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def registered_worker(state, client, worker):
    # Existing read-only Worker dispatch stream validates canonical registered
    # project scope before sending its headers. PID/exec alone is not readiness.
    env = C.read_json(Path(state["root"]) / "worker-env.json", private=True)
    current = C.snapshot(client, state["project_id"])
    route = f"/api/v1/workers/{worker}/dispatch-events?project_id={state['project_id']}&after={current['revision']}"
    request = urllib.request.Request(client.base + route, headers={"Authorization": "Bearer " + env["FORGEFLOW_WORKER_TOKEN"], "Accept": "text/event-stream"})
    try:
        with client.opener.open(request, timeout=20) as response:
            return response.status == 200 and "text/event-stream" in response.headers.get("Content-Type", "")
    except urllib.error.HTTPError as error:
        if error.code in (403,404,409): return False
        raise
    except TimeoutError: return False


def operate(a):
    C.require(a.execute, "up/down requires explicit --execute")
    fleet = C.read_json(a.fleet, private=True)
    C.require(fleet["schema_version"] == "forgeflow.concurrency-workers.v1", "reviewed fleet required")
    state = C.read_json(C.pin(fleet["environment"], private=True), private=True)
    if a.environment:
        newer = C.read_json(a.environment, private=True)
        C.require(all(newer.get(k) == state.get(k) for k in ("project_id","api_url","data_root","database","owner_credential","root")),
            "Core handoff may change only the pinned server identity, not fleet project/database/auth scope")
        state = newer
    C.isolated_server(state)
    client = C.Client(state)
    current = C.snapshot(client, state["project_id"])
    C.require(current["project"]["paused"], "project must be paused before fleet operation")
    C.require(not [x for x in current["attempts"] if x["state"] not in C.TERMINAL]
        and not [r for r in current["native_model_requests"] if r["status"] != "SETTLED"], "drain unsettled attempts and models before fleet operation")
    C.require(not [r for key in ("allocations", "native_child_allocations", "native_child_lifecycles") for r in current[key] if r["state"] != "RELEASED"], "nonreleased resources block fleet operation")
    launcher = C.pin(fleet["launcher"]); C.pin(fleet["worker"])
    live_refs, identities = [], []
    for reference in fleet["plans"]:
        path = C.pin(reference["plan"], private=True)
        plan = C.read_json(path, private=True)
        preparation = C.read_json(C.pin(reference["preparation"], private=True), private=True)
        if a.command == "up":
            invoke([sys.executable, str(launcher), "start", "--plan", str(path), "--plan-sha256", reference["plan"]["sha256"],
                "--unit-sha256", preparation["unit_sha256"], "--execute"])
            start = time.monotonic()
            while True:
                props = unit_properties(plan["unit_name"])
                delegated = path.parent / "delegated-config.json"
                current_pid = C.fingerprint(int(props.get("MainPID", 0)))
                if delegated.is_file() and current_pid and current_pid["exe"] == fleet["worker"]["path"]:
                    config = C.read_json(delegated, private=True)
                    if registered_worker(state, client, config["worker_id"]): break
                C.require(time.monotonic() - start <= 120 and props["ActiveState"] not in ("failed", "inactive"), "Worker startup failed; no fallback or automatic restart")
                time.sleep(.2)
            live_refs.append(file_pin(delegated))
            identities.append({"unit_name": plan["unit_name"], **current_pid})
        else:
            props = unit_properties(plan["unit_name"])
            pid = int(props.get("MainPID", 0))
            if pid:
                identity = C.fingerprint(pid)
                C.require(identity and identity["exe"] == fleet["worker"]["path"], "Worker service binary identity changed")
                result = subprocess.run(["systemctl", "--user", "stop", plan["unit_name"]], capture_output=True, timeout=90)
                C.require(result.returncode == 0 and not C.fingerprint(pid), "owned Worker stop unconfirmed")
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    if a.command == "up":
        campaign = C.read_json(C.pin(fleet["campaign"]))
        campaign["worker_configs"] = live_refs
        C.write_json(a.output / "campaign-live-workers.json", campaign)
        C.write_json(a.output / "worker-identities.json", identities)
    result = {"status": "FLEET_UP_PROJECT_PAUSED" if a.command == "up" else "OWNED_FLEET_STOPPED",
        "workers": len(fleet["plans"]), "capacity": fleet["capacity"], "actual_native_agents_claimed": 0,
        "models_started_by_fleet_tool": 0, "g20": "NOT_RUN"}
    C.write_json(a.output / "report.json", result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("prepare", "up", "down"))
    for name in ("environment", "profile", "managed", "resource-profile", "worker", "fleet", "output"):
        p.add_argument("--" + name, type=Path, required=name == "output")
    p.add_argument("--worker-sha256")
    p.add_argument("--model")
    p.add_argument("--workers", type=int, default=2)
    p.add_argument("--capacity", type=int, default=16)
    p.add_argument("--active-limit", type=int, choices=C.STAGES, default=32)
    p.add_argument("--execute", action="store_true")
    a = p.parse_args()
    try:
        if a.command == "prepare":
            C.require(all([a.environment, a.profile, a.managed, a.resource_profile, a.worker, a.worker_sha256, a.model]), "explicit reviewed fleet inputs required")
            result = prepare(a)
        else:
            C.require(a.fleet, "reviewed fleet manifest required"); result = operate(a)
        print(json.dumps(result)); return 0
    except Exception as error:
        print(json.dumps({"status": "BLOCKED", "error_type": type(error).__name__,
            "reason": str(error) if isinstance(error, C.Blocked) else "Private fleet evidence retained", "g20": "NOT_RUN"})); return 2


if __name__ == "__main__": sys.exit(main())
