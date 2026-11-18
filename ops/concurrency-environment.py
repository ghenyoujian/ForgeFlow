#!/usr/bin/env python3
"""Create/stop a private concurrency Core and a fresh database. Never starts authors."""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import time
import urllib.parse
import uuid

SPEC = importlib.util.spec_from_file_location("campaign", Path(__file__).with_name("concurrency-readiness.py"))
C = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(C)


def postgres_environment(url, psql):
    u = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qs(u.query)
    host = query.get("host", [u.hostname or "localhost"])[0]
    C.require(host.startswith("/") or host in ("localhost", "127.0.0.1", "::1"), "local PostgreSQL required")
    env = {"PATH": "/usr/bin:/bin", "PGHOST": host, "PGPORT": str(u.port or 5432),
        "PGUSER": urllib.parse.unquote(u.username or ""), "PGDATABASE": "postgres", "PGCONNECT_TIMEOUT": "5"}
    if u.password: env["PGPASSWORD"] = urllib.parse.unquote(u.password)
    library = Path(psql).resolve().parents[3] / "x86_64-linux-gnu"
    if library.is_dir(): env["LD_LIBRARY_PATH"] = str(library)
    return u, env


def ctl(psql, env, sql):
    result = subprocess.run([str(psql), "-X", "-w", "-v", "ON_ERROR_STOP=1", "-Atc", sql],
        env=env, capture_output=True, timeout=30)
    C.require(result.returncode == 0, "PostgreSQL operation failed; no private values printed")
    return result.stdout.decode().strip()


def create(a):
    server = C.pin({"path": str(a.server.absolute()), "sha256": a.server_sha256})
    root = a.root.absolute()
    C.require(not root.exists() and not str(root).startswith("/mnt/"), "fresh Linux private directory required")
    C.require(C.ID.fullmatch(a.project_id), "valid isolated project ID required")
    template = C.read_json(a.postgres_admin_env, private=True)
    u, pg_env = postgres_environment(template["DATABASE_URL"], a.psql)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    database = "ff_concurrency_" + uuid.uuid4().hex[:20]
    ctl(a.psql, pg_env, 'CREATE DATABASE "' + database + '"')
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0)); port = listener.getsockname()[1]
    data_root = root / "data"; data_root.mkdir(mode=0o700)
    owner, worker = secrets.token_hex(32), secrets.token_hex(32)
    values = {"DATABASE_URL": urllib.parse.urlunsplit(u._replace(path="/" + database)),
        "FORGEFLOW_BIND": f"127.0.0.1:{port}", "FORGEFLOW_DATA_ROOT": str(data_root),
        "FORGEFLOW_CONSOLE_DIR": str(a.console.absolute()), "FORGEFLOW_OWNER_TOKEN": owner,
        "FORGEFLOW_WORKER_TOKEN": worker, "FORGEFLOW_OWNER_PASSWORD": secrets.token_hex(24), "RUST_LOG": "warn"}
    if a.gateway_config:
        values["FORGEFLOW_GATEWAY_CONFIG"] = str(a.gateway_config.resolve(strict=True))
    C.write_json(root / "runtime-env.json", values)
    C.write_json(root / "owner.json", {"owner_token": owner})
    C.write_json(root / "worker-env.json", {"FORGEFLOW_WORKER_TOKEN": worker, "RUST_LOG": "warn"})
    safe_env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(Path.home()), "LANG": "C.UTF-8", **values}
    with (root / "core.log").open("xb") as log:
        process = subprocess.Popen([str(server)], env=safe_env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    # Preserve cleanup identity immediately, even when startup fails.
    identity = C.fingerprint(process.pid)
    C.require(identity, "created Core exited before identity capture")
    C.write_json(root / "server-identity.json", identity)
    state = {"schema_version": "forgeflow.concurrency-environment.v1", "database": database,
        "root": str(root), "project_id": a.project_id, "api_url": f"http://127.0.0.1:{port}",
        "data_root": str(data_root), "server_binary": {"path": str(server), "sha256": a.server_sha256},
        "server_identity": {"path": str(root / "server-identity.json"), "sha256": C.digest(root / "server-identity.json")},
        "owner_credential": {"path": str(root / "owner.json"), "sha256": C.digest(root / "owner.json")},
        "models_started": 0, "workers_started": 0, "main_database_modified": False}
    C.write_json(root / "environment.json", state)
    client = C.Client(state)
    start = time.monotonic()
    try:
        while True:
            C.require(process.poll() is None and time.monotonic() - start < 30, "private Core failed startup; see private core.log")
            try:
                if client.request("GET", "/healthz").get("status") == "ok": break
            except (OSError, ValueError): pass
            time.sleep(.1)
        C.isolated_server(state)
        seed = root / "seed"; seed.mkdir()
        def git(*args):
            result = subprocess.run(["/usr/bin/git", "-C", str(seed), "-c", "core.hooksPath=/dev/null",
                "-c", "commit.gpgsign=false", *args], env={"PATH": "/usr/bin:/bin", "HOME": str(root),
                    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}, capture_output=True, timeout=15)
            C.require(result.returncode == 0, "private Git fixture creation failed")
        git("init", "--initial-branch=main")
        (seed / "README.md").write_text("Independent ForgeFlow real-session concurrency fixture. No customer project inputs.\n")
        outputs = seed / "outputs"; outputs.mkdir()
        campaign = C.template(a.project_id, data_root, a.active_limit, a.contexts)
        for stage in campaign["stages"]:
            for identity in stage["task_ids"]: (outputs / (identity + ".json")).write_text("{}\n")
        git("add", "."); git("-c", "user.name=ForgeFlow qualification", "-c", "user.email=qualification@localhost", "commit", "-m", "Independent concurrency fixture")
        project = {"project_id": a.project_id, "name": "Independent real DSH concurrency campaign",
            "root_path": str(seed), "authority_mode": "MANAGED", "data_origin": "NATIVE",
            "goal": "Measure real native sessions, resources, usage and lawful stop", "technology_stack": [],
            "timezone": "UTC", "paused": True, "archived": False, "revision": 0}
        created = client.request("POST", "/api/v1/projects", project, key="create-" + a.project_id)
        C.require(created["paused"] and created["project_id"] == a.project_id, "private project creation mismatch")
        campaign.update({k: state[k] for k in ("api_url", "owner_credential", "server_identity", "server_binary")})
        C.write_json(root / "campaign-template.json", campaign)
        report = {"status": "ISOLATED_CORE_READY", "api_url": state["api_url"], "database": database,
            "project_id": a.project_id, "root": str(root), "models_started": 0, "workers_started": 0,
            "g20": "NOT_RUN", "production_data_mutated": False}
        C.write_json(root / "creation-receipt.json", report)
        return report
    except Exception:
        current = C.fingerprint(process.pid)
        if current and current["start_ticks"] == identity["start_ticks"]:
            os.kill(process.pid, signal.SIGTERM)
            try: process.wait(10)
            except subprocess.TimeoutExpired: pass
        raise


def stop(a):
    state = C.read_json(a.environment, private=True)
    C.require(state.get("schema_version") == "forgeflow.concurrency-environment.v1", "environment receipt required")
    current = C.isolated_server(state)
    client = C.Client(state)
    project = C.snapshot(client, state["project_id"])
    C.require(not [x for x in project["attempts"] if x["state"] not in C.TERMINAL], "drain authors before stopping Core")
    spec = importlib.util.spec_from_file_location("lite_stop", Path(__file__).with_name("lite.py"))
    lite = importlib.util.module_from_spec(spec); spec.loader.exec_module(lite)
    fd = lite.open_pidfd(current["pid"])
    try:
        latest = C.fingerprint(current["pid"])
        C.require(latest and latest["start_ticks"] == current["start_ticks"], "Core PID reused")
        lite.send_pidfd_signal(fd, signal.SIGTERM)
    finally: os.close(fd)
    start = time.monotonic()
    while C.fingerprint(current["pid"]):
        C.require(time.monotonic() - start < 15, "Core exit unconfirmed; retained evidence")
        time.sleep(.1)
    result = {"status": "OWNED_CORE_STOPPED", "database_preserved": state["database"], "models_started": 0}
    destination = C.pin(state["control_unit_pin"], private=True).parent if state.get("control_unit") else Path(state["root"])
    target = destination / "stop-receipt.json"
    if target.exists(): target = destination / f"stop-receipt-{current['pid']}-{current['start_ticks']}.json"
    C.write_json(target, result)
    return result


def delegate(a):
    """Move this paused private Core onto an exact delegated installed service."""
    C.require(a.execute and a.release_dir and a.environment and a.manifest, "explicit installed release, environment, campaign and --execute required")
    state = C.read_json(a.environment, private=True); C.isolated_server(state)
    client = C.Client(state); current = C.snapshot(client, state["project_id"])
    C.require(current["project"]["paused"] and not [x for x in current["attempts"] if x["state"] not in C.TERMINAL]
        and not [x for x in current["native_model_requests"] if x["status"] != "SETTLED"]
        and not [x for k in ("allocations", "native_child_allocations", "native_child_lifecycles") for x in current[k] if x["state"] != "RELEASED"], "paused fully drained Core required before delegated handoff")
    plan = C.read_json(a.manifest)
    C.require(plan["project_id"] == state["project_id"] and C.origin(plan["api_url"]) == C.origin(state["api_url"]), "handoff campaign identity mismatch")
    release = a.release_dir.resolve(strict=True)
    delivery = C.read_json(release / "delivery-manifest.json")
    def installed(relative):
        return C.pin({"path": str(release / relative), "sha256": delivery["files"][relative]["sha256"]})
    server, launcher = installed("bin/forgeflow-server"), installed("ops/run-service.py")
    root = Path(state["root"]) / "delegated-control"; root.mkdir(mode=0o700, exist_ok=False)
    values = C.read_json(Path(state["root"]) / "runtime-env.json", private=True)
    values["FORGEFLOW_CONSOLE_DIR"] = str(release / "console")
    C.write_json(root / "runtime-env.json", values)
    name = "forgeflow-control-" + uuid.uuid4().hex; unit = name + ".service"
    def quote(value):
        value = str(value)
        C.require("\n" not in value and "\r" not in value, "single-line service argument required")
        return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%') + '"'
    unit_path = root / unit
    content = "\n".join(["[Unit]", "Description=ForgeFlow isolated context campaign Core", "[Service]", "Type=simple",
        "Slice=forgeflowcontrolresources" + name.removeprefix("forgeflow-control-") + ".slice",
        "Delegate=cpu memory pids", "DelegateSubgroup=supervisor", "NoNewPrivileges=yes",
        "ExecStart=:/usr/bin/python3 " + quote(launcher) + " --release-dir " + quote(release)
            + " --runtime-env " + quote(root / "runtime-env.json") + " --verifier-cgroups --service-name " + quote(unit),
        "Restart=no", "TimeoutStopSec=30", "KillMode=mixed", "UMask=0077", ""])
    unit_path.write_text(content); unit_path.chmod(0o600)
    C.write_json(root / "handoff-intent.json", {"source_environment": {"path":str(a.environment.absolute()),"sha256":C.digest(a.environment)},
        "release": str(release), "unit_name":unit, "unit_sha256":C.digest(unit_path), "models_started":0})
    # Existing immutable PID proof and canonical drain, never a service-name kill.
    stop(a)
    def systemctl(*args):
        result = subprocess.run(["systemctl", "--user", *args], capture_output=True, text=True, timeout=40)
        C.require(result.returncode == 0, "owned delegated Core service operation failed; private intent retained")
        return result.stdout
    systemctl("link", str(unit_path)); systemctl("daemon-reload"); systemctl("start", unit)
    start = time.monotonic()
    while True:
        props = dict(line.split("=",1) for line in systemctl("show",unit,"-p","MainPID","-p","ActiveState","-p","ControlGroup","-p","Delegate").splitlines() if "=" in line)
        identity = C.fingerprint(int(props.get("MainPID",0)))
        if identity and identity["exe"] == str(server):
            try:
                if client.request("GET","/healthz").get("status") == "ok": break
            except OSError: pass
        C.require(time.monotonic()-start < 30 and props.get("ActiveState") not in ("failed","inactive"), "delegated Core startup unconfirmed; owned unit and original database retained")
        time.sleep(.1)
    C.write_json(root / "server-identity.json", identity)
    newer = {**state, "server_binary":{"path":str(server),"sha256":C.digest(server)},
        "server_identity":{"path":str(root / "server-identity.json"),"sha256":C.digest(root / "server-identity.json")},
        "control_unit":unit, "control_unit_pin":{"path":str(unit_path),"sha256":C.digest(unit_path)}}
    C.isolated_server(newer)
    C.write_json(root / "environment.json", newer)
    plan.update(server_binary=newer["server_binary"],server_identity=newer["server_identity"])
    C.write_json(root / "campaign.json", plan)
    report = {"status":"ISOLATED_DELEGATED_CORE_READY", "unit_name":unit, "api_url":state["api_url"],
        "database_preserved":state["database"], "models_started":0, "workers_started":0, "autostart_enabled":False,
        "scope":"Existing data reopened on exact installed Core with verified private verifier delegation; no workload qualification"}
    C.write_json(root / "receipt.json",report); return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("create", "stop", "delegate"))
    p.add_argument("--root", type=Path)
    p.add_argument("--project-id")
    p.add_argument("--server", type=Path)
    p.add_argument("--server-sha256")
    p.add_argument("--console", type=Path, default=Path(__file__).resolve().parents[1] / "console/dist")
    p.add_argument("--postgres-admin-env", type=Path)
    p.add_argument("--psql", type=Path)
    p.add_argument("--release-dir", type=Path)
    p.add_argument("--manifest", type=Path)
    p.add_argument("--execute", action="store_true")
    p.add_argument("--gateway-config", type=Path)
    p.add_argument("--active-limit", type=int, choices=C.STAGES, default=32)
    p.add_argument("--contexts", type=int, default=128)
    p.add_argument("--environment", type=Path)
    a = p.parse_args()
    try:
        if a.command == "create":
            C.require(all([a.root, a.project_id, a.server, a.server_sha256, a.postgres_admin_env, a.psql]), "explicit private deployment inputs required")
            result = create(a)
        elif a.command == "delegate":
            result = delegate(a)
        else:
            C.require(a.environment, "environment receipt required")
            result = stop(a)
        print(json.dumps(result)); return 0
    except Exception as error:
        print(json.dumps({"status": "BLOCKED", "error_type": type(error).__name__,
            "reason": str(error) if isinstance(error, C.Blocked) else "Private evidence retained; credentials omitted"})); return 2


if __name__ == "__main__":
    sys.exit(main())
