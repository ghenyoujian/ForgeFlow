#!/usr/bin/env python3
"""Prepare, inspect and run an isolated, staged REAL_DSH campaign through canonical APIs.

No direct author/model spawning, no production fallback, no SQL resource release.
Run consumes already approved finite tasks and independently configured Workers.
Preflight is read-only. A preparation PASS never earns G20.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import resource
import signal
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SCHEMA = "forgeflow.context-campaign.v1"
STAGES = (1, 4, 10, 32, 64)
TERMINAL = {"SUCCEEDED", "FAILED", "CANCELLED"}
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
ABORT = False


class Blocked(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Blocked(message)


def utc():
    return datetime.now(timezone.utc).isoformat()


def read_json(path, private=False):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 32 * 1024 * 1024, "bounded regular JSON file required")
        if private:
            require(info.st_uid == os.geteuid() and not info.st_mode & 0o077, "private file must be current-user owned mode 0600")
        def pairs(items):
            result = {}
            for key, value in items:
                require(key not in result, "duplicate JSON key")
                result[key] = value
            return result
        return json.load(stream, object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Blocked("nonfinite JSON number")))


def write_json(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n"); stream.flush(); os.fsync(stream.fileno())


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for raw in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(raw)
    return h.hexdigest()


def pin(ref, private=False):
    require(isinstance(ref, dict) and set(ref) == {"path", "sha256"}, "exact path/sha256 pin required")
    path = Path(ref["path"])
    require(path.is_absolute() and not path.is_symlink() and path.is_file()
        and SHA.fullmatch(str(ref["sha256"])) and digest(path) == ref["sha256"], "pinned file absent or changed")
    if private:
        info = path.stat()
        require(info.st_uid == os.geteuid() and not info.st_mode & 0o077, "private pin permissions differ")
    return path


def worker_config(reference):
    value = read_json(pin(reference, private=True), private=True)
    for source, target in (("profile_ref", "profile"), ("managed_dsh_ref", "managed_dsh")):
        if source in value:
            require(target not in value, "inline/shared Worker configuration conflict")
            value[target] = read_json(pin(value.pop(source), private=True), private=True)
    return value


def origin(value):
    u = urllib.parse.urlsplit(value)
    try:
        local = ipaddress.ip_address(u.hostname or "").is_loopback
    except ValueError:
        local = False
    require(local and u.scheme == "http" and u.port not in (None, 8787, 3080, 17891)
        and not u.username and not u.password and not u.query and not u.fragment
        and u.path in ("", "/"), "explicit isolated loopback API required; main/provider/Web origins refused")
    return value.rstrip("/")


def fingerprint(pid):
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
        fields = raw[raw.rfind(")") + 2:].split()
        if fields[0] in ("Z", "X"):
            return None
        return {"pid": int(pid), "start_ticks": int(fields[19]),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "exe": str(Path(f"/proc/{pid}/exe").resolve(strict=True)),
            "rss_bytes": int(fields[21]) * os.sysconf("SC_PAGE_SIZE")}
    except (OSError, ValueError, IndexError):
        return None


def validate(plan):
    require(plan.get("schema_version") == SCHEMA and plan.get("workload") == "REAL_DSH_CONTEXT_POOL", "real DSH campaign schema required")
    require(ID.fullmatch(str(plan.get("campaign_id", ""))) and ID.fullmatch(str(plan.get("project_id", ""))), "campaign/project identity required")
    origin(plan["api_url"])
    require(plan.get("qualification") == "NOT_RUN", "run manifest cannot predeclare qualification")
    limit, count = plan.get("active_limit"), plan.get("context_count")
    require(type(limit) is int and limit in STAGES and type(count) is int and 101 <= count <= 10000,
        "100+ independent contexts and an explicit 1/4/10/32/64 active limit required")
    contexts = plan.get("contexts", [])
    context_ids = [c.get("context_id") for c in contexts]
    require(len(contexts) == count and len(set(context_ids)) == count and all(ID.fullmatch(str(c)) for c in context_ids),
        "exact distinct persistent context population required")
    stages = plan["stages"]
    tiers = [n for n in STAGES if n <= limit]
    require([s.get("tier") for s in stages[:len(tiers)]] == tiers, "enabled activation tiers must be tested in order")
    ids, used_contexts = set(), set()
    for stage in stages:
        n, tier = stage["agents"], stage["tier"]
        require(type(n) is int and type(tier) is int and tier in tiers and 1 <= n <= tier <= limit
            and type(stage.get("hold_seconds")) is int and 1 <= stage["hold_seconds"] <= 3600,
            "finite activation batch within its hard active limit required")
        tasks, selected = stage["task_ids"], stage["context_ids"]
        require(len(tasks) == n and all(ID.fullmatch(str(t)) for t in tasks) and len(set(tasks)) == n
            and not ids.intersection(tasks), "fresh distinct task IDs required for every activation batch")
        require(len(selected) == n and len(set(selected)) == n and set(selected) <= set(context_ids)
            and not used_contexts.intersection(selected), "context coverage must be exact and independent across fixture batches")
        ids.update(tasks); used_contexts.update(selected)
    require(used_contexts == set(context_ids), "activation batches must cover the entire persistent context pool")
    for field in ("poll_seconds", "startup_timeout_seconds", "drain_timeout_seconds"):
        require(type(plan.get(field)) is int and 1 <= plan[field] <= 3600, "bounded timing field required: " + field)
    require(plan["poll_seconds"] <= 10, "observation interval must be at most ten seconds")
    for field in ("max_cost_usd", "max_model_requests", "memory_bytes_per_agent", "system_memory_reserve_bytes", "disk_reserve_bytes", "provider_inflight"):
        require(type(plan.get(field)) is int and plan[field] > 0, "explicit positive integer budget required: " + field)
    require(plan["provider_inflight"] >= plan["active_limit"], "provider capacity must cover requested real concurrency")
    require(plan["max_model_requests"] >= plan["context_count"], "model request budget below session denominator")
    require(isinstance(plan.get("worker_configs"), list) and plan["worker_configs"], "explicit Worker configurations required")
    require(plan.get("model") and plan.get("model_route_id"), "exact model and route required")
    root = Path(plan["data_root"])
    require(root.is_absolute() and root.exists() and root.stat().st_uid == os.geteuid()
        and not root.is_symlink(), "owned isolated data root required")
    require(not root.resolve().is_relative_to(Path.home() / ".local/state/forgeflow/control"), "main runtime subtree refused")
    return plan


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Client:
    def __init__(self, plan, output=None):
        self.base = origin(plan["api_url"])
        credential = read_json(pin(plan["owner_credential"], private=True), private=True)
        self.token = credential["owner_token"]
        require(isinstance(self.token, str) and self.token.strip(), "Owner credential missing")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.output, self.sequence, self.latencies = output, 0, []
        self.snapshot_latencies = []

    def request(self, method, path, body=None, key=None):
        require(path.startswith("/api/v1/") or path == "/healthz", "unexpected API namespace")
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/json"}
        raw = None
        if body is not None:
            require(key, "mutation requires stable idempotency identity")
            raw = json.dumps(body, allow_nan=False).encode()
            headers.update({"Content-Type": "application/json", "Idempotency-Key": key})
        request = urllib.request.Request(self.base + path, data=raw, method=method, headers=headers)
        start = time.monotonic()
        try:
            with self.opener.open(request, timeout=30) as response:
                raw = response.read(32 * 1024 * 1024 + 1)
                require(len(raw) <= 32 * 1024 * 1024 and "application/json" in response.headers.get("Content-Type", ""), "bounded JSON authority response required")
                result = json.loads(raw)
        except urllib.error.HTTPError as error:
            raw = error.read(1024 * 1024)
            try: result = json.loads(raw)
            except ValueError: result = {"unparsed_response_sha256": hashlib.sha256(raw).hexdigest()}
            if self.output:
                self.sequence += 1
                write_json(self.output / f"http-{self.sequence:06d}-failed.json", {"at":utc(),"method":method,"path":path,
                    "status":error.code,"response":result,"response_sha256":hashlib.sha256(raw).hexdigest()})
            error.forgeflow_response = result
            raise
        latency = (time.monotonic() - start) * 1000
        self.latencies.append(latency)
        if method == "GET" and path.endswith("/snapshot"): self.snapshot_latencies.append(latency)
        if self.output:
            self.sequence += 1
            write_json(self.output / f"http-{self.sequence:06d}.json",
                {"at": utc(), "method": method, "path": path, "response_sha256": hashlib.sha256(raw).hexdigest(), "response": result})
        self.last_envelope = result
        return result.get("data", result)

    def collection(self, route):
        rows, seen, cursor = [], set(), None
        while True:
            path = route + ("&" if "?" in route else "?") + "limit=500"
            if cursor: path += "&cursor=" + urllib.parse.quote(str(cursor), safe="")
            batch = self.request("GET", path)
            require(isinstance(batch, list), "bounded collection response required")
            rows.extend(batch)
            require(len(rows) <= 10000, "collection denominator exceeds bound")
            cursor = self.last_envelope.get("next_cursor")
            if not cursor: return rows
            require(cursor not in seen, "collection cursor repeated")
            seen.add(cursor)


def snapshot(client, project):
    value = client.request("GET", f"/api/v1/projects/{project}/snapshot")
    require(value.get("source") == "POSTGRESQL_AUTHORITY" and value.get("project", {}).get("project_id") == project,
        "project-scoped PostgreSQL snapshot required")
    return value


def isolated_server(plan):
    receipt = read_json(pin(plan["server_identity"], private=True), private=True)
    current = fingerprint(receipt["pid"])
    require(current and all(current.get(k) == receipt.get(k) for k in ("pid", "start_ticks", "boot_id", "exe")), "isolated server process identity changed")
    require(Path(current["exe"]).resolve() == pin(plan["server_binary"]).resolve(), "server binary differs from campaign pin")
    entries = Path(f"/proc/{current['pid']}/environ").read_bytes().split(b"\0")
    env = dict(e.split(b"=", 1) for e in entries if b"=" in e)
    require(env.get(b"FORGEFLOW_DATA_ROOT", b"").decode() == str(Path(plan["data_root"]).resolve()), "server data root differs")
    url = urllib.parse.urlsplit(env.get(b"DATABASE_URL", b"").decode())
    require(url.path.lstrip("/").startswith("ff_concurrency_") and url.path.lstrip("/") != "ff_concurrency_", "dedicated ff_concurrency_* database required")
    # Verify that this exact server owns the requested listener, not just a PID.
    inodes = set()
    for fd in Path(f"/proc/{current['pid']}/fd").iterdir():
        try:
            link = os.readlink(fd)
            if link.startswith("socket:["): inodes.add(link[8:-1])
        except OSError:
            pass
    port = urllib.parse.urlsplit(plan["api_url"]).port
    listening = False
    for name in ("tcp", "tcp6"):
        for line in Path(f"/proc/{current['pid']}/net/{name}").read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] == "0A" and int(fields[1].split(":")[1], 16) == port and fields[9] in inodes:
                listening = True
    require(listening, "pinned server does not own campaign listening socket")
    return {**current, "database": url.path.lstrip("/"), "data_root": plan["data_root"], "owns_listener": True}


def verifier_delegation(proof):
    entries = Path(f"/proc/{proof['pid']}/environ").read_bytes().split(b"\0")
    env = dict(e.split(b"=",1) for e in entries if b"=" in e)
    require(b"FORGEFLOW_VERIFIER_CGROUP_DELEGATION" in env,
        "physical verifier preparation requires delegate --release-dir before real activation")
    value = json.loads(env[b"FORGEFLOW_VERIFIER_CGROUP_DELEGATION"])
    unit, root = value.get("unit_name", ""), Path(value.get("root_path", "/"))
    require(re.fullmatch(r"forgeflow-control-[0-9a-f]{32}\.service",unit)
        and root.is_relative_to(Path("/sys/fs/cgroup")) and root.name == unit
        and not root.is_symlink() and root.resolve() == root and root.stat().st_uid == os.geteuid()
        and Path(f"/proc/{proof['pid']}/cgroup").read_text().strip() == "0::" + "/" + str(root.relative_to("/sys/fs/cgroup")) + "/supervisor"
        and not (root / "cgroup.procs").read_text().strip()
        and {"cpu","memory","pids"} <= set((root/"cgroup.controllers").read_text().split()),
        "Core verifier delegation differs from actual owned supervisor and controllers")
    return {"unit_name":unit,"root_path":str(root),"root_inode":root.stat().st_ino,"actual_supervisor_verified":True}


def hardware(plan):
    memory = dict((line.split(":")[0], int(line.split()[1]) * 1024)
        for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith(("MemTotal:", "MemAvailable:")))
    needed = plan["active_limit"] * plan["memory_bytes_per_agent"]
    require(memory["MemAvailable"] >= needed + plan.get("system_memory_reserve_bytes", 1024 ** 3), "insufficient measured available memory for selected active reservations")
    disk = os.statvfs(plan["data_root"])
    free = disk.f_bavail * disk.f_frsize
    require(free >= plan["disk_reserve_bytes"], "insufficient free disk reserve")
    nofile = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    require(nofile == resource.RLIM_INFINITY or nofile >= plan["active_limit"] * 16, "file descriptor soft limit too low")
    return {"cpu_affinity_count": len(os.sched_getaffinity(0)), "memory": memory,
        "reserved_agent_memory_bytes": needed, "free_disk_bytes": free, "nofile_soft": nofile,
        "cgroup_v2": Path("/sys/fs/cgroup/cgroup.controllers").exists(), "recorded_at": utc()}


def preflight(plan, client):
    validate(plan)
    proof = isolated_server(plan)
    host = hardware(plan)
    control_delegation = verifier_delegation(proof)
    require(host["cgroup_v2"], "cgroup v2 required")
    require(client.request("GET", "/healthz").get("database") == "postgres", "PostgreSQL health unavailable")
    workers, capacity = {}, 0
    for reference in plan["worker_configs"]:
        config = worker_config(reference)
        identifier = config["worker_id"]
        require(identifier not in workers and ID.fullmatch(identifier), "duplicate/invalid worker identity")
        require(origin(config["control_url"]) == origin(plan["api_url"]) and config["project_id"] == plan["project_id"], "Worker control/project mismatch")
        require(Path(config["data_root"]).resolve().is_relative_to(Path(plan["data_root"]).resolve()), "Worker data root escapes campaign")
        require(config.get("managed_dsh") and config.get("sandbox") and config.get("cgroup_delegation"), "managed DSH, sandbox and delegated cgroup required")
        require(config["model_route_id"] == plan["model_route_id"] and config["profile"].get("kind") != "CLAUDE_CODE_LEAF", "real DSH route required")
        for item in config["profile"]["artifact_pins"]: pin(item)
        require(config["profile"]["artifact_pins"], "nonempty runtime pin closure required")
        require(config.get("model_route_id") == config["profile"].get("model_route_id"), "Worker profile route drift")
        delegation = config["cgroup_delegation"]
        root = Path(delegation["root_path"])
        require(root.is_relative_to(Path("/sys/fs/cgroup")) and root.is_dir()
            and root.stat().st_uid == os.geteuid() and root.name == delegation["unit_name"], "owned live delegated Worker cgroup required")
        require({"cpu", "memory", "pids"} <= set((root / "cgroup.controllers").read_text().split()), "Worker cgroup controllers missing")
        require(type(config["max_active_attempts"]) is int and 1 <= config["max_active_attempts"] <= 64, "bounded per-Worker capacity required")
        workers[identifier] = config; capacity += config["max_active_attempts"]
    require(capacity >= plan["active_limit"], "combined Worker capacity below selected active limit")
    current = snapshot(client, plan["project_id"])
    require(current["project"]["paused"] and not current["project"].get("archived", False) and current["project"]["authority_mode"] == "MANAGED", "campaign must begin paused and managed")
    require(not [a for a in current["attempts"] if a["state"] not in TERMINAL], "unfinished attempts block new campaign")
    require(not [r for r in current["native_model_requests"] if r["status"] != "SETTLED"], "unknown/inflight model requests block campaign")
    tasks = {t["task_id"]: t for t in current["tasks"]}
    declared = [t for stage in plan["stages"] for t in stage["task_ids"]]
    context_rows = client.collection(f"/api/v1/projects/{plan['project_id']}/documents/agent_contexts")
    require(isinstance(context_rows, list) and len(context_rows) == plan["context_count"]
        and {c["context_id"] for c in context_rows} == {c["context_id"] for c in plan["contexts"]},
        "all independent context descriptors must be persisted in authority")
    limits = [row for row in current["resource_limits"] if row["dimension"] == "active_slot"]
    require(limits and any(row["scope_id"] == "campaign-project" and row["hard_limit"] == plan["active_limit"] for row in limits),
        "project active-slot policy must enforce the selected active limit")
    contexts_by_id = {row["context_id"]: row for row in context_rows}
    require(all(contexts_by_id[c["context_id"]]["revision"] == c.get("revision") for c in plan["contexts"]),
        "context history changed after approval; materialize current history into a newly approved task before activation")
    task_contexts = {task: context for stage in plan["stages"] for task, context in zip(stage["task_ids"], stage["context_ids"])}
    resource_profiles = {}
    for identity in declared:
        task = tasks.get(identity)
        require(task and task.get("envelope") and not task.get("dependencies"), "approved independent task envelope required")
        e = task["envelope"]
        require(task["resource_request"].get("active_slot") == 1
            and 0 < task["resource_request"].get("memory_bytes", 0) <= plan["memory_bytes_per_agent"],
            "hardware estimate cannot understate frozen per-Agent memory or active reservations")
        resource_id = e["resource_profile_id"]
        if resource_id not in resource_profiles:
            resource_profiles[resource_id] = client.request("GET", f"/api/v1/projects/{plan['project_id']}/documents/resource_profiles/{urllib.parse.quote(resource_id,safe='')}")
        resource_profile = resource_profiles[resource_id]
        require(resource_profile.get("physical_limits", {}).get("required") is True
            and resource_profile.get("native_child_policy", {}).get("enabled") is False,
            "bounded root-Agent campaign requires physical limits and disabled Native child pool")
        descriptor = contexts_by_id[task_contexts[identity]]
        require(descriptor["model_route_id"] == plan["model_route_id"]
            and all(e["context_manifest"][key] == descriptor["input_manifest_ref"][key] for key in ("artifact_id", "sha256"))
            and e["prompt_artifact"] == descriptor["prompt_ref"], "task context/prompt binding differs from persistent descriptor")
        worker = plan.get("task_workers", {}).get(identity, e["worker_id"])
        require(worker in workers and e["model_route_id"] == plan["model_route_id"], "task Worker/route mismatch")
        require(e["executor_profile_id"] == workers[worker]["profile"]["id"], "task executor differs from selected Worker")
        require(identity in plan.get("task_workers", {}) or e["worker_id"] == worker, "explicit Worker assignment required")
        require(e["enforcement"].get("model_budget_mode") == "gateway_enforced"
            and e["enforcement"].get("all_model_routes_covered") is True, "hard gateway coverage required")
        require(e.get("max_model_requests", 0) > 0 and e.get("command") is None, "actual finite DSH task required, no controlled command substitute")
        result = client.request("POST", f"/api/v1/projects/{plan['project_id']}/tasks/{identity}/admission-checks", {}, key=plan["campaign_id"] + "-check-" + identity)
        # Paused project is intentional; other admission blockers remain material.
        blockers = result.get("blockers", result.get("blocking_reasons", []))
        require(not [b for b in blockers if (b.get("code") if isinstance(b, dict) else str(b).split(":")[0]) not in {"PROJECT_PAUSED", "PROJECT_NOT_ADMISSIBLE"}], "task admission preflight has unresolved blockers")
    for stage in plan["stages"]:
        assigned = {}
        for identity in stage["task_ids"]:
            worker = plan.get("task_workers", {}).get(identity, tasks[identity]["envelope"]["worker_id"])
            assigned[worker] = assigned.get(worker, 0) + 1
        require(all(count <= workers[worker]["max_active_attempts"] for worker, count in assigned.items()), "stage assignment exceeds per-Worker concurrency")
    require(sum(tasks[t]["envelope"]["max_model_requests"] for t in declared) <= plan["max_model_requests"], "frozen request reservations exceed campaign budget")
    quota = read_json(pin(plan["quota_receipt"]))
    require(quota.get("schema_version") == "forgeflow.provider-quota.v1" and quota.get("model") == plan["model"]
        and quota.get("model_route_id") == plan["model_route_id"] and quota.get("provider_inflight", 0) >= plan["active_limit"]
        and quota.get("available_usd", 0) >= plan["max_cost_usd"], "provider quota/model/budget receipt insufficient")
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(quota["observed_at"])).total_seconds()
    require(0 <= age <= 3600, "quota receipt must be fresh within one hour")
    require(quota.get("source_response_sha256") and SHA.fullmatch(quota["source_response_sha256"]), "original provider response digest required")
    require(digest(pin(quota["source_response"])) == quota["source_response_sha256"], "provider quota original response changed")
    return {"status": "READY_FOR_STAGED_EXECUTION", "server": proof, "hardware": host,
        "verifier_delegation": control_delegation, "worker_capacity": capacity, "active_limit": plan["active_limit"], "persistent_contexts": plan["context_count"], "tasks": len(declared), "new_model_calls": 0, "g20": "NOT_RUN"}


def physical_author(attempt, workers):
    config = workers[attempt["worker_id"]]
    journal = Path(config["data_root"]) / "attempts" / attempt["attempt_id"]
    try:
        receipt = read_json(journal / "launch-receipt.json")
        intent, process = receipt["intent"], receipt["process"]
        require(intent["attempt_id"] == attempt["attempt_id"] and process["attempt_id"] == attempt["attempt_id"]
            and intent["generation"] == attempt["generation"] and intent["worker_id"] == attempt["worker_id"], "launch receipt identity mismatch")
        actual = fingerprint(process["pid"])
        if not actual or actual["start_ticks"] != process["start_ticks"] or actual["boot_id"] != process["boot_id"]:
            return None
        fence = read_json(journal / "cgroup-fence.json")
        leaf = Path(fence["leaf_path"])
        require(fence["attempt_id"] == attempt["attempt_id"] and fence["generation"] == attempt["generation"]
            and leaf.is_relative_to(Path("/sys/fs/cgroup")) and leaf.stat().st_ino == fence["leaf_inode"], "physical fence mismatch")
        membership = Path(f"/proc/{actual['pid']}/cgroup").read_text().strip().split(":", 2)[-1]
        require(Path("/sys/fs/cgroup") / membership.lstrip("/") == leaf, "author is outside its admitted cgroup")
        values = {name: (leaf / name).read_text().strip() for name in ("memory.max", "pids.max", "cpu.max")}
        require(values["memory.max"] == str(fence["limits"]["memory_max_bytes"])
            and values["pids.max"] == str(fence["limits"]["pids_max"])
            and values["cpu.max"] == f"{fence['limits']['cpu_quota_us']} {fence['limits']['cpu_period_us']}", "physical limit readback differs from frozen fence")
        return {"attempt_id": attempt["attempt_id"], **actual, "cgroup": str(leaf), "limits": values}
    except FileNotFoundError:
        return None


def durable_author(attempt, workers):
    config = workers.get(attempt["worker_id"])
    if not config: return None
    journal = Path(config["data_root"]) / "attempts" / attempt["attempt_id"]
    try:
        receipt = read_json(journal / "launch-receipt.json")
        fence = read_json(journal / "cgroup-fence.json")
        intent, process = receipt["intent"], receipt["process"]
        require(intent["attempt_id"] == process["attempt_id"] == fence["attempt_id"] == attempt["attempt_id"]
            and intent["generation"] == fence["generation"] == attempt["generation"]
            and intent["worker_id"] == attempt["worker_id"] and process["boot_id"] == intent["boot_id"] == fence["boot_id"]
            and process["pid"] > 0 and process["start_ticks"] > 0
            and Path(fence["leaf_path"]).is_relative_to(Path(config["cgroup_delegation"]["root_path"]))
            and fence["limits"]["memory_max_bytes"] > 0, "historical launch and physical fence identity mismatch")
        return {"attempt_id": attempt["attempt_id"], **process,
            "launch_receipt_sha256": digest(journal / "launch-receipt.json"), "physical_fence_sha256": digest(journal / "cgroup-fence.json")}
    except FileNotFoundError:
        return None


def observation(current, task_ids, workers, model):
    attempts = [a for a in current["attempts"] if a["task_id"] in task_ids]
    require(len({a["attempt_id"] for a in attempts}) == len(attempts), "duplicate attempt identity")
    require(len({a["task_id"] for a in attempts}) == len(attempts), "duplicate task execution")
    require(not [a for a in attempts if a["state"] in {"FAILED", "RECOVERY_REQUIRED"}], "failed/recovery attempt during campaign")
    proofs = {}
    for a in attempts:
        if a["state"] == "RUNNING":
            proof = physical_author(a, workers)
            if proof: proofs[a["attempt_id"]] = proof
    require(len({(p["pid"], p.get("start_ticks")) for p in proofs.values()}) == len(proofs), "distinct root attempts share a physical process")
    lifecycles = [l for l in current["native_child_lifecycles"] if l["attempt_id"] in proofs
        and l["state"] == "HELD" and not l["revoked"] and l.get("disposed_at") is None
        and l.get("process_stopped_at") is None and l.get("released_at") is None]
    # This campaign qualifies distinct root DSH sessions. Children, configured
    # positions, allocations and queued tasks cannot inflate the denominator.
    roots = [l for l in lifecycles if l.get("parent_session_id") is None]
    requests = [r for r in current["native_model_requests"] if r["attempt_id"] in {a["attempt_id"] for a in attempts}]
    require(not [r for r in requests if r["status"] == "QUARANTINED" or r["model"] != model], "unknown usage or wrong model")
    requested_sessions = {(r["attempt_id"], r["native_session_id"]) for r in requests
        if r.get("purpose") == "conversation" and r.get("dispatched_at")
        and r.get("status") == "SETTLED" and r.get("usage_complete") is True
        and (r.get("transport") or {}).get("outcome") == "RESPONSE_BODY_COMPLETED"
        and 200 <= ((r.get("transport") or {}).get("upstream_status") or 0) < 300
        and (r.get("transport") or {}).get("received_bytes", 0) > 0
        and sum(v for v in (r.get("usage") or {}).values() if type(v) in (int, float)) > 0}
    real = {(l["attempt_id"], l["native_session_id"]) for l in roots if (l["attempt_id"], l["native_session_id"]) in requested_sessions}
    historical_roots = [l for l in current["native_child_lifecycles"]
        if l["attempt_id"] in {a["attempt_id"] for a in attempts} and l.get("parent_session_id") is None]
    historical_proofs = {a["attempt_id"]: proof for a in attempts if (proof := durable_author(a, workers))}
    used = {(l["attempt_id"], l["native_session_id"]) for l in historical_roots
        if l["attempt_id"] in historical_proofs and (l["attempt_id"], l["native_session_id"]) in requested_sessions}
    require(len({session for _, session in real}) == len(real), "native session aliases collide")
    for limit in current.get("resource_limits", []):
        if "allocated" in limit and "hard_limit" in limit:
            require(0 <= limit["allocated"] <= limit["hard_limit"], "resource scope exceeds hard limit")
    return {"at": utc(), "revision": current["revision"], "real_root_agents": len(real), "active_root_processes": len(proofs),
        "activated_root_sessions": sorted([list(pair) for pair in used]), "historical_physical_launches": list(historical_proofs.values()),
        "native_sessions": sorted([list(pair) for pair in real]), "physical_authors": list(proofs.values()),
        "model_requests": len(requests), "settled_model_requests": sum(r["status"] == "SETTLED" for r in requests),
        "usage_complete": all(r["usage_complete"] for r in requests if r["status"] == "SETTLED")}


def pause(client, plan, label):
    route = f"/api/v1/projects/{plan['project_id']}"
    project = client.request("GET", route)
    if not project["paused"]:
        client.request("PATCH", route, {"project": {**project, "paused": True}, "expected_revision": project["revision"]}, key=plan["campaign_id"] + "-pause-" + label)


def drain(client, plan, task_ids, label):
    pause(client, plan, label)
    project = plan["project_id"]
    # Canonical cancellation retains unknown custody. No direct kill or release.
    state = snapshot(client, project)
    for a in state["attempts"]:
        if a["task_id"] in task_ids and a["state"] not in TERMINAL:
            client.request("POST", f"/api/v1/attempts/{a['attempt_id']}/cancel",
                {"project_id": project, "expected_revision": a["revision"], "reason": "Finite concurrency campaign drain"},
                key=plan["campaign_id"] + "-cancel-" + a["attempt_id"])
    start = time.monotonic()
    while True:
        state = snapshot(client, project)
        attempts = [a for a in state["attempts"] if a["task_id"] in task_ids]
        ids = {a["attempt_id"] for a in attempts}
        quiet = (all(a["state"] in TERMINAL for a in attempts)
            and not [r for r in state["native_model_requests"] if r["attempt_id"] in ids and r["status"] != "SETTLED"]
            and not [a for key in ("allocations", "native_child_allocations", "native_child_lifecycles")
                for a in state[key] if a["attempt_id"] in ids and a["state"] != "RELEASED"])
        if quiet: return {"status": "DRAINED", "revision": state["revision"]}
        require(time.monotonic() - start < plan["drain_timeout_seconds"], "drain unconfirmed; project stays paused, quarantine retained")
        time.sleep(min(plan["poll_seconds"], 5))


def checkpoint_contexts(client, plan, task_ids, task_contexts, label):
    # Checkpoint original authority metadata after lawful drain. This is durable
    # logical context, never a claim of reusing a native process/session ID.
    import importlib.util
    spec = importlib.util.spec_from_file_location("checkpoint_context", Path(__file__).with_name("agent-context.py"))
    helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
    current = snapshot(client, plan["project_id"])
    reports = []
    workers = {w["worker_id"]:w for ref in plan["worker_configs"] for w in [worker_config(ref)]}
    history_spec = importlib.util.spec_from_file_location("native_history_checkpoint", Path(__file__).with_name("native-context-history.py"))
    native = importlib.util.module_from_spec(history_spec); history_spec.loader.exec_module(native)
    for attempt in current["attempts"]:
        if attempt["task_id"] not in task_ids: continue
        identity = task_contexts[attempt["task_id"]]
        requests = [r for r in current["native_model_requests"] if r["attempt_id"] == attempt["attempt_id"]]
        session_ids = {l["native_session_id"] for l in current["native_child_lifecycles"] if l["attempt_id"] == attempt["attempt_id"] and l.get("parent_session_id") is None}
        histories = native.collect(workers[attempt["worker_id"]], plan["project_id"], attempt["attempt_id"], session_ids)
        content = {"schema_version": "forgeflow.agent-context-checkpoint.v1", "context_id": identity,
            "source": "POSTGRESQL_AUTHORITY_METADATA", "task_id": attempt["task_id"],
            "attempt_id": attempt["attempt_id"], "generation": attempt["generation"], "state": attempt["state"],
            "native_requests": requests, "not_proven": ["Native session reuse", "Task success unless canonical state is SUCCEEDED"]}
        reports.append(helper.append(client, plan["project_id"], identity, json.dumps(content, sort_keys=True),
            plan["campaign_id"] + "-checkpoint-" + label + "-" + identity))
        for original in histories:
            text = original.pop("content_utf8")
            chunks = [text[i:i+65536] for i in range(0,len(text),65536)]
            for index, chunk in enumerate(chunks):
                saved = {"schema_version":"forgeflow.native-context-history.v1", "context_id":identity,
                    "attempt_id":attempt["attempt_id"], "source":"ORIGINAL_DSH_SESSION_JSONL",
                    **original, "chunk_index":index, "chunk_count":len(chunks), "content_utf8":chunk}
                reports.append(helper.append(client, plan["project_id"], identity, json.dumps(saved,sort_keys=True),
                    plan["campaign_id"] + "-native-history-" + hashlib.sha256(json.dumps(saved,sort_keys=True).encode()).hexdigest()))
    return reports


def run(plan, client, output):
    proof = preflight(plan, client)
    write_json(output / "preflight.json", proof)
    workers = {c["worker_id"]: c for ref in plan["worker_configs"] for c in [worker_config(ref)]}
    report = {"schema_version": "forgeflow.concurrency-report.v1", "campaign_id": plan["campaign_id"],
        "started_at": utc(), "status": "RUNNING", "g20": "INCONCLUSIVE", "stages": [], "errors": []}
    all_tasks = []
    try:
        qualified_contexts, session_owners = set(), {}
        task_contexts = {task: context for stage in plan["stages"] for task, context in zip(stage["task_ids"], stage["context_ids"])}
        for stage_index, stage in enumerate(plan["stages"], 1):
            n, ids = stage["agents"], stage["task_ids"]
            all_tasks.extend(ids)
            current = snapshot(client, plan["project_id"])
            tasks = {t["task_id"]: t for t in current["tasks"]}
            for identity in ids:
                task = tasks[identity]
                client.request("POST", f"/api/v1/projects/{plan['project_id']}/queue-entries",
                    {"task_id": identity, "expected_revision": task["revision"], "worker_id": plan.get("task_workers", {}).get(identity, task["envelope"]["worker_id"]),
                        "worker_scope_id": plan.get("worker_scopes", {}).get(plan.get("task_workers", {}).get(identity, task["envelope"]["worker_id"]), ""), "scope_ids": [], "priority": 0, "lease_seconds": 30},
                    key=plan["campaign_id"] + "-queue-" + identity)
            route = f"/api/v1/projects/{plan['project_id']}"
            project = client.request("GET", route)
            client.request("PATCH", route, {"project": {**project, "paused": False}, "expected_revision": project["revision"]},
                key=plan["campaign_id"] + f"-resume-{stage_index}-{n}")
            began, holding, samples = time.monotonic(), None, []
            stage_key = f"{stage_index:03d}-{n:03d}"
            peak_active = 0
            while True:
                require(not ABORT, "operator interrupted campaign")
                current = snapshot(client, plan["project_id"])
                value = observation(current, set(ids), workers, plan["model"])
                now = time.monotonic()
                require(len(current["native_model_requests"]) <= plan["max_model_requests"], "request budget exceeded")
                require(value["active_root_processes"] <= stage["tier"] <= plan["active_limit"], "actual active Agent limit exceeded")
                peak_active = max(peak_active, value["active_root_processes"])
                by_attempt = {a["attempt_id"]: a for a in current["attempts"]}
                for attempt_id, session_id in value["activated_root_sessions"]:
                    context_id = task_contexts[by_attempt[attempt_id]["task_id"]]
                    require(session_owners.get(session_id, context_id) == context_id, "native session reused across independent contexts")
                    session_owners[session_id] = context_id; qualified_contexts.add(context_id)
                samples.append(value)
                write_json(output / f"batch-{stage_key}-sample-{len(samples):06d}.json", value)
                if set(stage["context_ids"]) <= qualified_contexts:
                    if holding is None: holding = now
                    if now - holding >= stage["hold_seconds"]: break
                require(now - began <= plan["startup_timeout_seconds"], "bounded context activation expired before every requested context had a real model result")
                time.sleep(plan["poll_seconds"])
            observed_seconds = time.monotonic() - holding
            closure = drain(client, plan, set(ids), stage_key)
            checkpoints = checkpoint_contexts(client, plan, set(ids), task_contexts, stage_key)
            report["stages"].append({"checkpoints": checkpoints,"agents": n, "observed_seconds": observed_seconds,
                "samples": len(samples), "tier": stage["tier"], "peak_active_agents": peak_active,
                "activated_contexts": len(stage["context_ids"]), "status": "PASS_SCOPED_CONTEXT_ACTIVATION", "closure": closure})
        require(len(qualified_contexts) == plan["context_count"], "actual activation coverage differs from context pool")
        report["activated_contexts"] = len(qualified_contexts)
        report["active_limit"] = plan["active_limit"]
        report["status"] = "CONTEXT_ACTIVATION_COMPLETED_REVIEW_REQUIRED"
    except Exception as error:
        report["status"] = "FAILED"; report["errors"].append(type(error).__name__ + ": " + str(error))
    finally:
        try: report["cleanup"] = drain(client, plan, set(all_tasks), "final")
        except Exception as error: report["cleanup"] = {"status": "UNCONFIRMED", "error_type": type(error).__name__}
        report["finished_at"] = utc()
        values = sorted(client.snapshot_latencies)
        report["query_latency"] = {"samples": len(values), "p95_ms": values[max(0, math.ceil(len(values) * .95) - 1)] if values else None}
        if values and values[max(0, math.ceil(len(values) * .95) - 1)] > 500:
            report["status"] = "FAILED"
            report["errors"].append("state query P95 exceeds 500 ms")
        report["not_qualified"] = ["Provider billing reconciliation", "Native same-session resume qualification", "Per-task independent verification and Git integration",
            "Browser event-render P95", "Original simultaneous100+ G20 is outside the revised user scope"]
        write_json(output / "report.json", report)
    return report


def template(project, root, active_limit=32, context_count=128):
    require(active_limit in STAGES and type(context_count) is int and max(101, sum(n for n in STAGES if n <= active_limit)) <= context_count <= 10000,
        "100+contexts must cover the selected tier boundaries; default128")
    contexts = [{"context_id": f"context-{i + 1:04d}"} for i in range(context_count)]
    stages, cursor = [], 0
    tiers = [n for n in STAGES if n <= active_limit]
    while cursor < context_count:
        tier = tiers[len(stages)] if len(stages) < len(tiers) else active_limit
        n = min(tier, context_count - cursor)
        selected = [c["context_id"] for c in contexts[cursor:cursor + n]]
        stages.append({"tier": tier, "agents": n, "hold_seconds": 10, "context_ids": selected,
            "task_ids": [f"activate-{identity}" for identity in selected]})
        cursor += n
    return {"schema_version": SCHEMA, "campaign_id": "campaign-" + project, "project_id": project,
        "workload": "REAL_DSH_CONTEXT_POOL", "qualification": "NOT_RUN", "api_url": "http://127.0.0.1:18787",
        "context_count": context_count, "contexts": contexts, "active_limit": active_limit,
        "data_root": str(Path(root).absolute()), "model": "SET_EXPLICIT_MODEL", "model_route_id": "SET_EXPLICIT_ROUTE",
        "owner_credential": {"path": "/REPLACE/private-owner.json", "sha256": "0" * 64},
        "server_identity": {"path": "/REPLACE/server-identity.json", "sha256": "0" * 64},
        "server_binary": {"path": "/REPLACE/forgeflow-server", "sha256": "0" * 64},
        "quota_receipt": {"path": "/REPLACE/provider-quota.json", "sha256": "0" * 64},
        "worker_configs": [], "max_cost_usd": 100, "max_model_requests": context_count * 10,
        "memory_bytes_per_agent": 256 * 1024 * 1024, "system_memory_reserve_bytes": 1024 ** 3, "disk_reserve_bytes": 2 * 1024 ** 3,
        "provider_inflight": active_limit, "poll_seconds": 2, "startup_timeout_seconds": 600, "drain_timeout_seconds": 180,
        "stages": stages}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("init", "validate", "preflight", "run", "drain"))
    p.add_argument("--manifest", type=Path)
    p.add_argument("--project-id")
    p.add_argument("--data-root", type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--execute", action="store_true")
    p.add_argument("--active-limit", type=int, choices=STAGES, default=32)
    p.add_argument("--contexts", type=int, default=128)
    a = p.parse_args()
    try:
        if a.command == "init":
            require(a.project_id and ID.fullmatch(a.project_id) and a.data_root, "project and data root required")
            write_json(a.output, template(a.project_id, a.data_root, a.active_limit, a.contexts)); result = {"status": "TEMPLATE_WRITTEN", "g20": "NOT_RUN"}
        else:
            require(a.manifest, "explicit manifest required")
            plan = validate(read_json(a.manifest))
            if a.command == "validate":
                result = {"status": "MANIFEST_VALID", "g20": "NOT_RUN", "new_model_calls": 0}
                write_json(a.output, result)
            else:
                require(a.command == "preflight" or a.execute, "run/drain requires explicit --execute")
                a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
                write_json(a.output / "manifest.json", plan)
                client = Client(plan, a.output)
                if a.command == "preflight": result = preflight(plan, client)
                elif a.command == "drain":
                    isolated_server(plan)
                    result = drain(client, plan, {t for s in plan["stages"] for t in s["task_ids"]}, "manual")
                else: result = run(plan, client, a.output)
                if a.command != "run": write_json(a.output / "report.json", result)
        print(json.dumps({k: v for k, v in result.items() if k in ("status", "g20", "new_model_calls", "worker_capacity", "tasks")}))
        return 1 if result.get("status") == "FAILED" else 0
    except Exception as error:
        # Never print HTTP bodies, request headers, URLs with credentials or arbitrary private file values.
        result = {"status": "BLOCKED", "error_type": type(error).__name__,
            "reason": str(error) if isinstance(error, Blocked) else "See private inputs and original execution evidence", "g20": "NOT_RUN"}
        print(json.dumps(result))
        if a.output.is_dir() and not (a.output / "blocked.json").exists(): write_json(a.output / "blocked.json", result)
        return 2


def interrupted(*_):
    global ABORT
    ABORT = True


if __name__ == "__main__":
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(main())
