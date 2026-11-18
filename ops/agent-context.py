#!/usr/bin/env python3
"""Append or export independent context data using Owner APIs; never activates an Agent."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import urllib.parse
import urllib.request

spec = importlib.util.spec_from_file_location("context_campaign", Path(__file__).with_name("concurrency-readiness.py"))
C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)


def artifact(client, project, ref):
    route = "/api/v1/artifacts/" + urllib.parse.quote(ref["artifact_id"], safe="") + "/content?project_id=" + urllib.parse.quote(project, safe="")
    request = urllib.request.Request(client.base + route, headers={"Authorization": "Bearer " + client.token})
    with client.opener.open(request, timeout=30) as response: raw = response.read(1024 * 1024 + 1)
    C.require(len(raw) <= 1024 * 1024 and hashlib.sha256(raw).hexdigest() == ref["sha256"], "bounded context content with exact digest required")
    return raw.decode("utf-8")


def export(client, project, identity):
    row = client.request("GET", f"/api/v1/projects/{project}/documents/agent_contexts/{identity}")
    total = 0
    def content(ref):
        nonlocal total
        text = artifact(client, project, ref); total += len(text.encode())
        C.require(total <= 8 * 1024 * 1024, "context replay exceeds8MiB; explicitly compact into a new independent context, preserving prior history")
        return text
    manifest = json.loads(content(row["input_manifest_ref"]))
    inputs = [{"logical_path": item["logical_path"], "ref": item["artifact"],
        "content_utf8": content(item["artifact"])} for item in manifest.get("artifact_inputs", [])]
    return {"schema_version": "forgeflow.agent-context-replay.v1", "project_id": project, "context_id": identity,
        "revision": row["revision"], "position_id": row["position_id"], "model_route_id": row["model_route_id"],
        "base_manifest": manifest, "inputs": inputs,
        "prompt": content(row["prompt_ref"]),
        "history": [{"ref": ref, "content_utf8": content(ref)} for ref in row["history_refs"]],
        "execution_authority": False, "native_session_resume_claimed": False}


def append(client, project, identity, content, key):
    C.require(len(content.encode()) <= 1024 * 1024 and content.strip(), "bounded nonempty checkpoint required")
    route = f"/api/v1/projects/{project}/documents/agent_contexts/{identity}"
    row = client.request("GET", route)
    digest = hashlib.sha256(content.encode()).hexdigest()
    if any(ref["sha256"] == digest for ref in row["history_refs"]):
        return {"status": "CHECKPOINT_ALREADY_PRESENT", "context_id": identity, "revision": row["revision"]}
    C.require(len(row["history_refs"]) < 256, "history capacity reached; compact into a new context explicitly")
    saved = client.request("POST", f"/api/v1/projects/{project}/artifacts", {"content_utf8": content, "kind": "AGENT_CONTEXT_HISTORY"}, key + "-artifact")
    expected = row.pop("revision")
    row["history_refs"].append({k: saved[k] for k in ("artifact_id", "sha256")})
    result = client.request("POST", f"/api/v1/projects/{project}/documents/agent_contexts", {"id": identity, "expected_revision": expected, "value": row}, key + "-append")
    return {"status": "CONTEXT_CHECKPOINT_APPENDED", "context_id": identity, "revision": result.get("revision"), "history_entries": len(row["history_refs"]), "models_started": 0}


def materialize(client, project, identity):
    replay = export(client, project, identity)
    content = json.dumps(replay, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    C.require(len(content.encode()) <= 8 * 1024 * 1024, "encoded context replay exceeds8MiB; explicit compaction required")
    sha = hashlib.sha256(content.encode()).hexdigest()
    key = "materialize-" + identity + "-" + sha
    saved = client.request("POST", f"/api/v1/projects/{project}/artifacts", {"content_utf8":content,"kind":"AGENT_CONTEXT_REPLAY"}, key + "-input")
    reference = {k:saved[k] for k in ("artifact_id","sha256")}
    logical = "agent-contexts/" + identity + "/replay-" + sha[:24] + ".json"
    client.request("POST", f"/api/v1/projects/{project}/documents/input_snapshots",
        {"id":logical,"value":{"path":logical,"relative_path":logical,"sha256":sha,"artifact":reference,"source_kind":"CONTROLLED_ARTIFACT"}}, key + "-snapshot")
    manifest = {"files":[],"mandatory_paths":[logical],"artifact_inputs":[{"logical_path":logical,"artifact":reference}]}
    bound = client.request("POST", f"/api/v1/projects/{project}/artifacts",
        {"content_utf8":json.dumps(manifest,separators=(",",":")),"kind":"CONTEXT_MANIFEST"}, key + "-manifest")
    row = client.request("GET", f"/api/v1/projects/{project}/documents/agent_contexts/{identity}")
    C.require(row["revision"] == replay["revision"], "context changed during materialization; retry from current history")
    return {"status":"CONTEXT_INPUT_MATERIALIZED_NO_ACTIVATION", "project_id":project,"context_id":identity,
        "context_revision":replay["revision"],"position_id":replay["position_id"],"model_route_id":replay["model_route_id"],
        "context_manifest":{**{k:bound[k] for k in ("artifact_id","sha256")},"mandatory_paths":[logical],
            "rendered_utf8_bytes":len(content.encode())+8192,"token_estimate":None,"tokenizer_id":None},
        "prompt_artifact":row["prompt_ref"],"read_set":[logical],
        "inputs":[{"path":logical,"sha256":sha,"producer_task_id":None}],"mandatory_paths":[logical],
        "history_entries":len(replay["history"]),"requires_new_approved_task":True,
        "execution_authority":False,"models_started":0,"native_session_resume_claimed":False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("export", "append", "materialize"))
    p.add_argument("--environment", required=True, type=Path)
    p.add_argument("--context-id", required=True)
    p.add_argument("--checkpoint", type=Path)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    try:
        state = C.read_json(a.environment, private=True); C.isolated_server(state)
        C.require(C.ID.fullmatch(a.context_id), "valid context identity required")
        client = C.Client(state)
        if a.command == "export":
            C.write_json(a.output, export(client, state["project_id"], a.context_id))
            result = {"status": "CONTEXT_REPLAY_EXPORTED", "context_id": a.context_id, "models_started": 0}
        elif a.command == "materialize":
            result = materialize(client, state["project_id"], a.context_id)
            C.write_json(a.output, result)
        else:
            C.require(a.checkpoint, "explicit checkpoint content file required")
            content = a.checkpoint.read_text()
            result = append(client, state["project_id"], a.context_id, content,
                "checkpoint-" + a.context_id + "-" + hashlib.sha256(content.encode()).hexdigest())
            C.write_json(a.output, result)
        print(json.dumps(result)); return 0
    except Exception as error:
        print(json.dumps({"status": "BLOCKED", "error_type": type(error).__name__, "reason": str(error) if isinstance(error, C.Blocked) else "Private context evidence retained"})); return 2


if __name__ == "__main__": sys.exit(main())
