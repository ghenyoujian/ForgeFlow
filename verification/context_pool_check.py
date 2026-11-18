#!/usr/bin/env python3
"""Real isolated API/PG checks for dormant context isolation; zero model calls."""
import argparse
import copy
import importlib.util
import json
import subprocess
from pathlib import Path
import urllib.error
import uuid

ROOT = Path(__file__).resolve().parents[1]

def module(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value

C=module("context_check_campaign",ROOT/"ops/concurrency-readiness.py")
H=module("context_check_history",ROOT/"ops/agent-context.py")


def run(a):
    state=C.read_json(a.environment,private=True); C.isolated_server(state)
    a.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    client=C.Client(state,a.output)
    project=state["project_id"]; prefix=f"/api/v1/projects/{project}"
    plan=C.read_json(a.campaign)
    checks=[]
    def check(name, passed):
        C.require(passed,name); checks.append({"name":name,"passed":True})
    def rejected(name,identity,value,expected_revision=None):
        body={"id":identity,"value":value}
        if expected_revision is not None: body["expected_revision"]=expected_revision
        try:
            client.request("POST",prefix+"/documents/agent_contexts",body,"reject-"+uuid.uuid4().hex)
        except urllib.error.HTTPError as error:
            raw=getattr(error,"forgeflow_response",None)
            if raw is None: raw=json.loads(error.read())
            expected_codes={"runtime_authority_rejected":"AGENT_CONTEXT_INVALID", "foreign_project_identity_rejected":"AGENT_CONTEXT_INVALID",
                "missing_artifact_rejected":"AGENT_CONTEXT_ARTIFACT_MISMATCH", "foreign_artifact_rejected":"AGENT_CONTEXT_ARTIFACT_MISMATCH",
                "history_reset_rejected":"AGENT_CONTEXT_HISTORY_CHANGED", "role_rebinding_rejected":"AGENT_CONTEXT_IDENTITY_CHANGED",
                "stale_revision_rejected":"REVISION_CONFLICT"}
            check(name,error.code in (400,403,409,422) and raw.get("code")==expected_codes[name])
            C.write_json(a.output/(name+".json"),{"status":error.code,"response":raw})
        else: raise C.Blocked("unexpected acceptance: "+name)
    contexts=client.collection(prefix+"/documents/agent_contexts")
    check("128_persistent_contexts",len(contexts)==128 and len({c["context_id"] for c in contexts})==128)
    check("independent_roles_prompts_inputs",all(len({json.dumps(c[k],sort_keys=True) for c in contexts})==128 for k in ("position_id","input_manifest_ref","prompt_ref")))
    current=C.snapshot(client,project)
    check("paused_no_attempts_models_allocations",current["project"]["paused"] and all(not current[k] for k in ("attempts","native_model_requests","allocations","native_child_lifecycles")))
    active=[r for r in current["resource_limits"] if r["scope_id"]=="campaign-project" and r["dimension"]=="active_slot"]
    check("active_cap32_independent_of128contexts",len(active)==1 and active[0]["hard_limit"]==32)
    tasks={t["task_id"]:t for t in current["tasks"]}; rows={c["context_id"]:c for c in contexts}
    for batch in plan["stages"]:
        check("batch_within_tier_"+str(len(checks)),batch["agents"]<=batch["tier"]<=32)
        for task_id,context_id in zip(batch["task_ids"],batch["context_ids"]):
            task=tasks[task_id]; row=rows[context_id]
            check("binding_"+context_id,task["envelope"]["prompt_artifact"]==row["prompt_ref"] and all(task["envelope"]["context_manifest"][k]==row["input_manifest_ref"][k] for k in ("artifact_id","sha256")))
    row=rows["context-0001"]; original=copy.deepcopy(row)
    value=copy.deepcopy(row); value["state"]="RUNNING"
    rejected("runtime_authority_rejected",row["context_id"],value,row["revision"])
    value=copy.deepcopy(row); value["project_id"]="other-project"
    rejected("foreign_project_identity_rejected",row["context_id"],value,row["revision"])
    value=copy.deepcopy(row); value["context_id"]="missing-artifact"; value["prompt_ref"]["artifact_id"]="not-existing"
    rejected("missing_artifact_rejected",value["context_id"],value)
    other_project="other-context-"+uuid.uuid4().hex[:8]
    foreign_root=a.output/"foreign-root";foreign_root.mkdir()
    subprocess.run(["/usr/bin/git","-C",str(foreign_root),"-c","core.hooksPath=/dev/null","init","--initial-branch=main"],check=True,capture_output=True)
    other={**current["project"],"project_id":other_project,"root_path":str(foreign_root),"name":"Cross-project artifact rejection fixture","revision":0}
    client.request("POST","/api/v1/projects",other,"create-"+other_project)
    foreign=client.request("POST",f"/api/v1/projects/{other_project}/artifacts",{"content_utf8":"foreign fixture","kind":"TEST"},"artifact-"+other_project)
    value=copy.deepcopy(row); value["context_id"]="foreign-artifact";value["prompt_ref"]={k:foreign[k] for k in ("artifact_id","sha256")}
    rejected("foreign_artifact_rejected",value["context_id"],value)
    content=json.dumps({"scope":"Context persistence fixture, zero model execution","context_id":row["context_id"],"marker":uuid.uuid4().hex})
    first=H.append(client,project,row["context_id"],content,"history-check-"+uuid.uuid4().hex)
    second=H.append(client,project,row["context_id"],content,"history-repeat-"+uuid.uuid4().hex)
    check("history_append_and_retry_no_duplicate",first["history_entries"]==1 and second["status"]=="CHECKPOINT_ALREADY_PRESENT")
    fresh=C.Client(state)
    reopened=H.export(fresh,project,row["context_id"])
    check("reopen_exact_input_prompt_and_history",len(reopened["history"])==1 and reopened["history"][0]["content_utf8"]==content and reopened["inputs"][0]["logical_path"]=="agent-contexts/context-0001.json" and row["context_id"] in reopened["inputs"][0]["content_utf8"])
    second_context=fresh.request("GET",prefix+"/documents/agent_contexts/context-0002")
    check("other_context_history_unchanged",second_context["history_refs"]==[])
    latest=fresh.request("GET",prefix+"/documents/agent_contexts/context-0001")
    value=copy.deepcopy(latest);value["history_refs"]=[]
    rejected("history_reset_rejected",value["context_id"],value,latest["revision"])
    value=copy.deepcopy(latest);value["position_id"]="agent-0002"
    rejected("role_rebinding_rejected",value["context_id"],value,latest["revision"])
    rejected("stale_revision_rejected",latest["context_id"],latest,original["revision"])
    check("original_base_preserved",all(latest[k]==original[k] for k in ("input_manifest_ref","prompt_ref","position_id","model_route_id")))
    after=C.snapshot(client,project)
    check("checks_did_not_launch_execution",not after["attempts"] and not after["native_model_requests"])
    report={"status":"PASS_SCOPED_CONTEXT_PERSISTENCE", "project_id":project,"contexts":len(contexts),"active_limit":32,"checks":checks,"models_started":0,"g20":"NOT_RUN","limitation":"No real model activation or physical capacity qualification"}
    C.write_json(a.output/"report.json",report); print(json.dumps({k:v for k,v in report.items() if k!="checks"}|{"checks":len(checks)}))


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("environment","campaign","output"):p.add_argument("--"+name,required=True,type=Path)
    run(p.parse_args())
