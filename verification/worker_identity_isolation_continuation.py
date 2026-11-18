#!/usr/bin/env python3
"""Only the unexecuted remainder of the frozen individual-credential API point.

The original FAIL and nine successful checks remain unchanged. The same private
metadata fixture is reused; unsupported Owner collection422 reaches its handler,
whereas Worker403 must be produced by the role guard before that handler.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode=True
from worker_identity_isolation_point import Client, binding, counts, fingerprint, save, sha
from guarded_api_chain import database_command

ORIGINAL_DRIVER_SHA="24714a6259e161f7a0e2db4627ba6d23cb62f4eac8a4a4467ec91f3d1ed6f287"


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run",action="store_true")
    p.add_argument("--root-go")
    p.add_argument("--original-report",type=Path,required=True)
    p.add_argument("--build-receipt",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    original=json.loads(a.original_report.read_text())
    private=Path(original["private_runtime"])
    env=json.loads((private/"runtime-env.json").read_text())
    credentials=json.loads(Path(env["FORGEFLOW_WORKER_CREDENTIALS_FILE"]).read_text())
    projects=original["projects"]
    worker_ids=original["worker_ids"]
    sources={n:Path(v["canonical_root"]) for n,v in original["source_fingerprints_before"].items()}
    driver=Path(__file__).with_name("worker_identity_isolation_point.py")
    if sha(driver)!=ORIGINAL_DRIVER_SHA or original["status"]!="FAIL" or original["failure"]["message"]!="Owner_heartbeat_named_collection_route_exists":
        raise RuntimeError("exact original failure and unchanged frozen driver required")
    if env["FORGEFLOW_BIND"]!="127.0.0.1:8898":raise RuntimeError("requires same private8898")
    frozen=binding(a.build_receipt)
    if frozen!=original["source_binding"]:raise RuntimeError("requires original frozen build")
    grants={n:next(g for g in credentials["workers"] if g["worker_id"]==worker_ids[n] and g["project_id"]==projects[n]) for n in ["P","Q"]}
    artifacts={}
    for name in ["P","Q"]:
        path="/projects/"+projects[name]+"/artifacts"
        matches=[json.loads(f.read_text()) for f in (a.original_report.parent/"requests").glob("owner-*.json")]
        found=[v for v in matches if v["path"]==path and v["method"]=="POST" and v["status"]==200]
        if len(found)!=1:raise RuntimeError("one original actual artifact receipt required")
        artifacts[name]=found[0]["response"]["data"]
    plan={"status":"PREPARED_NOT_RUN","driver_sha256":sha(__file__),"original_driver_sha256":sha(driver),
        "original_report_sha256":sha(a.original_report),"source_binding":frozen,"private_runtime":str(private),
        "private_env_sha256":sha(private/"runtime-env.json"),"private_credentials_sha256":sha(env["FORGEFLOW_WORKER_CREDENTIALS_FILE"]),
        "projects":projects,"worker_ids":worker_ids,"actual_original_artifacts":artifacts,
        "authority_baseline":original["authority_at_shutdown"],"source_fingerprints":original["source_fingerprints_before"],
        "skip_original_passed_checks":[c["name"] for c in original["checks"] if c["status"]=="PASS"],
        "remaining_scope":"real Owner generic collection422 versus Worker403; remaining identity/role negatives; two real registrations,emptyclaims,artifact reads; original counter and source checks",
        "actors":"one temporary same private API8898; no Worker/model/browser/newDB/metadata",
        "not_proven":original["not_proven"]}
    if not a.run:
        if counts(env)!=plan["authority_baseline"] or fingerprint(sources)!=plan["source_fingerprints"]:
            raise RuntimeError("existing private fixture changed")
        save(a.output/"plan.json",plan)
        print(json.dumps({"status":plan["status"],"driver_sha256":plan["driver_sha256"],"actors_started":0}))
        return 0
    if a.root_go!="G02_IDENTITY_CONTINUATION_ONLY" or json.loads((a.output/"plan.json").read_text())!=plan or (a.output/"report.json").exists():
        raise RuntimeError("Root exact continuation GO and append-only output required")
    with socket.socket() as probe:probe.bind(("127.0.0.1",8898))
    report={"status":"FAIL","plan":plan,"checks":[],"private_runtime":str(private),
        "original_failure_preserved":True,"repeated_original_passed_checks":[],"models_started":0,"workers_started":0,"main_changed":False}
    server=log=None
    secrets=[env["DATABASE_URL"],env["FORGEFLOW_OWNER_TOKEN"],env["FORGEFLOW_WORKER_TOKEN"],env["FORGEFLOW_OWNER_PASSWORD"],*(g["token"] for g in credentials["workers"])]
    def check(name,ok,**facts):
        report["checks"].append({"name":name,"status":"PASS" if ok else "FAIL",**facts})
        if not ok:raise RuntimeError(name)
    try:
        if counts(env)!=plan["authority_baseline"] or fingerprint(sources)!=plan["source_fingerprints"]:
            raise RuntimeError("continuation precondition changed")
        log=os.fdopen(os.open(private/"identity-continuation-api.log",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"wb")
        server=subprocess.Popen([frozen["server"]["path"]],env={"PATH":"/usr/bin:/bin",**env},stdout=log,stderr=subprocess.STDOUT)
        report["own_server_pid"]=server.pid
        owner=Client(env["FORGEFLOW_OWNER_TOKEN"],"owner",a.output)
        clients={n:Client(grants[n]["token"],"worker-"+n,a.output) for n in ["P","Q"]}
        legacy=Client(env["FORGEFLOW_WORKER_TOKEN"],"legacy-shared",a.output)
        deadline=time.monotonic()+30
        while True:
            if server.poll() is not None:raise RuntimeError("owned API exited before readiness")
            try:
                if owner.ok("GET","/healthz").get("database")=="postgres":break
            except OSError:pass
            if time.monotonic()>deadline:raise RuntimeError("owned API readiness timeout")
            time.sleep(.2)
        document_path="/projects/"+projects["Q"]+"/documents/heartbeat"
        status,value=owner.request("GET",document_path)
        check("Owner_generic_route_reaches_collection_validator",status==422 and value.get("code")=="VALIDATION_ERROR",http_status=status,error_code=value.get("code"))
        base=lambda n:{"worker_id":worker_ids[n],"boot_id":"metadata-boot-"+n,"project_id":projects[n],"capabilities":[],"executor_profile_ids":[]}
        negatives=[("P","Owner_heartbeat_collection_GET_denied","GET",document_path,None,None,403,"FORBIDDEN"),
            ("P","Owner_heartbeat_collection_POST_denied","POST",document_path,{"id":"unauthorized-heartbeat-document","value":{},"expected_revision":None},None,403,"FORBIDDEN")]
        fake_attempt=str(uuid.uuid4())
        for name,other in [("P","Q"),("Q","P")]:
            negatives.extend([(name,"register_other_worker","POST","/workers/register",{**base(name),"worker_id":worker_ids[other]},None,403,"WORKER_SCOPE_DENIED"),
                (name,"register_other_project","POST","/workers/register",{**base(name),"project_id":projects[other]},None,403,"WORKER_SCOPE_DENIED"),
                (name,"register_missing_project","POST","/workers/register",{**base(name),"project_id":None},None,403,"WORKER_SCOPE_DENIED"),
                (name,"claim_other_worker","POST","/workers/"+worker_ids[other]+"/claim",{"project_id":projects[name]},None,403,"WORKER_SCOPE_DENIED"),
                (name,"claim_other_project","POST","/workers/"+worker_ids[name]+"/claim",{"project_id":projects[other]},None,403,"WORKER_SCOPE_DENIED"),
                (name,"dispatch_other_worker","GET","/workers/"+worker_ids[other]+"/dispatch-events?project_id="+projects[name],None,None,403,"WORKER_SCOPE_DENIED"),
                (name,"dispatch_other_project","GET","/workers/"+worker_ids[name]+"/dispatch-events?project_id="+projects[other],None,None,403,"WORKER_SCOPE_DENIED"),
                (name,"artifact_other_project","GET","/artifacts/"+artifacts[other]["artifact_id"]+"/content?project_id="+projects[other],None,None,403,"WORKER_SCOPE_DENIED"),
                (name,"artifact_missing_project","GET","/artifacts/"+artifacts[name]["artifact_id"]+"/content",None,None,403,"PROJECT_SCOPE_REQUIRED"),
                (name,"owner_read","GET","/projects/"+projects[name],None,None,403,"FORBIDDEN"),
                (name,"owner_write","POST","/projects",{"project_id":projects[name]},None,403,"FORBIDDEN"),
                (name,"native_header_other_worker","POST","/attempts/"+fake_attempt+"/native-controller",
                    {"operation":"status","attempt_id":fake_attempt,"project_id":projects[name],"generation":1},{"x-forgeflow-worker-id":worker_ids[other]},403,"WORKER_SCOPE_DENIED")])
        negatives.extend([("P","readonly_project_spoof","POST","/workers/register",{**base("P"),"project_id":projects["S"]},None,403,"WORKER_SCOPE_DENIED"),
            ("legacy","shared_token_disabled","POST","/workers/register",base("P"),None,401,"AUTHENTICATION_REQUIRED")])
        for name,label,method,path,body,headers,status,code in negatives:
            actual,value=(legacy if name=="legacy" else clients[name]).request(method,path,body,headers)
            check(name+"_"+label,actual==status and value.get("code")==code,http_status=actual,error_code=value.get("code"))
        check("remaining_negatives_leave_authority_unchanged",counts(env)==plan["authority_baseline"])
        for name in ["P","Q"]:
            clients[name].ok("POST","/workers/register",base(name))
            check(name+"_own_empty_claim",clients[name].ok("POST","/workers/"+worker_ids[name]+"/claim",{"project_id":projects[name]})=={"envelope":None})
            content=clients[name].ok("GET","/artifacts/"+artifacts[name]["artifact_id"]+"/content?project_id="+projects[name])
            check(name+"_own_real_artifact_bytes",content.get("content_sha256")==artifacts[name]["sha256"])
        after=counts(env)
        check("exact_two_scoped_registrations_no_execution",after=={**plan["authority_baseline"],"workers":2},counts=after)
        rows=database_command(env["DATABASE_URL"],"SELECT json_agg(json_build_object('worker_id',worker_id,'project_id',project_id) ORDER BY worker_id) FROM workers")
        if rows.returncode:raise RuntimeError("readonly Worker identity query failed")
        check("persisted_two_exact_credential_bindings",json.loads(rows.stdout)==sorted([{"worker_id":worker_ids[n],"project_id":projects[n]} for n in ["P","Q"]],key=lambda r:r["worker_id"]))
        check("original_roots_HEADs_files_unchanged",fingerprint(sources)==plan["source_fingerprints"] and
            all(owner.ok("GET","/projects/"+projects[n])["root_path"]==str(sources[n]) for n in projects))
        report["final_authority"]=after
        report["status"]="PASS_SCOPED_IDENTITY_CONTINUATION"
    except Exception as e:
        message=str(e)
        for secret in secrets:message=message.replace(secret,"[PRIVATE]")
        report["failure"]={"type":type(e).__name__,"message":message[:240]}
    finally:
        if server:
            server.send_signal(signal.SIGTERM)
            try:server.wait(timeout=20)
            except subprocess.TimeoutExpired:
                server.kill();server.wait(timeout=10);report["status"]="FAIL"
                report["shutdown_failure"]="own API required SIGKILL"
            report["own_server_exit"]={"pid":server.pid,"code":server.returncode}
        if log:log.close()
        try:
            report["authority_at_shutdown"]=counts(env)
            report["source_fingerprints_at_shutdown"]=fingerprint(sources)
            if report["source_fingerprints_at_shutdown"]!=plan["source_fingerprints"]:report["status"]="FAIL"
        except Exception as e:
            report["shutdown_observation_error"]=type(e).__name__;report["status"]="FAIL"
        report["assertions"]=len(report["checks"])
        save(a.output/"report.json",report)
    print(json.dumps({"status":report["status"],"assertions":report["assertions"]}))
    return 0 if report["status"].startswith("PASS") else 1


if __name__=="__main__":raise SystemExit(main())
