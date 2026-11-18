#!/usr/bin/env python3
"""Finite actual Worker-credential API isolation point; preparation has no actors.

One private metadata fixture, two configured bearer identities, no Worker process,
model, Attempt or lease. Original results are append-only; Root GO pins execution.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "verification"))
sys.path.insert(0, str(ROOT / "benchmarks"))
from guarded_api_chain import create_database, database_command, secure_save
from project_scope_registration_point import COUNTS, fingerprint, sha

SOURCES = ("crates/api/src/auth.rs", "crates/api/src/workers.rs", "crates/api/src/worker_dispatch.rs",
    "crates/api/src/collaboration.rs", "crates/api/src/catalog.rs", "crates/api/src/handoff.rs",
    "crates/api/src/lib.rs", "crates/server/src/main.rs")
HELPERS = ("verification/guarded_api_chain.py", "verification/project_scope_registration_point.py")


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def binding(path):
    receipt = json.loads(path.read_text())
    binary = receipt["binaries"]["forgeflow-server"]
    if sha(binary["path"]) != binary["sha256"]:
        raise RuntimeError("frozen executable mismatch")
    source = {}
    for name in SOURCES:
        actual = sha(Path(receipt["snapshot_root"]) / name)
        if actual != receipt["source_files"][name]:
            raise RuntimeError("frozen source mismatch: " + name)
        source[name] = actual
    auth = (Path(receipt["snapshot_root"]) / SOURCES[0]).read_text()
    if "forgeflow.worker-credentials.v1" not in auth or "FORGEFLOW_WORKER_CREDENTIALS_FILE" not in auth:
        raise RuntimeError("build lacks configured individual Worker credential authority")
    return {"receipt_sha256": sha(path), "source_identity": receipt["source_identity"],
        "server": binary, "source_files": source}


class Client:
    def __init__(self, token, role, output):
        self.token, self.role, self.output = token, role, output
        self.number = 0
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.last_headers = {}

    def request(self, method, path, body=None, extra_headers=None):
        self.number += 1
        raw = b"" if body is None else json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
        headers = {"Content-Type": "application/json",
            "Idempotency-Key": "worker-identity-" + uuid.uuid4().hex, **(extra_headers or {})}
        if self.token is not None:
            headers["Authorization"] = "Bearer " + self.token
        req = urllib.request.Request("http://127.0.0.1:8898" + ("" if path == "/healthz" else "/api/v1") + path,
            data=raw if body is not None else None, headers=headers, method=method)
        try:
            response = self.opener.open(req, timeout=15)
        except urllib.error.HTTPError as e:
            response = e
        with response:
            self.last_headers = dict(response.headers)
            payload, status = response.read(), response.status
        try:
            value = json.loads(payload)
        except (ValueError, UnicodeDecodeError):
            value = {"content_sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}
        def redact(value):
            if isinstance(value, dict):
                return {k: "[PRIVATE]" if k.lower() in ["password", "token", "csrf_token", "cookie", "x-csrf-token"] else redact(v) for k,v in value.items()}
            if isinstance(value, list):return [redact(v) for v in value]
            return value
        save(self.output / "requests" / f"{self.role}-{self.number:03d}.json", {
            "method": method, "path": path, "principal": self.role, "body": redact(body),
            "public_extra_headers": redact(extra_headers), "status": status, "response": redact(value),
            "request_sha256": hashlib.sha256(raw).hexdigest(), "response_sha256": hashlib.sha256(payload).hexdigest()})
        return status, value

    def ok(self, method, path, body=None):
        status, value = self.request(method, path, body)
        if not 200 <= status < 300:
            raise RuntimeError(f"{self.role} {method} {path}: HTTP{status}/{value.get('code')}")
        return value.get("data", value)


def counts(env):
    result = database_command(env["DATABASE_URL"], COUNTS)
    if result.returncode:
        raise RuntimeError("private readonly authority counts failed")
    return json.loads(result.stdout)


def plan(args):
    result = {"status": "PREPARED_NOT_RUN", "driver_sha256": sha(__file__), "port": 8898,
        "credential_schema": "forgeflow.worker-credentials.v1", "source_ready": {p:sha(ROOT/p) for p in SOURCES},
        "helpers": {p:sha(ROOT/p) for p in HELPERS}, "actors": "one private API; two bounded invalid-config startup refusals; no actual Worker/model/browser",
        "fixture": "fresh private DB with two paused managed repos and one readonly source; two small public artifacts; no task/flow/attempt/lease",
        "startup_cases": ["valid credentials file mode0644 refuses", "duplicate token with mode0600 refuses"],
        "positive_cases": ["two own identity registrations", "two own empty claims", "two own artifact reads"],
        "auth_preservation": ["Owner password bad/good login", "actual session Cookie read", "missing CSRF denied", "CSRF logout and identical Cookie subsequently401"],
        "negative_cases": ["both directions worker/project impersonation", "missing bound project", "Owner routes", "native trusted Worker header",
            "dispatch scope", "artifact project scope", "readonly project register spoof", "configured shared legacy token401",
            "GET/POST Owner document collection named heartbeat cannot inherit Worker suffix permission"],
        "oracles": "negative batch leaves full private SQL counters unchanged; positives register exactly two scoped Workers, empty claims allocate nothing; source roots/HEAD/bytes unchanged",
        "not_proven": ["actual Worker process", "same-project second-worker stored Attempt isolation (no Attempt fabricated)", "production credential rotation"],
        "needs_root_go": True}
    if args.build_receipt:
        result["source_binding"] = binding(args.build_receipt)
    return result


def run(args, prepared):
    if args.root_go != "G02_INDIVIDUAL_CREDENTIALS_PRIVATE_POINT" or not args.build_receipt:
        raise RuntimeError("exact frozen build and Root GO required")
    output = args.output
    if json.loads((output / "preparation.json").read_text()) != prepared or (output / "report.json").exists():
        raise RuntimeError("exact prepared plan required; preserve original result")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1",8898))
    private = Path(tempfile.mkdtemp(prefix="forgeflow-worker-identity-",dir="/home/chenyoujian/.cache"))
    private.chmod(0o700)
    tag = uuid.uuid4().hex[:12]
    projects = {name:"g02-identity-"+name.lower()+"-"+tag for name in ["P","Q","S"]}
    worker_ids = {name:"g02-individual-"+name.lower()+"-"+tag for name in ["P","Q"]}
    tokens = {name:secrets.token_hex(32) for name in ["P","Q"]}
    credentials = {"schema_version":"forgeflow.worker-credentials.v1","workers":[{
        "worker_id":worker_ids[name],"project_id":projects[name],"token":tokens[name]} for name in ["P","Q"]]}
    env = {"DATABASE_URL":create_database(json.loads(args.database_env.read_text()),"forgeflow_identity_"+tag,private),
        "FORGEFLOW_BIND":"127.0.0.1:8898","FORGEFLOW_DATA_ROOT":str(private/"state"),
        "FORGEFLOW_OWNER_TOKEN":secrets.token_hex(32),"FORGEFLOW_WORKER_TOKEN":secrets.token_hex(32),"RUST_LOG":"info",
        "FORGEFLOW_OWNER_PASSWORD":secrets.token_hex(24),
        "FORGEFLOW_WORKER_CREDENTIALS_FILE":str(private/"worker-credentials.json")}
    secure_save(private/"worker-credentials.json",credentials)
    secure_save(private/"runtime-env.json",env)
    sources = {}
    for name in projects:
        source = private/("source-"+name)
        source.mkdir(mode=0o700)
        (source/"input.json").write_text(json.dumps({"source":name,"purpose":"WORKER_IDENTITY_METADATA_ONLY"})+"\n")
        if name != "S":
            for argv in [["git","init","--initial-branch=main",str(source)],
                ["git","-C",str(source),"add","input.json"],
                ["git","-C",str(source),"-c","user.name=G02 fixture","-c","user.email=g02@example.invalid","commit","-m","identity metadata source"]]:
                subprocess.run(argv,capture_output=True,check=True,timeout=10)
        sources[name] = source
    original = fingerprint(sources)
    report = {"status":"FAIL","source_binding":prepared["source_binding"],"driver_sha256":sha(__file__),
        "checks":[],"projects":projects,"worker_ids":worker_ids,"private_runtime":str(private),
        "models_started":0,"workers_started":0,"attempts_created":0,"main_changed":False,
        "source_fingerprints_before":original,"not_proven":prepared["not_proven"]}
    server = log = None
    all_secrets = [env["DATABASE_URL"],env["FORGEFLOW_OWNER_TOKEN"],env["FORGEFLOW_WORKER_TOKEN"],env["FORGEFLOW_OWNER_PASSWORD"],*tokens.values()]
    def check(name, ok, **facts):
        report["checks"].append({"name":name,"status":"PASS" if ok else "FAIL",**facts})
        if not ok:raise RuntimeError(name)
    try:
        for name, mode, value in [("permissions",0o644,credentials),("duplicate-token",0o600,
            {**credentials,"workers":[credentials["workers"][0],{**credentials["workers"][1],"token":tokens["P"]}]})]:
            bad = private/("bad-"+name+".json")
            secure_save(bad,value)
            bad.chmod(mode)
            result = subprocess.run([prepared["source_binding"]["server"]["path"]],
                env={"PATH":"/usr/bin:/bin",**env,"FORGEFLOW_WORKER_CREDENTIALS_FILE":str(bad)},capture_output=True,timeout=20)
            # Startup output is private: it is not copied into public evidence.
            fd=os.open(private/("startup-"+name+".log"),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,"wb") as stream:stream.write(result.stdout+result.stderr)
            text=(result.stdout+result.stderr).decode(errors="replace")
            check("bad_"+name+"_startup_refused",result.returncode!=0 and "credential" in text.lower(),
                returncode=result.returncode,file_mode=oct(mode),private_log_sha256=hashlib.sha256(result.stdout+result.stderr).hexdigest())
        log=os.fdopen(os.open(private/"server.log",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"wb")
        server=subprocess.Popen([prepared["source_binding"]["server"]["path"]],env={"PATH":"/usr/bin:/bin",**env},stdout=log,stderr=subprocess.STDOUT)
        report["own_server_pid"]=server.pid
        owner=Client(env["FORGEFLOW_OWNER_TOKEN"],"owner",output)
        clients={name:Client(tokens[name],"worker-"+name,output) for name in tokens}
        legacy=Client(env["FORGEFLOW_WORKER_TOKEN"],"legacy-shared",output)
        deadline=time.monotonic()+30
        while True:
            if server.poll() is not None:raise RuntimeError("valid-config API exited before readiness")
            try:
                if owner.ok("GET","/healthz").get("database")=="postgres":break
            except OSError:pass
            if time.monotonic()>deadline:raise RuntimeError("private API readiness timeout")
            time.sleep(.2)
        check("actual_frozen_ELF",sha(f"/proc/{server.pid}/exe")==prepared["source_binding"]["server"]["sha256"])
        session=Client(None,"owner-session",output)
        status,value=session.request("POST","/session",{"password":"incorrect-private-password"})
        check("Owner_wrong_password_denied",status==401 and value.get("code")=="INVALID_CREDENTIALS")
        login=session.ok("POST","/session",{"password":env["FORGEFLOW_OWNER_PASSWORD"]})
        cookie_header=next((v for k,v in session.last_headers.items() if k.lower()=="set-cookie"),"")
        cookie=cookie_header.split(";",1)[0]
        check("Owner_password_login_preserved",bool(login.get("token")) and bool(login.get("csrf_token")) and
            "HttpOnly" in cookie_header and "SameSite=Strict" in cookie_header and "Path=/api/v1" in cookie_header)
        all_secrets.extend([login["token"],login["csrf_token"],cookie])
        status,value=session.request("GET","/me",extra_headers={"Cookie":cookie})
        check("Owner_actual_cookie_read_preserved",status==200)
        status,value=session.request("POST","/logout",{},extra_headers={"Cookie":cookie})
        check("Owner_cookie_missing_CSRF_denied",status==401 and value.get("code")=="AUTHENTICATION_REQUIRED")
        status,value=session.request("POST","/logout",{},extra_headers={"Cookie":cookie,"X-CSRF-Token":login["csrf_token"]})
        after_status,_=session.request("GET","/me",extra_headers={"Cookie":cookie})
        check("Owner_CSRF_logout_revokes_identical_cookie",status==200 and value.get("data",{}).get("logged_out") is True and after_status==401)
        saved={}
        artifacts={}
        for name,project in projects.items():
            saved[name]=owner.ok("POST","/projects",{"project_id":project,"name":"G02 individual identity "+name,
                "root_path":str(sources[name]),"authority_mode":"OBSERVED_READ_ONLY" if name=="S" else "MANAGED",
                "data_origin":"NATIVE","goal":"worker credential metadata point","technology_stack":[],"timezone":"UTC",
                "paused":True,"archived":False,"revision":0})
            if name!="S":
                artifacts[name]=owner.ok("POST","/projects/"+project+"/artifacts",{"content_utf8":"Private identity fixture "+name+"\n","kind":"CONTEXT"})
        baseline=counts(env)
        check("metadata_fixture_execution_zero",all(baseline[k]==0 for k in ["workers","attempts","leases","allocations","allocated","provider_requests","model_requests","native_model_requests"]),counts=baseline)
        document_path="/projects/"+projects["Q"]+"/documents/heartbeat"
        status,value=owner.request("GET",document_path)
        check("Owner_heartbeat_named_collection_route_exists",status==200 and isinstance(value.get("data"),list))
        fake_attempt=str(uuid.uuid4())
        base=lambda name:{"worker_id":worker_ids[name],"boot_id":"metadata-boot-"+name,"project_id":projects[name],"capabilities":[],"executor_profile_ids":[]}
        negatives=[]
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
                (name,"owner_write","POST","/projects",saved[name],None,403,"FORBIDDEN"),
                (name,"native_header_other_worker","POST","/attempts/"+fake_attempt+"/native-controller",
                    {"operation":"status","attempt_id":fake_attempt,"project_id":projects[name],"generation":1},
                    {"x-forgeflow-worker-id":worker_ids[other]},403,"WORKER_SCOPE_DENIED")])
        negatives.extend([("P","readonly_project_spoof","POST","/workers/register",{**base("P"),"project_id":projects["S"]},None,403,"WORKER_SCOPE_DENIED"),
            ("legacy","shared_token_disabled","POST","/workers/register",base("P"),None,401,"AUTHENTICATION_REQUIRED"),
            ("P","Owner_heartbeat_collection_GET_denied","GET",document_path,None,None,403,"FORBIDDEN"),
            ("P","Owner_heartbeat_collection_POST_denied","POST",document_path,
                {"id":"unauthorized-heartbeat-document","value":{},"expected_revision":None},None,403,"FORBIDDEN")])
        for name,label,method,path,body,headers,status,code in negatives:
            client=legacy if name=="legacy" else clients[name]
            actual,value=client.request(method,path,body,headers)
            check(name+"_"+label,actual==status and value.get("code")==code,http_status=actual,error_code=value.get("code"))
        check("all_negative_requests_no_authority_effect",counts(env)==baseline)
        for name in ["P","Q"]:
            clients[name].ok("POST","/workers/register",base(name))
            check(name+"_own_claim_empty",clients[name].ok("POST","/workers/"+worker_ids[name]+"/claim",{"project_id":projects[name]})=={"envelope":None})
            artifact=clients[name].ok("GET","/artifacts/"+artifacts[name]["artifact_id"]+"/content?project_id="+projects[name])
            check(name+"_own_artifact_exact",artifact.get("content_sha256")==hashlib.sha256(("Private identity fixture "+name+"\n").encode()).hexdigest())
        after=counts(env)
        check("two_registration_rows_without_execution",after=={**baseline,"workers":2},counts=after)
        row=database_command(env["DATABASE_URL"],"SELECT json_agg(json_build_object('worker_id',worker_id,'project_id',project_id) ORDER BY worker_id) FROM workers")
        if row.returncode:raise RuntimeError("readonly Worker identity lookup failed")
        check("persisted_exact_two_principal_associations",json.loads(row.stdout)==sorted([{"worker_id":worker_ids[n],"project_id":projects[n]} for n in ["P","Q"]],key=lambda r:r["worker_id"]))
        report["source_fingerprints_after"]=fingerprint(sources)
        check("source_roots_HEADs_files_unchanged",report["source_fingerprints_after"]==original and
            all(owner.ok("GET","/projects/"+projects[n])["root_path"]==saved[n]["root_path"] for n in projects))
        report["final_authority"]=after
        report["status"]="PASS_SCOPED_INDIVIDUAL_WORKER_CREDENTIALS"
    except Exception as e:
        message=str(e)
        for secret in all_secrets:message=message.replace(secret,"[PRIVATE]")
        report["failure"]={"type":type(e).__name__,"message":message[:240]}
    finally:
        if server:
            server.send_signal(signal.SIGTERM)
            try:server.wait(timeout=20)
            except subprocess.TimeoutExpired:
                server.kill();server.wait(timeout=10)
                report["status"]="FAIL"
                report["shutdown_failure"]="owned API required SIGKILL"
            report["own_server_exit"]={"pid":server.pid,"code":server.returncode}
        if log:log.close()
        try:
            report["source_fingerprints_at_shutdown"]=fingerprint(sources)
            report["source_unchanged_at_shutdown"]=report["source_fingerprints_at_shutdown"]==original
            report["authority_at_shutdown"]=counts(env)
            if not report["source_unchanged_at_shutdown"]:
                report["status"]="FAIL"
        except Exception as e:
            report["shutdown_observation_error"]=type(e).__name__
            report["status"]="FAIL"
        report["assertions"]=len(report["checks"])
        save(output/"report.json",report)
    print(json.dumps({"status":report["status"],"assertions":report["assertions"]}))
    return 0 if report["status"].startswith("PASS") else 1


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run",action="store_true")
    p.add_argument("--root-go")
    p.add_argument("--build-receipt",type=Path)
    p.add_argument("--database-env",type=Path,default=Path("/home/chenyoujian/.local/state/forgeflow/control/runtime-env.json"))
    p.add_argument("--output",type=Path,default=Path("evidence/goal-gap-points-r2/g02/runtime-r1"))
    args=p.parse_args()
    prepared=plan(args)
    if args.run:return run(args,prepared)
    save(args.output/"preparation.json",prepared)
    print(json.dumps({"status":prepared["status"],"driver_sha256":prepared["driver_sha256"],"actors_started":0}))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
