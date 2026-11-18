#!/usr/bin/env python3
"""Read only a drained attempt's original native session logs; never grants execution."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess

spec=importlib.util.spec_from_file_location("history_campaign",Path(__file__).with_name("concurrency-readiness.py"))
C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
MAX_BYTES=8*1024*1024
CODEC="const fs=require('node:fs'),z=require('node:zlib');process.stdout.write(z.zstdDecompressSync(fs.readFileSync(0),{maxOutputLength:8388608}));"


def collect(config, project, attempt_id, session_ids):
    C.require(C.ID.fullmatch(project) and C.ID.fullmatch(attempt_id) and session_ids,"exact native context/attempt/session identities required")
    data_root=Path(config["data_root"])
    C.require(data_root.is_absolute() and data_root.resolve()==data_root,"canonical Worker data root required")
    home=data_root/"executor-homes"/project/attempt_id/"managed"
    settings=C.read_json(data_root/"attempts"/attempt_id/"managed-native-config.json")
    C.require(settings.get("home")==str(home),"session home differs from original Worker preparation")
    root=home/"sessions"
    C.require(root.is_dir() and root.resolve()==root and root.stat().st_uid==os.geteuid(),"original owned native session persistence missing or aliased")
    node=Path(config["profile"]["program"])
    pins={p["path"]:p["sha256"] for p in config["profile"]["artifact_pins"]}
    C.pin({"path":str(node),"sha256":pins.get(str(node))})
    records=[];total=0;seen=set();directories=0
    for directory,dirs,files in os.walk(root,followlinks=False):
        directories+=1;C.require(directories<=512,"native session directory bound exceeded")
        for name in dirs: C.require(not (Path(directory)/name).is_symlink(),"native session directory alias refused")
        for name in sorted(files):
            path=Path(directory)/name
            C.require(not path.is_symlink(),"native session file alias refused")
            if not (name.endswith(".jsonl") or name.endswith(".jsonl.zstd")):continue
            C.require(len(records)<256,"native history file bound exceeded")
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(fd,"rb") as stream:
                before=os.fstat(stream.fileno())
                C.require(stat.S_ISREG(before.st_mode) and before.st_uid==os.geteuid() and before.st_size<=MAX_BYTES,"bounded owned native history file required")
                raw=stream.read(MAX_BYTES+1);after=os.fstat(stream.fileno())
            C.require(len(raw)<=MAX_BYTES and (before.st_size,before.st_mtime_ns)==(after.st_size,after.st_mtime_ns),"native history changed after drain")
            if name.endswith(".zstd"):
                result=subprocess.run([str(node),"--max-old-space-size=64","-e",CODEC],input=raw,capture_output=True,
                    timeout=10,env={"PATH":"/usr/bin:/bin","LANG":"C.UTF-8"})
                C.require(result.returncode==0 and len(result.stdout)<=MAX_BYTES,"bounded pinned native zstd decoding failed; original retained")
                content=result.stdout
            else:content=raw
            total+=len(content);C.require(total<=MAX_BYTES,"native history exceeds8MiB; preserve original and review compaction")
            text=content.decode("utf-8");lines=text.splitlines()
            C.require(lines,"empty native persistence cannot establish context continuity")
            header=json.loads(lines[0]);session=header.get("id")
            C.require(header.get("type")=="session" and session in session_ids,"native history belongs to another session/context")
            events=[json.loads(line) for line in lines[1:]]
            C.require(any(event.get("type") in ("assistant/message","assistant/attempt") for event in events),
                "native persistence has no assistant history; metadata/header alone is not conversation memory")
            seen.add(session)
            records.append({"native_session_id":session,"relative_path":str(path.relative_to(root)),
                "source_file_sha256":hashlib.sha256(raw).hexdigest(),"content_sha256":hashlib.sha256(content).hexdigest(),"content_utf8":text})
    C.require(seen==set(session_ids),"original native history missing for an activated root session")
    return records
