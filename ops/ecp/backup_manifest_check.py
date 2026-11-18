#!/usr/bin/env python3
"""Verify an existing backup manifest without copying data or touching SQL."""
from __future__ import annotations
import argparse,hashlib,json,os,re
from pathlib import Path, PurePosixPath

MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 500_000


def safe_relative(value: str) -> str:
    """Return a canonical relative inventory path or raise.

    The preflight runs before restore, so it must reject path tricks even when
    the later restore verifier would never extract them.
    """
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ValueError("unsafe inventory path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) != value:
        raise ValueError("unsafe inventory path")
    return value

def digest(p:Path)->str:
 h=hashlib.sha256();
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()

def verify_backup(root: Path) -> dict:
    """Verify the complete on-disk inventory without copying or touching SQL."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError("backup must be a regular directory")
    mpath = root / "manifest.json"
    if mpath.is_symlink() or not mpath.is_file() or mpath.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError("manifest must be a bounded regular file")
    manifest = json.loads(mpath.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "forgeflow.backup.v1":
        raise ValueError("unsupported backup schema")
    if (
        manifest.get("dispatch_paused") is not True
        or manifest.get("unsettled_attempts") != 0
        or manifest.get("file_quiescence_checked") is not True
    ):
        raise ValueError("backup is not explicitly quiescent")
    hashes = manifest.get("sha256")
    links = manifest.get("symlinks", {})
    if not isinstance(hashes, dict) or not isinstance(links, dict):
        raise ValueError("manifest inventory must be objects")
    if len(hashes) + len(links) > MAX_MEMBERS:
        raise ValueError("inventory member limit exceeded")
    expected = {}
    for relative, value in hashes.items():
        safe_relative(relative)
        if relative == "manifest.json" or not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("invalid file inventory entry")
        expected[relative] = value
    for relative, target in links.items():
        safe_relative(relative)
        if relative == "manifest.json" or not isinstance(target, str) or "\x00" in target:
            raise ValueError("invalid symlink inventory entry")
        expected[relative] = "SYMLINK:" + target
    if "postgres.dump" not in hashes:
        raise ValueError("database export is missing")
    observed = {}
    entries = 0
    total_bytes = 0
    for item in root.rglob("*"):
        entries += 1
        if entries > MAX_MEMBERS:
            raise ValueError("backup member limit exceeded")
        relative = str(item.relative_to(root))
        if relative == "manifest.json":
            continue
        safe_relative(relative)
        if item.is_symlink():
            observed[relative] = "SYMLINK:" + os.readlink(item)
        elif item.is_file():
            total_bytes += item.stat().st_size
            observed[relative] = digest(item)
        elif not item.is_dir():
            raise ValueError("special backup members are unsupported")
    if observed != expected:
        missing = sorted(set(expected) - set(observed))[:8]
        unexpected = sorted(set(observed) - set(expected))[:8]
        mismatched = sorted(k for k in set(expected) & set(observed) if expected[k] != observed[k])[:8]
        raise ValueError(f"inventory mismatch missing={missing} unexpected={unexpected} mismatched={mismatched}")
    return {"schema_version": manifest["schema_version"], "status": "VERIFIED", "file_count": len(hashes), "symlink_count": len(links), "bytes": total_bytes, "dispatch_paused": True}


def main():
    p=argparse.ArgumentParser();p.add_argument('--backup',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args(); checks=[]
    try:
        preview=verify_backup(a.backup.resolve())
        checks.extend([
            {'name':'schema','status':'PASS'},
            {'name':'quiescence','status':'PASS'},
            {'name':'inventory','status':'PASS','expected_files':preview['file_count'],'observed_files':preview['file_count'],'symlinks':preview['symlink_count'],'bytes':preview['bytes']},
        ])
    except Exception as exc:
        checks.append({'name':'read','status':'FAIL','reason':str(exc)})
    status='PASS' if checks and all(c['status']=='PASS' for c in checks) else 'FAIL'; report={'schema_version':'forgeflow.ecp-backup-check.v1','product_gate_effect':'NONE','qualification':'NOT_RUN','status':status,'checks':checks,'sql_executed':False,'state_copied':False}; a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');print(json.dumps({'status':status,'product_gate_effect':'NONE'}));raise SystemExit(0 if status=='PASS' else 10)
if __name__=='__main__':main()
