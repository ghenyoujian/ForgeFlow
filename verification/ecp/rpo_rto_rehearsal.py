#!/usr/bin/env python3
"""Bounded, opt-in PostgreSQL backup/restore rehearsal for ECP.

The default invocation is deliberately NOT_RUN.  ``--run`` creates a private
fixture database, dumps it with pg_dump, verifies an immutable backup
inventory, restores it into a new database, and compares a durable row count
and data digest.  This is an observed fixture rehearsal; it never qualifies
50 GiB RPO/RTO or an ECP Gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import uuid
from datetime import datetime, timezone
from typing import Any

import sys

OPS_ECP = Path(__file__).resolve().parents[2] / "ops" / "ecp"
if str(OPS_ECP) not in sys.path:
    sys.path.insert(0, str(OPS_ECP))
from backup_manifest_check import verify_backup

MAX_DEFAULT_FIXTURE_BYTES = 64 * 1024 * 1024
MAX_LARGE_FIXTURE_BYTES = 64 * 1024 * 1024 * 1024
DEFAULT_PG_BIN = Path("/home/chenyoujian/.cache/forgeflow-postgres/root/usr/lib/postgresql/16/bin")
DEFAULT_PG_LIB = Path("/home/chenyoujian/.cache/forgeflow-postgres/root/usr/lib/x86_64-linux-gnu")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pg_env(url: str, database: str | None = None) -> dict[str, str]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"postgres", "postgresql"}:
        raise ValueError("database URL must use postgres:// or postgresql://")
    query = urllib.parse.parse_qs(parsed.query)
    env = os.environ.copy()
    env.update(
        {
            "PGHOST": query.get("host", [parsed.hostname or "127.0.0.1"])[0],
            "PGPORT": query.get("port", [str(parsed.port or 5432)])[0],
            "PGUSER": query.get("user", [urllib.parse.unquote(parsed.username or "")])[0],
            "PGPASSWORD": query.get("password", [urllib.parse.unquote(parsed.password or "")])[0],
            "PGDATABASE": database or urllib.parse.unquote(parsed.path.lstrip("/")),
        }
    )
    for key, target in (("sslmode", "PGSSLMODE"), ("sslrootcert", "PGSSLROOTCERT"), ("options", "PGOPTIONS")):
        if key in query:
            env[target] = query[key][0]
    if DEFAULT_PG_LIB.is_dir():
        env["LD_LIBRARY_PATH"] = f"{DEFAULT_PG_LIB}:{env.get('LD_LIBRARY_PATH', '')}".rstrip(":")
    return env


def run_tool(args: list[str], env: dict[str, str], *, timeout: float = 120.0, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    command = list(args)
    if command and command[0] in {"psql", "createdb", "dropdb", "pg_dump", "pg_restore"}:
        bundled = Path(os.environ.get("FORGEFLOW_PG_BIN", str(DEFAULT_PG_BIN))) / command[0]
        if bundled.is_file():
            command[0] = str(bundled)
    return subprocess.run(command, env=env, input=input_text, capture_output=True, text=True, timeout=timeout, check=False)


def sql(database_url: str, database: str, statement: str, *, timeout: float = 120.0) -> str:
    result = run_tool(
        ["psql", "-X", "--no-password", "-v", "ON_ERROR_STOP=1", "-At", "-c", statement],
        pg_env(database_url, database),
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(f"psql failed: {result.stderr.strip()[:500]}")
    return result.stdout.strip()


def create_database(database_url: str, name: str) -> None:
    result = run_tool(["createdb", name], pg_env(database_url), timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"createdb failed: {result.stderr.strip()[:500]}")


def drop_database(database_url: str, name: str) -> None:
    result = run_tool(["dropdb", "--if-exists", "--force", name], pg_env(database_url), timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"dropdb failed: {result.stderr.strip()[:500]}")


def make_fixture(root: Path, fixture_bytes: int) -> tuple[int, int]:
    data = root / "data"
    data.mkdir(parents=True)
    # The file is intentionally outside PostgreSQL so the inventory check also
    # covers the authoritative data-root copy used by restore.py.
    payload = data / "fixture.bin"
    block = b"forgeflow-ecp-rpo-fixture\n"
    repeats, remainder = divmod(fixture_bytes, len(block))
    # Stream bounded chunks instead of constructing the entire fixture as one
    # bytes object.  A 50 GiB rehearsal must remain memory bounded; the
    # previous ``block * repeats`` expression raised MemoryError before the
    # backup phase even started.
    chunk_repeats = 65536  # approximately 1.7 MiB per write
    chunk = block * chunk_repeats
    with payload.open("wb") as handle:
        while repeats >= chunk_repeats:
            handle.write(chunk)
            repeats -= chunk_repeats
        if repeats:
            handle.write(block * repeats)
        handle.write(block[:remainder])
    return payload.stat().st_size, 1


def seal_manifest(root: Path) -> dict[str, Any]:
    hashes: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "manifest.json":
            hashes[str(path.relative_to(root))] = sha256(path)
    manifest = {
        "schema_version": "forgeflow.backup.v1",
        "data_root_original": str((root / "data").resolve()),
        "project_event_watermarks": {},
        "file_quiescence_checked": True,
        "sha256": hashes,
        "symlinks": {},
        "dispatch_paused": True,
        "unsettled_attempts": 0,
        "projects": [],
        "repositories": [],
    }
    (root / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def run(args: argparse.Namespace) -> dict[str, Any]:
    watermark_events = max(0, int(getattr(args, "watermark_events", 8)))
    report: dict[str, Any] = {
        "schema_version": "forgeflow.ecp-rpo-rto-rehearsal.v1",
        "scope": "ECP_PHASE8_RPO_RTO_FIXTURE_REHEARSAL",
        "product_gate_effect": "NONE",
        "qualification": "NOT_RUN",
        "status": "NOT_RUN",
        "model_calls": 0,
        "checks": [],
        "denominator": {"total": 0, "passed": 0, "failed": 0, "not_run": 0, "inconclusive": 0},
        "fixture": {"requested_bytes": args.fixture_bytes, "max_bytes": args.max_fixture_bytes, "watermark_events": watermark_events},
        "limitations": [
            "This is a bounded disposable fixture rehearsal, not ECP-G8 qualification.",
            "Application event-watermark RPO is NOT_RUN; only PostgreSQL dump/restore and file inventory are measured.",
            "50 GiB RPO/RTO, production workload overlap, independent Principal approval and Gate state remain NOT_RUN.",
        ],
    }
    if not args.run:
        report["reason"] = "explicit --run is required; no database or filesystem side effects were attempted"
        report["denominator"]["not_run"] = 1
        return report
    if not args.database_url:
        report.update({"status": "BLOCKED", "qualification": "BLOCKED", "reason": "--database-url is required for an isolated PostgreSQL rehearsal"})
        report["denominator"]["inconclusive"] = 1
        return report
    if args.fixture_bytes < 1 or args.fixture_bytes > args.max_fixture_bytes:
        report.update({"status": "BLOCKED", "qualification": "BLOCKED", "reason": "fixture size is outside the explicit safety bound"})
        report["denominator"]["inconclusive"] = 1
        return report

    private = Path(tempfile.mkdtemp(prefix="forgeflow-ecp-rpo-rto-", dir=args.private_root))
    source_db = "forgeflow_ecp_rpo_src_" + uuid.uuid4().hex[:12]
    restore_db = "forgeflow_ecp_rpo_dst_" + uuid.uuid4().hex[:12]
    backup = private / "backup"
    restored_data = private / "restored-data"
    created_dbs: list[str] = []
    started = time.monotonic()
    try:
        create_database(args.database_url, source_db)
        created_dbs.append(source_db)
        rows = max(1, (args.fixture_bytes + 8191) // 8192)
        sql(args.database_url, source_db, "CREATE TABLE ecp_rpo_fixture(id BIGINT PRIMARY KEY, payload TEXT NOT NULL);")
        sql(
            args.database_url,
            source_db,
            f"INSERT INTO ecp_rpo_fixture SELECT i, repeat(md5(i::text), 256) FROM generate_series(1, {rows}) AS s(i);",
            timeout=args.timeout_seconds,
        )
        if watermark_events:
            sql(args.database_url, source_db, "CREATE TABLE ecp_rpo_watermark(event_seq BIGINT PRIMARY KEY, occurred_at TIMESTAMPTZ NOT NULL);")
            sql(args.database_url, source_db, f"INSERT INTO ecp_rpo_watermark SELECT i, clock_timestamp() FROM generate_series(1, {watermark_events}) AS s(i);")
        source_count = int(sql(args.database_url, source_db, "SELECT count(*) FROM ecp_rpo_fixture;"))
        source_watermark = (int(sql(args.database_url, source_db, "SELECT COALESCE(max(event_seq), 0) FROM ecp_rpo_watermark;")) if watermark_events else 0)
        fixture_size, _ = make_fixture(backup, args.fixture_bytes)
        dump_start = time.monotonic()
        dump = run_tool(["pg_dump", "--format=custom", "--no-owner", "--no-privileges", "--file", str(backup / "postgres.dump"), source_db], pg_env(args.database_url), timeout=args.timeout_seconds)
        if dump.returncode != 0:
            raise RuntimeError(f"pg_dump failed: {dump.stderr.strip()[:500]}")
        seal_manifest(backup)
        inventory = verify_backup(backup)
        backup_seconds = time.monotonic() - dump_start
        report["checks"].append({"name": "quiescent backup inventory is verified", "status": "PASS", "facts": inventory})
        report["checks"].append({"name": "fixture data is within explicit bound", "status": "PASS", "facts": {"bytes": fixture_size, "bound": args.max_fixture_bytes}})

        create_database(args.database_url, restore_db)
        created_dbs.append(restore_db)
        restored_data.mkdir(parents=True)
        shutil.copytree(backup / "data", restored_data / "data", symlinks=True)
        restore_start = time.monotonic()
        restored = run_tool(["pg_restore", "--exit-on-error", "--single-transaction", "--no-owner", "--no-privileges", "--dbname", restore_db, str(backup / "postgres.dump")], pg_env(args.database_url), timeout=args.timeout_seconds)
        if restored.returncode != 0:
            raise RuntimeError(f"pg_restore failed: {restored.stderr.strip()[:500]}")
        restored_count = int(sql(args.database_url, restore_db, "SELECT count(*) FROM ecp_rpo_fixture;"))
        restored_watermark = (int(sql(args.database_url, restore_db, "SELECT COALESCE(max(event_seq), 0) FROM ecp_rpo_watermark;")) if watermark_events else 0)
        restored_hash = sha256(restored_data / "data" / "fixture.bin")
        source_hash = sha256(backup / "data" / "fixture.bin")
        restore_seconds = time.monotonic() - restore_start
        report["checks"].append({"name": "isolated PostgreSQL restore preserves durable rows", "status": "PASS" if source_count == restored_count else "FAIL", "facts": {"source_count": source_count, "restored_count": restored_count}})
        watermark_ok = source_watermark == restored_watermark == watermark_events
        report["checks"].append({"name": "application event watermark survives isolated restore", "status": "PASS" if watermark_ok else "FAIL", "facts": {"source_max_event_seq": source_watermark, "restored_max_event_seq": restored_watermark, "expected": watermark_events}})
        report["checks"].append({"name": "isolated data-root restore preserves immutable bytes", "status": "PASS" if source_hash == restored_hash else "FAIL", "facts": {"source_sha256": source_hash, "restored_sha256": restored_hash}})
        within_rto = restore_seconds <= args.rto_threshold_seconds
        report["checks"].append({"name": "isolated restore meets explicit RTO observation threshold", "status": "PASS" if within_rto else "FAIL", "facts": {"restore_seconds": restore_seconds, "threshold_seconds": args.rto_threshold_seconds}})
        report["status"] = "PASS" if all(item["status"] == "PASS" for item in report["checks"]) else "FAIL"
        report["qualification"] = "OBSERVED_NOT_GATE" if report["status"] == "PASS" else "NOT_RUN"
        report["fixture"].update({"requested_bytes": args.fixture_bytes, "actual_bytes": fixture_size, "rows": source_count, "watermark_events": watermark_events})
        report["timings"] = {"backup_seconds": backup_seconds, "restore_seconds": restore_seconds, "wall_seconds": time.monotonic() - started}
        report["rpo"] = {"status": "NOT_RUN", "reason": "source outage interval and event production timestamps are not measured", "watermark_preserved": watermark_ok, "source_max_event_seq": source_watermark, "restored_max_event_seq": restored_watermark}
        report["rto"] = {"status": "OBSERVED_NOT_GATE", "seconds": restore_seconds, "threshold_seconds": args.rto_threshold_seconds, "within_threshold": restore_seconds <= args.rto_threshold_seconds}
    except Exception as exc:
        report.update({"status": "INCONCLUSIVE", "qualification": "INCONCLUSIVE", "reason": f"{type(exc).__name__}: {exc}"})
        report["timings"] = {"wall_seconds": time.monotonic() - started}
    finally:
        for database in reversed(created_dbs):
            try:
                drop_database(args.database_url, database)
            except Exception as exc:
                report.setdefault("cleanup_errors", []).append(str(exc))
        if not args.keep_private:
            shutil.rmtree(private, ignore_errors=True)
        else:
            report["private_root"] = str(private)
    report["cleanup"] = {"databases_dropped": len(created_dbs), "private_fixture_removed": not args.keep_private}
    report["denominator"] = {"total": len(report["checks"]), "passed": sum(item["status"] == "PASS" for item in report["checks"]), "failed": sum(item["status"] == "FAIL" for item in report["checks"]), "not_run": 1, "inconclusive": int(report["status"] == "INCONCLUSIVE")}
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL"))
    parser.add_argument("--fixture-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--max-fixture-bytes", type=int, default=MAX_DEFAULT_FIXTURE_BYTES)
    parser.add_argument("--rto-threshold-seconds", type=float, default=30.0)
    parser.add_argument("--watermark-events", type=int, default=8)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    parser.add_argument("--private-root", type=Path, default=Path("/tmp"))
    parser.add_argument("--keep-private", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "qualification": report["qualification"], "denominator": report["denominator"]}))
    return 0 if report["status"] in {"PASS", "NOT_RUN"} else 20


if __name__ == "__main__":
    raise SystemExit(main())
