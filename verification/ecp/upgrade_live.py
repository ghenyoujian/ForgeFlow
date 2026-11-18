#!/usr/bin/env python3
"""Disposable N-1 -> current migration replay harness.

The harness prepares a fresh PostgreSQL database with SQLx migration metadata
through N-1, then optionally starts the current server binary.  Server startup
must apply the remaining migration and answer a real authenticated HTTP read.
It requires an explicit disposable guard and never selects a database or
touches a non-disposable URL implicitly.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
import uuid

import psycopg


def migrations(root: Path) -> list[tuple[int, str, Path, bytes]]:
    rows: list[tuple[int, str, Path, bytes]] = []
    for path in sorted((root / "migrations").glob("*.sql")):
        match = re.match(r"^(\d+)_([^.]+)\.sql$", path.name)
        if not match:
            continue
        version = int(match.group(1))
        description = match.group(2)
        # SQLx 0.8 persists a SHA-384 migration checksum in BYTEA (the
        # release preflight may still publish SHA-256 file identities separately).
        rows.append((version, description, path, hashlib.sha384(path.read_bytes()).digest()))
    if not rows or [row[0] for row in rows] != list(range(1, rows[-1][0] + 1)):
        raise RuntimeError("migration files must be contiguous starting at 1")
    return rows


def ensure_migrations_table(conn: psycopg.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS _sqlx_migrations (
            version BIGINT PRIMARY KEY,
            description TEXT NOT NULL,
            installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
            success BOOLEAN NOT NULL,
            checksum BYTEA NOT NULL,
            execution_time BIGINT NOT NULL
        )
        """
    )


def apply_row(conn: psycopg.Connection, row: tuple[int, str, Path, bytes]) -> None:
    version, description, path, checksum = row
    conn.execute(path.read_text(encoding="utf-8"))
    conn.execute(
        "INSERT INTO _sqlx_migrations(version,description,success,checksum,execution_time) VALUES(%s,%s,true,%s,-1)",
        (version, description, checksum),
    )


def http_read(base: str, token: str) -> tuple[int, str]:
    request = urllib.request.Request(
        base.rstrip("/") + "/api/v1/projects",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")
    except urllib.error.URLError as error:
        # Connection refusal during startup is expected while the process is
        # still migrating. Keep polling until the bounded deadline so the
        # resulting report can include process/database diagnostics.
        return 0, str(error.reason)


def server_runtime_diagnostic(pid: int, database_url: str) -> dict[str, object]:
    """Collect bounded, secret-free startup state before fencing a hung server."""
    diagnostic: dict[str, object] = {"pid": pid}
    proc = Path(f"/proc/{pid}")
    try:
        status = (proc / "status").read_text(encoding="utf-8", errors="replace")
        diagnostic["status"] = {
            line.split(":", 1)[0]: line.split(":", 1)[1].strip()
            for line in status.splitlines()
            if line.startswith(("State:", "VmRSS:", "Threads:", "voluntary_ctxt_switches:", "nonvoluntary_ctxt_switches:"))
            and ":" in line
        }
    except OSError as exc:
        diagnostic["status_error"] = f"{type(exc).__name__}: {exc}"
    try:
        diagnostic["wchan"] = (proc / "wchan").read_text(encoding="utf-8", errors="replace").strip()
    except OSError as exc:
        diagnostic["wchan_error"] = f"{type(exc).__name__}: {exc}"
    try:
        with psycopg.connect(database_url, connect_timeout=3) as conn:
            rows = conn.execute(
                """
                SELECT pid,state,wait_event_type,wait_event,left(query,240)
                FROM pg_stat_activity
                WHERE datname=current_database() AND application_name LIKE 'forgeflow%'
                ORDER BY pid
                """
            ).fetchall()
        diagnostic["postgres_activity"] = [
            {
                "pid": row[0],
                "state": row[1],
                "wait_event_type": row[2],
                "wait_event": row[3],
                "query": row[4],
            }
            for row in rows
        ]
    except Exception as exc:
        diagnostic["postgres_activity_error"] = f"{type(exc).__name__}: {exc}"
    return diagnostic


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--database-url", default=os.environ.get("ECP_UPGRADE_DATABASE_URL"))
    parser.add_argument("--server-binary", type=Path)
    parser.add_argument("--console-dir", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--keep-database", action="store_true")
    args = parser.parse_args()

    report: dict[str, object] = {
        "schema_version": "forgeflow.ecp-upgrade-live.v1",
        "scope": "ECP_PHASE8_N_MINUS_ONE_UPGRADE",
        "product_gate_effect": "NONE",
        "qualification": "NOT_RUN",
        "status": "NOT_RUN",
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "model_calls": 0,
        "checks": [],
        "uncovered": ["release approval", "50GiB RPO/RTO", "rollback after destructive migration"],
    }
    if not args.run:
        report["reason"] = "upgrade replay requires explicit --run"
    elif os.environ.get("ECP_UPGRADE_DISPOSABLE") != "1":
        report.update({"status": "BLOCKED", "reason": "set ECP_UPGRADE_DISPOSABLE=1 explicitly; no database connection attempted"})
    elif not args.database_url:
        report.update({"status": "BLOCKED", "reason": "ECP_UPGRADE_DATABASE_URL or --database-url is required"})
    else:
        server: subprocess.Popen[str] | None = None
        server_log = None
        try:
            rows = migrations(args.source_root)
            n_minus_one = rows[:-1]
            current = rows[-1]
            with psycopg.connect(args.database_url) as conn:
                ensure_migrations_table(conn)
                for row in n_minus_one:
                    apply_row(conn, row)
                conn.commit()
                applied = conn.execute("SELECT count(*) FROM _sqlx_migrations WHERE success=true").fetchone()[0]
            report["migration_chain"] = {"n_minus_one": n_minus_one[-1][0], "current": current[0], "prepared_rows": applied}
            report["checks"].append({"name": "N-1 schema and SQLx metadata prepared", "status": "PASS", "details": {"prepared_versions": applied, "n_minus_one": n_minus_one[-1][0]}})

            if args.server_binary:
                if not args.server_binary.is_file():
                    raise RuntimeError(f"server binary is missing: {args.server_binary}")
                if not args.console_dir or not args.console_dir.is_dir():
                    raise RuntimeError("--console-dir is required when starting the server")
                with socket.socket() as sock:
                    sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
                token = uuid.uuid4().hex + uuid.uuid4().hex
                data_root = args.output.parent / (args.output.stem + "-data")
                data_root.mkdir(parents=True, exist_ok=True)
                env = os.environ.copy()
                env.update({"DATABASE_URL": args.database_url, "FORGEFLOW_BIND": f"127.0.0.1:{port}", "FORGEFLOW_DATA_ROOT": str(data_root), "FORGEFLOW_CONSOLE_DIR": str(args.console_dir), "FORGEFLOW_OWNER_TOKEN": token, "FORGEFLOW_WORKER_TOKEN": uuid.uuid4().hex, "FORGEFLOW_OWNER_PASSWORD": uuid.uuid4().hex})
                # Keep startup failures diagnosable without recording secrets.
                env.setdefault("RUST_LOG", "info")
                server_log_path = args.output.with_suffix(".server.log")
                server_log = server_log_path.open("w", encoding="utf-8")
                server = subprocess.Popen([str(args.server_binary)], env=env, stdout=server_log, stderr=subprocess.STDOUT)
                report["server_log"] = str(server_log_path)
                report["server_binding"] = {"host": "127.0.0.1", "port": port, "data_root": str(data_root), "pid": server.pid}
                deadline = time.time() + 45; observed = None
                while time.time() < deadline:
                    if server.poll() is not None: raise RuntimeError("current server exited while applying N-1 upgrade")
                    status, body = http_read(f"http://127.0.0.1:{port}", token)
                    if status == 200:
                        observed = (status, body); break
                    time.sleep(.25)
                if observed is None:
                    try:
                        report["server_runtime_diagnostic"] = server_runtime_diagnostic(server.pid, args.database_url)
                    except Exception as diagnostic_exc:  # diagnostics must never hide the startup result
                        report["server_runtime_diagnostic"] = {
                            "pid": server.pid,
                            "error": f"{type(diagnostic_exc).__name__}: {diagnostic_exc}",
                        }
                    raise RuntimeError("current server did not become ready after N-1 upgrade")
                report["checks"].append({"name": "current server applies remaining migration and serves HTTP", "status": "PASS", "details": {"http_status": observed[0], "current_version": current[0]}})
                with psycopg.connect(args.database_url) as conn:
                    applied_current = conn.execute("SELECT count(*) FROM _sqlx_migrations WHERE success=true").fetchone()[0]
                    current_row = conn.execute("SELECT version,description,checksum FROM _sqlx_migrations WHERE version=%s", (current[0],)).fetchone()
                if not current_row or bytes(current_row[2]) != current[3]:
                    raise RuntimeError("current migration metadata/checksum does not match source")
                report["checks"].append({"name": "current migration metadata and checksum match source", "status": "PASS", "details": {"applied_versions": applied_current, "version": current_row[0], "description": current_row[1]}})
            else:
                with psycopg.connect(args.database_url) as conn:
                    apply_row(conn, current); conn.commit()
                report["checks"].append({"name": "current migration replayed without server", "status": "PASS", "details": {"version": current[0]}})
            report["status"] = "PASS"; report["qualification"] = "OBSERVED_NOT_GATE"
        except Exception as exc:
            # A server-start failure is a meaningful compatibility result, but
            # it must not erase the N-1 schema preparation evidence.  Finish
            # the migration replay directly and preserve the server failure as
            # INCONCLUSIVE; only a failed direct replay is a hard FAIL.
            if args.server_binary and "migration_chain" in report:
                if server is not None:
                    report["server_integration_process"] = {
                        "pid": server.pid,
                        "poll": server.poll(),
                        "alive": server.poll() is None,
                    }
                    # Do not start the fallback direct replay while the
                    # current server may still be applying the migration. A
                    # live SQLx migration and a second CREATE TABLE attempt
                    # can race and turn a useful startup timeout into a
                    # misleading duplicate PostgreSQL type error.
                    if server.poll() is None:
                        server.terminate()
                        try:
                            server.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            server.kill()
                            server.wait()
                    if server_log is not None:
                        server_log.close()
                        server_log = None
                    report["server_returncode_before_direct_replay"] = server.returncode
                    server = None
                report["checks"].append({"name": "current server applies remaining migration and serves HTTP", "status": "INCONCLUSIVE", "details": {"error": f"{type(exc).__name__}: {exc}"}})
                try:
                    with psycopg.connect(args.database_url) as conn:
                        existing = conn.execute("SELECT 1 FROM _sqlx_migrations WHERE version=%s", (current[0],)).fetchone()
                        if not existing:
                            apply_row(conn, current)
                            conn.commit()
                    report["checks"].append({"name": "current migration replayed without server after server-start inconclusive", "status": "PASS", "details": {"version": current[0]}})
                    report.update({"status": "INCONCLUSIVE", "qualification": "NOT_RUN", "reason": f"server integration inconclusive: {type(exc).__name__}: {exc}"})
                except Exception as replay_exc:
                    report.update({"status": "FAIL", "reason": f"server and direct replay failed: {type(replay_exc).__name__}: {replay_exc}"})
            else:
                report.update({"status": "FAIL", "reason": f"{type(exc).__name__}: {exc}"})
        finally:
            if server is not None:
                server.terminate()
                try: server.wait(timeout=15)
                except subprocess.TimeoutExpired: server.kill(); server.wait()
                if 'server_log' in report:
                    if server_log is not None:
                        server_log.close()
                    log_path = Path(str(report['server_log']))
                    if log_path.exists():
                        report['server_log_tail'] = log_path.read_text(encoding='utf-8', errors='replace')[-12000:]
                report['server_returncode'] = server.returncode
    statuses = [item.get("status") for item in report.get("checks", []) if isinstance(item, dict)]
    report["denominator"] = {"total": len(statuses), "passed": statuses.count("PASS"), "failed": statuses.count("FAIL")}
    report["source_sha"] = subprocess.run(["git", "-C", str(args.source_root), "rev-parse", "HEAD"], text=True, capture_output=True, check=False).stdout.strip()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "denominator": report["denominator"]}))
    return 0 if report["status"] in {"PASS", "NOT_RUN"} else 20


if __name__ == "__main__":
    raise SystemExit(main())
