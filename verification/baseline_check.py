#!/usr/bin/env python3
"""Independent actual identity checks for G00; no capacity extrapolation."""
import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))
from metrics import hardware


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(args):
    import psycopg
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    build_path = Path(args.build_receipt)
    build = json.loads(build_path.read_text())
    archive = Path(__file__).resolve().parents[2] / "archive/forgeflow-python-baseline.tar.gz"
    baseline = json.loads((Path(__file__).resolve().parents[1] / "benchmarks/evidence/python-baseline.json").read_text())
    private = json.loads(Path(args.private_env).read_text())
    binding_path = Path(private["FORGEFLOW_DATA_ROOT"]) / "attempts" / args.native_attempt / "execution-bindings.json"
    profile = json.loads(binding_path.read_text())["executor_profile"]
    checks = []
    def check(name, value, facts):
        checks.append({"name": name, "status": "PASS" if value else "FAIL", "facts": facts})
    copy_errors = [p for p, wanted in build["source_files"].items()
        if not (Path(build["snapshot_root"]) / p).is_file() or sha(Path(build["snapshot_root"]) / p) != wanted]
    calculated = hashlib.sha256(json.dumps(build["source_files"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    check("immutable_source_snapshot_identity", not copy_errors and calculated == build["source_identity"] and build["consistent_copy"],
          {"source_identity": calculated, "files": len(build["source_files"]), "mismatches": copy_errors})
    binary_errors = [name for name, pin in build["binaries"].items() if sha(pin["path"]) != pin["sha256"]]
    check("actual_frozen_rust_binary_identities", not binary_errors, {"binaries": build["binaries"], "mismatches": binary_errors})
    check("preserved_python_archive_identity", sha(archive) == baseline["archive_sha256"], {"path": str(archive), "sha256": sha(archive)})
    machine = hardware()
    check("actual_toolchain_os_machine_profile", bool(machine["rustc"] and machine["cargo"] and machine["git"] and machine["cpuinfo"] and machine["meminfo"]), {"profile": machine})
    with psycopg.connect(private["DATABASE_URL"]) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT version(),current_database(),current_setting('server_version'),current_setting('max_connections'),current_setting('shared_buffers')")
            version, database, server_version, max_connections, shared_buffers = cursor.fetchone()
            cursor.execute("SELECT version,description,success FROM _sqlx_migrations ORDER BY version")
            migrations = cursor.fetchall()
    database_identity = {"version": version, "database": database, "server_version": server_version,
        "max_connections": max_connections, "shared_buffers": shared_buffers, "migrations": migrations,
        "private_configuration_path": str(Path(args.private_env).resolve()), "credential_values_disclosed": False}
    check("actual_postgresql_runtime_and_schema_identity", bool(version and migrations) and all(row[2] for row in migrations), database_identity)
    pin_errors = [p["path"] for p in profile["artifact_pins"] if not Path(p["path"]).is_file() or sha(p["path"]) != p["sha256"]]
    check("loaded_actual_native_profile_content_pins", not pin_errors and profile["id"] != "controlled-lightweight.v1", {"id": profile["id"], "pins": len(profile["artifact_pins"]), "mismatches": pin_errors, "binding_sha256": sha(binding_path)})
    command = [profile["program"], *profile["prefix_args"], "--profile", profile["profile_name"], "--help"]
    environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": profile["home"], "DSH_HOME": profile["home"], "LANG": "C.UTF-8"}
    result = subprocess.run(command, env=environment, capture_output=True, timeout=30)
    (output / "headless-help.stdout").write_bytes(result.stdout)
    (output / "headless-help.stderr").write_bytes(result.stderr)
    text = result.stdout.decode(errors="replace")
    check("actual_headless_protocol_help_probe", result.returncode == 0 and "--json" in text and "--session-id" in text,
        {"command": command, "exit_code": result.returncode, "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(), "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(), "model_request_invoked": False})
    profile_copy = output / "loaded-native-profile.json"
    profile_copy.write_text(json.dumps(profile, indent=2) + "\n")
    worktree = json.loads((binding_path.parent / "worktree.json").read_text())["worktree"]["absolute_path"]
    doctor_command = [build["binaries"]["forgeflow"]["path"], "executor", "doctor", "--profile-json", str(profile_copy), "--workspace", worktree]
    doctor_run = subprocess.run(doctor_command, capture_output=True, timeout=30)
    (output / "native-doctor.json").write_bytes(doctor_run.stdout)
    (output / "native-doctor.stderr").write_bytes(doctor_run.stderr)
    doctor = json.loads(doctor_run.stdout) if doctor_run.returncode == 0 else {}
    check("actual_frozen_rust_executor_doctor_receipt", doctor_run.returncode == 0 and doctor.get("executor_profile_id") == profile["id"] and doctor.get("artifact_pins") == profile["artifact_pins"] and doctor.get("stdin_protocol") == "UTF8_PROMPT_EOF",
        {"command": doctor_command, "exit_code": doctor_run.returncode, "stdout_sha256": hashlib.sha256(doctor_run.stdout).hexdigest(), "runtime_unverified_fields_retained": ["credential_resolution", "model_route_resolution", "sandbox_boundary", "session_persistence"]})
    native = json.loads((Path(__file__).with_name("evidence") / "native-g2-independent/report.json").read_text())
    check("actual_native_identity_consumed_by_completed_business_chain", native["status"] == "PASS" and native["attempt_id"] == args.native_attempt,
        {"attempt_id": args.native_attempt, "native_chain_assertions": native["assertions"], "native_chain_report_sha256": sha(Path(__file__).with_name("evidence") / "native-g2-independent/report.json")})
    report = {"schema_version": "forgeflow.verification.baseline.v1", "scope": "G00 actual code/archive/toolchain/DSH/PostgreSQL/machine identities only", "at": datetime.now(timezone.utc).isoformat(), "checks": checks,
        "assertions": len(checks), "failed": sum(c["status"] == "FAIL" for c in checks),
        "limitations": ["full external installed dependency-content inventory remains unverified; lockfile/version/content pins retain their actual scope", "native enforcement direct_observed; complete model inflight and cost unverified", "baseline identity PASS does not qualify real4/10/100 or controlled128/3600", "new source changes require a new immutable build identity"],
        "source_artifacts": [{"path": str(p), "sha256": sha(p)} for p in (build_path, binding_path, Path(__file__))]}
    report["status"] = "FAIL" if report["failed"] else "PASS"
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("status", "assertions", "failed")}))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    for name in ("build-receipt", "private-env", "native-attempt", "output"):
        p.add_argument("--" + name, required=True)
    run(p.parse_args())
