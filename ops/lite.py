#!/usr/bin/env python3
"""Core-only local lifecycle for an installed ForgeFlow directory package.

No Worker, DSH, model gateway, scheduler replacement or autostart installer is
launched here. Task state remains exclusively in the existing Rust Core/PG.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "forgeflow.lite.v1"


class UnsupportedPidfdError(ValueError):
    """No safe pidfd stop is available; ordinary PID signals are forbidden."""


def libc_pidfd_function(name, argument_types):
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        function = getattr(libc, name)
    except AttributeError as error:
        raise UnsupportedPidfdError("safe Lite stop requires Linux libc pidfd support") from error
    function.argtypes = argument_types
    function.restype = ctypes.c_int
    return function


def pidfd_result(result, operation):
    if result < 0:
        error = ctypes.get_errno()
        if error == errno.ENOSYS:
            raise UnsupportedPidfdError("kernel pidfd support is unavailable")
        raise OSError(error, operation + " failed")
    return result


def open_pidfd(pid):
    if hasattr(os, "pidfd_open"):
        try:
            return os.pidfd_open(pid)
        except OSError as error:
            if error.errno == errno.ENOSYS:
                raise UnsupportedPidfdError("kernel pidfd support is unavailable") from error
            raise
    function = libc_pidfd_function("pidfd_open", [ctypes.c_int, ctypes.c_uint])
    return pidfd_result(function(pid, 0), "pidfd_open")


def send_pidfd_signal(descriptor, number):
    if hasattr(signal, "pidfd_send_signal"):
        try:
            signal.pidfd_send_signal(descriptor, number)
            return
        except OSError as error:
            if error.errno == errno.ENOSYS:
                raise UnsupportedPidfdError("kernel pidfd support is unavailable") from error
            raise
    function = libc_pidfd_function("pidfd_send_signal",
                                  [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint])
    pidfd_result(function(descriptor, number, None, 0), "pidfd_send_signal")


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def private_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1048576):
            raise ValueError("configuration/state must be an owned regular mode-0600 file")
        return json.load(stream)


def save_private(path, value, exclusive=False):
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def address(bind):
    parsed = urllib.parse.urlsplit("http://" + bind)
    host, port = parsed.hostname, parsed.port
    if (parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment
            or not host or not port or not ipaddress.ip_address(host).is_loopback):
        raise ValueError("Lite bind must be an explicit numeric loopback host:port")
    return host, port


def configuration(path):
    cfg = private_json(path)
    required = {"schema_version", "release_dir", "database_url", "bind", "data_root",
                "owner_password", "owner_token", "worker_token"}
    if set(cfg) != required or cfg["schema_version"] != SCHEMA:
        raise ValueError("unsupported Lite configuration fields/schema")
    if not all(isinstance(value, str) and value for value in cfg.values()):
        raise ValueError("Lite configuration values must be nonempty strings")
    if Path(cfg["release_dir"]).resolve(strict=True) != ROOT:
        raise ValueError("configuration selects a different installed release")
    address(cfg["bind"])
    parsed = urllib.parse.urlsplit(cfg["database_url"])
    if parsed.scheme not in ("postgres", "postgresql") or not parsed.path.strip("/"):
        raise ValueError("an explicit PostgreSQL database URL is required")
    data = Path(cfg["data_root"])
    if not data.is_absolute() or data.resolve().is_relative_to(ROOT):
        raise ValueError("persistent data must be outside the installed release")
    if len(cfg["owner_password"]) < 12 or min(len(cfg[name]) for name in ("owner_token", "worker_token")) < 24:
        raise ValueError("private credentials are too short")
    if cfg["owner_token"] == cfg["worker_token"]:
        raise ValueError("Owner and unused Worker service credentials must differ")
    return cfg


def verify_installation():
    manifest = json.loads((ROOT / "delivery-manifest.json").read_text())
    if manifest.get("schema_version") != "forgeflow.local-delivery.v1":
        raise ValueError("installed delivery manifest is required")
    required = {"bin/forgeflow-server", "bin/forgeflow", "console/index.html", "ops/lite.py", "build/receipt.json"}
    selected = required | {name for name in manifest["files"] if name.startswith("console/")}
    for name in selected:
        part = Path(name)
        if part.is_absolute() or ".." in part.parts:
            raise ValueError("unsafe installed resource path")
        path = ROOT / name
        if not stat.S_ISREG(path.lstat().st_mode) or digest(path) != manifest["files"][name]["sha256"]:
            raise ValueError("installed executable, helper or console differs from its pin")
    receipt = json.loads((ROOT / "build/receipt.json").read_text())
    if (digest(ROOT / "build/receipt.json") != manifest["build"]["receipt_sha256"]
            or manifest["files"]["bin/forgeflow-server"]["sha256"] != receipt["binaries"]["forgeflow-server"]["sha256"]):
        raise ValueError("server identity differs from original build receipt")
    return manifest["files"]["bin/forgeflow-server"]["sha256"]


def environment(cfg):
    # Do not inherit the caller's gateway, Worker credentials, DSH or restore
    # environment. Starting a fresh Lite Core cannot revive an old executor.
    env = {key: os.environ[key] for key in ("PATH", "HOME", "LANG", "LC_ALL", "TZ") if key in os.environ}
    env.update(DATABASE_URL=cfg["database_url"], FORGEFLOW_BIND=cfg["bind"],
               FORGEFLOW_API_URL="http://" + cfg["bind"],
               FORGEFLOW_DATA_ROOT=cfg["data_root"], FORGEFLOW_CONSOLE_DIR=str(ROOT / "console"),
               FORGEFLOW_OWNER_PASSWORD=cfg["owner_password"], FORGEFLOW_OWNER_TOKEN=cfg["owner_token"],
               FORGEFLOW_WORKER_TOKEN=cfg["worker_token"])
    return env


def pg_environment(cfg):
    # psql does not expand a URI supplied as PGDATABASE. Resolve its individual
    # libpq parameters here, keeping credentials entirely out of argv/output.
    env = {key: os.environ[key] for key in ("PATH", "HOME", "LANG", "LC_ALL") if key in os.environ}
    parsed = urllib.parse.urlsplit(cfg["database_url"])
    values = {"host": urllib.parse.unquote(parsed.hostname or "127.0.0.1"),
              "port": str(parsed.port or 5432),
              "dbname": urllib.parse.unquote(parsed.path.lstrip("/")),
              "connect_timeout": "5"}
    if parsed.username is not None:
        values["user"] = urllib.parse.unquote(parsed.username)
    if parsed.password is not None:
        values["password"] = urllib.parse.unquote(parsed.password)
    for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
        values[key] = value
    parameters = {"host": "PGHOST", "hostaddr": "PGHOSTADDR", "port": "PGPORT",
                  "dbname": "PGDATABASE", "user": "PGUSER", "password": "PGPASSWORD",
                  "connect_timeout": "PGCONNECT_TIMEOUT", "options": "PGOPTIONS",
                  "application_name": "PGAPPNAME", "sslmode": "PGSSLMODE",
                  "sslrootcert": "PGSSLROOTCERT", "sslcert": "PGSSLCERT", "sslkey": "PGSSLKEY",
                  "sslcrl": "PGSSLCRL", "sslcrldir": "PGSSLCRLDIR", "sslsni": "PGSSLSNI",
                  "ssl_min_protocol_version": "PGSSLMINPROTOCOLVERSION",
                  "ssl_max_protocol_version": "PGSSLMAXPROTOCOLVERSION",
                  "channel_binding": "PGCHANNELBINDING", "gssencmode": "PGGSSENCMODE",
                  "krbsrvname": "PGKRBSRVNAME", "target_session_attrs": "PGTARGETSESSIONATTRS",
                  "passfile": "PGPASSFILE"}
    env.update({parameters[key]: value for key, value in values.items() if key in parameters})
    return env


def process_identity(pid):
    try:
        status = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        if status[0] == "Z":
            return None
        info = Path(f"/proc/{pid}/exe").stat()
        return {"pid": pid, "start_ticks": status[19], "exe_device": info.st_dev,
                "exe_inode": info.st_ino, "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}
    except FileNotFoundError:
        return None


def recorded_state(path):
    state_path = path.with_suffix(path.suffix + ".process.json")
    if not state_path.exists():
        return state_path, None, "STOPPED"
    state = private_json(state_path)
    actual = process_identity(state["identity"]["pid"])
    if actual is None:
        return state_path, state, "STOPPED"
    program = (ROOT / "bin/forgeflow-server").stat()
    matches = (actual == state["identity"] and actual["exe_device"] == program.st_dev
               and actual["exe_inode"] == program.st_ino)
    return state_path, state, "RUNNING" if matches else "IDENTITY_MISMATCH"


def request(cfg, route):
    req = urllib.request.Request("http://" + cfg["bind"] + route,
                                 headers={"Authorization": "Bearer " + cfg["owner_token"]})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=2) as response:
        return json.load(response)


def status(path, cfg):
    _, state, current = recorded_state(path)
    healthy = False
    if current == "RUNNING":
        try:
            healthy = request(cfg, "/healthz").get("status") == "ok"
            # A listening service alone is insufficient: also verify our Owner
            # identity so an occupied port cannot be mistaken for this Core.
            healthy = healthy and request(cfg, "/api/v1/me")["data"]["role"] == "owner"
        except (OSError, ValueError, KeyError):
            pass
    return {"status": current, "healthy": healthy, "url": "http://" + cfg["bind"],
            "pid": state["identity"]["pid"] if state and current != "STOPPED" else None,
            "workers_started": 0, "dsh_started": False, "autostart_enabled": False}


def init(args):
    path = args.config
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise ValueError("select an absolute, nonexistent private configuration file")
    address(args.bind)
    if args.database_url_file:
        fd = os.open(args.database_url_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd) as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 16384:
                raise ValueError("database URL file must be a private owned regular file")
            url = stream.read().strip()
    else:
        url = os.environ.get("DATABASE_URL", "")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("postgres", "postgresql") or not parsed.path.strip("/"):
        raise ValueError("supply a PostgreSQL URL through --database-url-file or DATABASE_URL")
    verify_installation()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.resolve().is_relative_to(ROOT):
        raise ValueError("configuration must be outside the installed release")
    cfg = {"schema_version": SCHEMA, "release_dir": str(ROOT), "database_url": url,
           "bind": args.bind, "data_root": str(path.parent / (path.stem + "-data")),
           "owner_password": secrets.token_urlsafe(24), "owner_token": secrets.token_urlsafe(48),
           "worker_token": secrets.token_urlsafe(48)}
    save_private(path, cfg, exclusive=True)
    return {"configuration": str(path), "status": "INITIALIZED", "services_started": False,
            "credentials": "Read the owned mode-0600 configuration locally; secrets are never printed."}


def doctor(cfg):
    pin = verify_installation()
    psql = shutil.which("psql")
    connected = False
    if psql:
        result = subprocess.run([psql, "-X", "--no-password", "-t", "-A", "--set", "ON_ERROR_STOP=1",
                                 "--command", "BEGIN READ ONLY; SELECT 1; ROLLBACK;"],
                                env=pg_environment(cfg), capture_output=True, text=True, timeout=10)
        connected = result.returncode == 0 and "1" in result.stdout.splitlines()
    return {"status": "READY" if connected else "POSTGRES_CHECK_FAILED" if psql else "PSQL_NOT_FOUND",
            "installed_pins_match": True, "server_sha256": pin, "database_read_only_query": connected,
            "core_only": True, "executor_qualification": "NOT_RUN", "autostart_enabled": False}


def up(path, cfg):
    pin = verify_installation()
    state_path, _, current = recorded_state(path)
    if current == "IDENTITY_MISMATCH":
        raise ValueError("recorded process identity differs; inspect it before changing the private process record")
    if current == "RUNNING":
        return status(path, cfg)
    host, port = address(cfg["bind"])
    with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((host, port))
        probe.listen(1)
    data = Path(cfg["data_root"])
    data.mkdir(parents=True, exist_ok=True, mode=0o700)
    log_path = path.with_suffix(path.suffix + ".core.log")
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "ab", buffering=0) as log:
        os.fchmod(log.fileno(), 0o600)
        executable = (ROOT / "bin/forgeflow-server").stat()
        child = subprocess.Popen([str(ROOT / "bin/forgeflow-server")], env=environment(cfg), cwd=ROOT,
                                 stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
    identity = None
    for _ in range(100):
        if child.poll() is not None:
            raise ValueError("Core exited during startup; inspect the private .core.log file")
        observed = process_identity(child.pid)
        if (observed is not None and observed["exe_device"] == executable.st_dev
                and observed["exe_inode"] == executable.st_ino):
            identity = observed
            break
        time.sleep(0.01)
    if identity is None:
        raise ValueError("Core process identity is unconfirmed; inspect the private log/process")
    save_private(state_path, {"identity": identity, "server_sha256": pin, "data_root": cfg["data_root"]})
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise ValueError("Core exited during startup; inspect the private .core.log file")
        observed = status(path, cfg)
        if observed["healthy"]:
            return observed
        time.sleep(0.25)
    return {**status(path, cfg), "startup": "NOT_READY", "instruction": "Inspect private log; down stops only this Core."}


def down(path, cfg):
    _, state, current = recorded_state(path)
    if current == "STOPPED":
        return status(path, cfg)
    if current != "RUNNING":
        raise ValueError("process identity mismatch; no signal was sent")
    # pidfd prevents a PID reuse race between identity verification and signal.
    descriptor = open_pidfd(state["identity"]["pid"])
    try:
        if process_identity(state["identity"]["pid"]) != state["identity"]:
            raise ValueError("process identity changed; no signal was sent")
        send_pidfd_signal(descriptor, signal.SIGTERM)
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            if process_identity(state["identity"]["pid"]) is None:
                return status(path, cfg)
            time.sleep(0.1)
    finally:
        os.close(descriptor)
    return {**status(path, cfg), "stop": "STOP_UNCONFIRMED", "instruction": "Original state retained; no forced kill was sent."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init", "up", "down", "status", "doctor"))
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--database-url-file", type=Path)
    parser.add_argument("--bind", default="127.0.0.1:8787")
    args = parser.parse_args()
    try:
        if args.command == "init":
            result = init(args)
        else:
            if not args.config.is_absolute():
                raise ValueError("configuration path must be absolute")
            cfg = configuration(args.config)
            if args.command in ("up", "down"):
                fd = os.open(args.config.with_suffix(args.config.suffix + ".lock"),
                             os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "w") as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    result = up(args.config, cfg) if args.command == "up" else down(args.config, cfg)
            else:
                result = doctor(cfg) if args.command == "doctor" else status(args.config, cfg)
        print(json.dumps(result, ensure_ascii=False))
        return 0 if (args.command != "doctor" or result["status"] == "READY") and result.get("startup") != "NOT_READY" and result.get("stop") != "STOP_UNCONFIRMED" else 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # Database/password/connection errors may include secrets. Do not echo
        # exception text or child output into public command results.
        print(json.dumps({"status": "ERROR", "error_class": type(error).__name__,
                          "instruction": "Check private config, installation pins, port and .core.log; no credential values are printed."}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
