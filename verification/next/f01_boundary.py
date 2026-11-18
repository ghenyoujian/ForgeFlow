#!/usr/bin/env python3
"""Independent F01 canaries. Default: create isolated fixtures, no HTTP or model call.

Only --base-url enables POST /api/v1/project-probes. The caller must provide an
isolated server; this script does not start services or databases. It never reads
real project content. All generated repositories and executable canaries are
inside one newly created directory. No existing directory is deleted.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

SCHEMA = "forgeflow.next.f01-boundary.v1"
GIT = Path("/usr/bin/git")
MAX_HTTP_BYTES = 1024 * 1024


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def inside(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    if not resolved.is_relative_to(root) or resolved == root:
        raise ValueError("fixture path must remain below its generated root")
    return resolved


class Suite:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.commands: list[dict] = []
        self.fixtures: list[dict] = []
        self.legacy: list[dict] = []
        self.env = {
            "PATH": "/usr/bin:/bin", "HOME": str(self.root / "home"),
            "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_COUNT": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }

    def git(self, root: Path, *args: str, check: bool = True) -> str:
        argv = [str(GIT), "-C", str(root), *args]
        start = time.monotonic()
        result = subprocess.run(argv, env=self.env, capture_output=True, timeout=12)
        self.commands.append({"argv": argv, "exit_code": result.returncode,
                              "elapsed_seconds": round(time.monotonic() - start, 6),
                              "stdout": result.stdout.decode("utf-8", "replace"),
                              "stderr": result.stderr.decode("utf-8", "replace")})
        if check and result.returncode:
            raise RuntimeError("isolated Git fixture command failed; see commands.json")
        return result.stdout.decode("utf-8", "replace").strip()

    def repo(self, name: str, attributes: bool = False) -> tuple[Path, str]:
        root = self.root / name
        root.mkdir()
        self.git(root, "init", "--initial-branch=main")
        self.git(root, "config", "user.name", "Independent F01 QA")
        self.git(root, "config", "user.email", "f01@example.test")
        (root / "tracked.txt").write_text("old\n")
        (root / ".gitignore").write_text("ignored.txt\n")
        if attributes:
            (root / ".gitattributes").write_text("tracked.txt filter=a10canary\n")
        self.git(root, "add", "--all")
        self.git(root, "-c", "core.hooksPath=/dev/null", "commit", "-m", "isolated F01 fixture")
        return root, self.git(root, "rev-parse", "HEAD")

    def canary(self, name: str, mode: str = "fsmonitor") -> tuple[Path, Path]:
        script, marker = self.root / "canaries" / name, self.root / "markers" / name
        tail = {"fsmonitor": "printf '\\0'\n", "clean": "/bin/cat\n", "process": "exit 1\n", "git": "exit 97\n"}[mode]
        script.write_text("#!/bin/sh\nprintf '%s\\n' 'F01_ISOLATED_CANARY' > " + shlex.quote(str(marker)) + "\n" + tail)
        script.chmod(0o700)
        return script, marker

    def add(self, name: str, repo: Path, expected: dict, marker: Path | None = None) -> None:
        self.fixtures.append({"id": name, "root_path": str(repo), "expected_data": expected,
                              "marker": str(marker) if marker else None})

    def preserve_legacy(self, name: str, marker: Path, repo: Path, *args: str) -> None:
        self.git(repo, *args, check=False)
        triggered = marker.is_file()
        saved = None
        if triggered:
            saved = self.root / "legacy-evidence" / (name + ".marker")
            marker.rename(saved)
        self.legacy.append({"id": name, "status": "VERIFIED" if triggered else "FAILED",
                            "claim": "unprotected Git command executed only the isolated marker canary",
                            "marker_saved_at": str(saved) if saved else None,
                            "marker_sha256": sha(saved) if saved else None,
                            "command_index": len(self.commands) - 1})

    def prepare(self) -> dict:
        for folder in ["home", "canaries", "markers", "legacy-evidence", "fake-bin"]:
            (self.root / folder).mkdir()
        clean, head = self.repo("ordinary-clean")
        (clean / "ignored.txt").write_text("ignored only by repository policy\n")
        self.add("ordinary-clean", clean, {"git_repository": True, "bare": False, "head": head, "main_sha": head, "branch": "main", "dirty": False})
        dirty, dh = self.repo("ordinary-dirty")
        (dirty / "tracked.txt").write_text("new\n")  # same byte count, different content
        (dirty / "untracked.txt").write_text("visible untracked\n")
        self.add("ordinary-dirty", dirty, {"git_repository": True, "bare": False, "head": dh, "branch": "main", "dirty": True})
        bare = self.root / "canonical.git"
        self.git(self.root, "clone", "--bare", str(clean), str(bare))
        self.add("bare", bare, {"git_repository": True, "bare": True, "head": head, "branch": "main", "dirty": False})
        linked = self.root / "linked"
        self.git(clean, "worktree", "add", "-b", "a10-linked", str(linked))
        self.add("linked", linked, {"git_repository": True, "bare": False, "head": head, "main_sha": head, "branch": "a10-linked", "dirty": False})
        fsrepo, fh = self.repo("local-fsmonitor")
        hook, marker = self.canary("fsmonitor")
        self.git(fsrepo, "config", "core.fsmonitor", str(hook))
        self.preserve_legacy("old-fsmonitor", marker, fsrepo, "status", "--porcelain")
        self.add("local-fsmonitor", fsrepo, {"git_repository": True, "head": fh, "dirty": False}, marker)
        filt, ch = self.repo("local-clean-filter", attributes=True)
        hook, marker = self.canary("clean-filter", "clean")
        self.git(filt, "config", "filter.a10canary.clean", str(hook))
        (filt / "tracked.txt").write_text("new\n")
        self.preserve_legacy("old-clean-filter", marker, filt, "-c", "core.fsmonitor=false", "status", "--porcelain")
        self.add("local-clean-filter", filt, {"git_repository": True, "head": ch, "dirty": None}, marker)
        proc, ph = self.repo("local-process-filter", attributes=True)
        hook, marker = self.canary("process-filter", "process")
        self.git(proc, "config", "filter.a10canary.process", str(hook))
        (proc / "tracked.txt").write_text("new\n")
        self.preserve_legacy("old-process-filter", marker, proc, "status", "--porcelain")
        self.add("local-process-filter", proc, {"git_repository": True, "head": ph, "dirty": None}, marker)
        inc, _ = self.repo("local-include")
        hook, marker = self.canary("included-fsmonitor")
        config = self.root / "included.config"
        config.write_text("[core]\n fsmonitor = " + json.dumps(str(hook)) + "\n")
        self.git(inc, "config", "include.path", str(config))
        self.preserve_legacy("old-included-fsmonitor", marker, inc, "status", "--porcelain")
        self.add("local-include", inc, {"git_repository": False, "head": None, "dirty": None}, marker)
        alt, _ = self.repo("local-alternates")
        # A real but independent object store; API must reject, not silently use it.
        (alt / ".git/objects/info/alternates").write_text(str(bare / "objects") + "\n")
        self.add("local-alternates", alt, {"git_repository": False, "head": None, "dirty": None})
        sym, _ = self.repo("metadata-symlink")
        original = sym / ".git/config"
        saved = self.root / "symlink-target.config"
        original.rename(saved)
        original.symlink_to(saved)
        self.add("metadata-symlink", sym, {"git_repository": False, "head": None, "dirty": None})
        host_hook, host_marker = self.canary("host-config-fsmonitor")
        host_config = self.root / "host.config"
        host_config.write_text("[core]\n fsmonitor = " + json.dumps(str(host_hook)) + "\n")
        fake, path_marker = self.canary("path-git", "git")
        shutil.copyfile(fake, self.root / "fake-bin/git")
        (self.root / "fake-bin/git").chmod(0o700)
        host_attrs = self.root / "host.attributes"
        host_attrs.write_text("* filter=hostattack\n")
        expected_env = {
            "PATH": str(self.root / "fake-bin") + ":/usr/bin:/bin",
            "HOME": str(self.root / "home"), "XDG_CONFIG_HOME": str(self.root / "home"),
            "GIT_DIR": str(bare), "GIT_COMMON_DIR": str(bare), "GIT_WORK_TREE": str(dirty),
            "GIT_INDEX_FILE": str(self.root / "host-index-do-not-create"),
            "GIT_OBJECT_DIRECTORY": str(bare / "objects"),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(bare / "objects"),
            "GIT_CONFIG_SYSTEM": str(host_config), "GIT_CONFIG_GLOBAL": str(host_config),
            "GIT_CONFIG_NOSYSTEM": "0", "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "core.fsmonitor", "GIT_CONFIG_VALUE_0": str(host_hook),
            "GIT_CONFIG_KEY_1": "core.attributesFile", "GIT_CONFIG_VALUE_1": str(host_attrs),
            "GIT_CONFIG_PARAMETERS": "'core.fsmonitor=" + str(host_hook) + "'",
            "GIT_NAMESPACE": "a10-host-namespace", "GIT_EXTERNAL_DIFF": str(host_hook),
        }
        write_json(self.root / "server-environment.json", expected_env)
        return {"schema_version": SCHEMA, "suite_id": self.root.name,
                "generated_at_unix": time.time(), "fixture_root": str(self.root),
                "fixtures": self.fixtures, "legacy_counterexamples": self.legacy,
                "host_markers": [str(host_marker), str(path_marker)],
                "server_environment_file": str(self.root / "server-environment.json"),
                "environment_test": "NOT_RUN until the isolated server itself inherits these values and --server-pid proves them"}


def metadata_state(root: Path) -> dict:
    """Hash finite metadata/tracked fixture paths without executing Git/filter hooks."""
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            result[str(path.relative_to(root))] = {"symlink": os.readlink(path)}
        elif path.is_file():
            result[str(path.relative_to(root))] = {"sha256": sha(path), "bytes": path.stat().st_size}
    return result


def origin(value: str) -> tuple[str, int]:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "http" or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ValueError("--base-url must be an explicit http loopback origin without path/credentials/query")
    host = parsed.hostname or ""
    if host == "localhost":
        host = "127.0.0.1"  # do not rely on DNS or a changed hosts file
    if not ipaddress.ip_address(host).is_loopback:
        raise ValueError("API requests require a numeric loopback host or localhost")
    port = parsed.port
    if port is None or port == 8787:
        raise ValueError("an explicit isolated port is required; production port 8787 is forbidden")
    authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    return "http://" + authority, port


def private_token(path: Path) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 8192:
            raise ValueError("token file must be a private regular file owned by the current user, at most 8192 bytes")
        token = stream.read(8193).decode("utf-8").strip()
    if not token or any(c.isspace() or ord(c) < 32 for c in token):
        raise ValueError("token file must contain only one nonempty bearer token")
    return token


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def server_proof(pid: int | None, port: int, expected: dict) -> dict:
    if pid is None:
        return {"status": "NOT_RUN", "reason": "no server PID supplied; client environment does not prove server environment injection"}
    proc = Path("/proc") / str(pid)
    raw = (proc / "environ").read_bytes()
    env = dict(item.split(b"=", 1) for item in raw.split(b"\0") if b"=" in item)
    matched = {key: env.get(key.encode()) == value.encode() for key, value in expected.items()}
    owned = set()
    for fd in (proc / "fd").iterdir():
        try:
            owned.add(os.readlink(fd))
        except FileNotFoundError:
            continue  # a server may close an unrelated connection while observed
    listening = False
    for network in ["tcp", "tcp6"]:
        for line in (proc / "net" / network).read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) > 9 and fields[3] == "0A" and int(fields[1].split(":")[1], 16) == port:
                listening |= "socket:[" + fields[9] + "]" in owned
    return {"status": "VERIFIED" if all(matched.values()) and listening else "FAILED",
            "pid": pid, "owns_requested_listening_port": listening,
            "matched_injected_environment_keys": matched,
            "server_executable_sha256": sha(proc / "exe"),
            "claim": "allowlisted injected variables match actual server process, which owns the requested listening socket; no other environment values exported"}


def load_manifest(path: Path) -> tuple[dict, Path]:
    manifest = json.loads(path.read_text())
    root = Path(manifest["fixture_root"]).resolve()
    if manifest.get("schema_version") != SCHEMA or path.resolve() != root / "fixture-manifest.json":
        raise ValueError("not a generated F01 fixture manifest")
    sentinel = json.loads((root / "suite-identity.json").read_text())
    if sentinel.get("suite_id") != manifest["suite_id"]:
        raise ValueError("fixture suite identity mismatch")
    for fixture in manifest["fixtures"]:
        inside(Path(fixture["root_path"]), root)
        if fixture["marker"]:
            inside(Path(fixture["marker"]), root)
    for marker in manifest["host_markers"]:
        inside(Path(marker), root)
    inside(Path(manifest["server_environment_file"]), root)
    return manifest, root


def api_checks(manifest: dict, root: Path, base_url: str, token_file: Path, pid: int | None) -> dict:
    base, port = origin(base_url)
    token = private_token(token_file)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    expected_env = json.loads(Path(manifest["server_environment_file"]).read_text())
    proof = server_proof(pid, port, expected_env)
    before = metadata_state(root)
    cases = []
    for fixture in manifest["fixtures"]:
        markers = manifest["host_markers"] + ([fixture["marker"]] if fixture["marker"] else [])
        preexisting = [p for p in markers if Path(p).exists()]
        if preexisting:
            cases.append({"id": fixture["id"], "status": "INCONCLUSIVE", "reason": "canary already existed before this API call; preserved without deleting"})
            continue
        body = json.dumps({"root_path": fixture["root_path"]}).encode()
        request = urllib.request.Request(base + "/api/v1/project-probes", data=body, method="POST", headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
        started = time.monotonic()
        status, response = None, b""
        transport_error = None
        try:
            with opener.open(request, timeout=35) as connection:
                status = connection.status
                response = connection.read(MAX_HTTP_BYTES + 1)
        except urllib.error.HTTPError as error:
            status = error.code
            response = error.read(MAX_HTTP_BYTES + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            # Do not export exception repr or request headers (bearer credential).
            transport_error = type(error).__name__
        safe_text = response[:MAX_HTTP_BYTES].decode("utf-8", "replace").replace(token, "<REDACTED>")
        try:
            payload = json.loads(safe_text)
        except ValueError:
            payload = None
        data = payload.get("data") if isinstance(payload, dict) else None
        comparisons = {key: isinstance(data, dict) and key in data and data[key] == value for key, value in fixture["expected_data"].items()}
        triggered = [p for p in markers if Path(p).exists()]
        passed = status == 200 and len(response) <= MAX_HTTP_BYTES and all(comparisons.values()) and not triggered
        cases.append({"id": fixture["id"], "status": "VERIFIED" if passed else "FAILED", "method": "POST", "route": "/api/v1/project-probes", "root_path": fixture["root_path"], "http_status": status, "elapsed_seconds": round(time.monotonic() - started, 6), "response": payload if payload is not None else safe_text, "transport_error": transport_error, "expected_comparisons": comparisons, "triggered_canaries": triggered})
    after = metadata_state(root)
    changed = [key for key in sorted(set(before) | set(after)) if before.get(key) != after.get(key)]
    good = sum(case["status"] == "VERIFIED" for case in cases)
    status = "FAILED" if good != len(cases) or changed or proof["status"] == "FAILED" else "VERIFIED" if proof["status"] == "VERIFIED" else "PARTIAL"
    return {"schema_version": SCHEMA, "status": status, "origin": base, "server_environment_injection": proof, "denominator": len(cases), "verified": good, "cases": cases, "all_fixture_bytes_unchanged": not changed, "changed_fixture_paths": changed, "metadata_before_sha256": hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(), "metadata_after_sha256": hashlib.sha256(json.dumps(after, sort_keys=True).encode()).hexdigest(), "scope": "isolated project-probes canaries and actual returned repository facts only; no project create/import, model, DB write, full execution or production qualification"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-parent", type=Path, help="existing parent for a NEW unique suite (default: system temp)")
    parser.add_argument("--fixture-manifest", type=Path, help="reuse this generated suite for explicit API validation; no fixture modifications")
    parser.add_argument("--base-url", help="explicit isolated http loopback origin; no default; port 8787 refused")
    parser.add_argument("--token-file", type=Path, help="owner bearer token in a private regular file; never printed")
    parser.add_argument("--server-pid", type=int, help="optional actual isolated server PID for /proc environment and listening-socket proof")
    args = parser.parse_args()
    if bool(args.base_url) != bool(args.token_file) or args.server_pid and not args.base_url:
        parser.error("--base-url and --token-file must be supplied together; --server-pid requires them")
    if args.base_url:
        origin(args.base_url)  # reject production/nonloopback before any fixture creation or HTTP
    if args.fixture_manifest:
        manifest, root = load_manifest(args.fixture_manifest)
    else:
        if not GIT.is_file():
            raise ValueError("trusted /usr/bin/git is required")
        parent = args.output_parent.resolve() if args.output_parent else None
        root = Path(tempfile.mkdtemp(prefix="forgeflow-f01-a10-", dir=parent))
        root.chmod(0o700)
        write_json(root / "suite-identity.json", {"suite_id": root.name, "schema_version": SCHEMA})
        suite = Suite(root)
        try:
            manifest = suite.prepare()
            manifest["git_binary"] = {"path": str(GIT), "sha256": sha(GIT), "version": suite.git(root, "--version")}
        finally:
            write_json(root / "commands.json", suite.commands)
        source_root = Path(__file__).resolve().parents[2]
        finite_sources = [Path(__file__).resolve(), source_root / "crates/git/src/safe_probe.rs", source_root / "crates/git/src/lib.rs", source_root / "crates/api/src/catalog.rs", source_root / "crates/api/src/lib.rs"]
        manifest["source_fingerprints"] = [{"path": str(p), "sha256": sha(p)} for p in finite_sources if p.is_file()]
        write_json(root / "fixture-manifest.json", manifest)
    legacy_passed = all(case["status"] == "VERIFIED" for case in manifest["legacy_counterexamples"])
    if args.base_url:
        report = api_checks(manifest, root, args.base_url, args.token_file, args.server_pid)
        result_path = root / ("api-result-" + uuid.uuid4().hex[:12] + ".json")
        write_json(result_path, report)
        print(json.dumps({"fixture_manifest": str(root / "fixture-manifest.json"), "api_result": str(result_path), "status": report["status"], "verified": report["verified"], "denominator": report["denominator"], "legacy_counterexamples_reproduced": legacy_passed}, ensure_ascii=False))
        return 0 if report["status"] in ("VERIFIED", "PARTIAL") and legacy_passed else 1
    print(json.dumps({"fixture_manifest": str(root / "fixture-manifest.json"), "api_status": "NOT_RUN", "network_requests": 0, "fixtures": len(manifest["fixtures"]), "legacy_counterexamples_reproduced": legacy_passed, "server_environment_file": manifest["server_environment_file"]}, ensure_ascii=False))
    return 0 if legacy_passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        # Errors never include parsed credential values, HTTP headers, or a dump of environment.
        print(json.dumps({"status": "FAILED", "error_type": type(error).__name__, "detail": str(error) if isinstance(error, ValueError) else "isolated boundary harness failed; preserve its temporary evidence"}), file=sys.stderr)
        raise SystemExit(2)
