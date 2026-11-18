#!/usr/bin/env python3
"""Emit build identity without building or publishing artifacts."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
from source_snapshot import DEFAULT_EXCLUDES, build_manifest as source_manifest


def tool_probe_environment() -> dict[str, str]:
    # Tool probes must not inherit shell startup hooks, preload libraries or
    # Node preload flags. Unknown build settings are not treated as attested.
    allowed = {'PATH', 'HOME', 'RUSTUP_HOME', 'CARGO_HOME', 'RUSTUP_TOOLCHAIN',
               'TMPDIR', 'TMP', 'TEMP', 'LANG', 'LC_ALL', 'LC_CTYPE', 'SYSTEMROOT', 'USERPROFILE'}
    return {key: value for key, value in os.environ.items() if key in allowed}


def tool_version(path: Path, root: Path) -> str:
    result = subprocess.run([str(path), "--version"], cwd=root, capture_output=True,
                            env=tool_probe_environment(), text=True, timeout=10, check=False)
    lines = (result.stdout or result.stderr).strip().splitlines()
    if result.returncode != 0 or not lines or not lines[0]:
        raise ValueError('tool version command failed')
    return lines[0]


def executable_identity(name: str, root: Path) -> dict:
    """Observe PATH selection, resolved files and their version, never attest provenance."""
    selected = shutil.which(name)
    if not selected:
        raise ValueError('tool is unavailable')
    selected_path = Path(selected).absolute()
    launcher = selected_path.resolve(strict=True)
    if not launcher.is_file() or not os.access(launcher, os.X_OK):
        raise ValueError('tool launcher is not an executable regular file')
    actual = launcher
    # A rustup shim is not the selected compiler. Ask the same rustup executable
    # in the source directory and compare the dispatched and direct versions.
    rustup = shutil.which('rustup') if name in ('cargo', 'rustc') else None
    rustup_launcher = Path(rustup).resolve(strict=True) if rustup else None
    launcher_is_rustup = launcher.name.lower() in ('rustup', 'rustup.exe')
    is_rustup = (name in ('cargo', 'rustc') and (launcher_is_rustup
                 or rustup_launcher is not None and os.path.samefile(launcher, rustup_launcher)))
    if is_rustup:
        command = launcher if launcher_is_rustup else rustup_launcher
        result = subprocess.run([str(command), 'which', name], cwd=root, capture_output=True,
                                env=tool_probe_environment(), text=True, timeout=10, check=False)
        lines = result.stdout.strip().splitlines()
        if result.returncode != 0 or len(lines) != 1 or not Path(lines[0]).is_absolute():
            raise ValueError('rustup could not identify the selected toolchain executable')
        actual = Path(lines[0]).resolve(strict=True)
        if not actual.is_file() or not os.access(actual, os.X_OK):
            raise ValueError('rustup-selected executable is unavailable')
    def file_digest(path: Path) -> str:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            return digest_fd(fd)
        finally:
            os.close(fd)
    launcher_hash, actual_hash = file_digest(launcher), file_digest(actual)
    selected_version = tool_version(selected_path, root)
    if actual != launcher and tool_version(actual, root) != selected_version:
        raise ValueError('rustup-selected executable version differs from shim')
    if (selected_path.resolve(strict=True) != launcher or file_digest(launcher) != launcher_hash
            or file_digest(actual) != actual_hash):
        raise ValueError('tool changed during identity observation')
    return {'selected_path': str(selected_path), 'launcher_path': str(launcher),
            'launcher_sha256': launcher_hash, 'executable_path': str(actual),
            'executable_sha256': actual_hash, 'version': selected_version}


def digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def open_artifact(root: Path, supplied: Path, directory: bool = False) -> int:
    """Open from an anchored directory FD; never follow a symlink component."""
    if '..' in supplied.parts:
        raise ValueError('artifact path contains parent traversal')
    candidate = supplied if supplied.is_absolute() else root / supplied
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError('artifact path is outside source root') from exc
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, part in enumerate(relative.parts):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if index + 1 < len(relative.parts) or directory:
                flags |= os.O_DIRECTORY
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def digest_fd(fd: int) -> str:
    """Hash an already-open regular inode and reject changes while reading."""
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('artifact is not a regular file')
    h = hashlib.sha256()
    with os.fdopen(fd, 'rb', closefd=False) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    after = os.fstat(fd)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError('artifact changed while hashing')
    return h.hexdigest()


def bundle_inventory(fd: int, prefix: str = '') -> dict[str, str]:
    """Read children relative to open directory FDs and reject all links."""
    result = {}
    with os.scandir(fd) as stream:
        entries = sorted(stream, key=lambda entry: entry.name)
    for entry in entries:
        relative = prefix + entry.name
        if entry.is_symlink():
            raise ValueError('bundle contains a symlink')
        if entry.is_dir(follow_symlinks=False):
            child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                result.update(bundle_inventory(child, relative + '/'))
            finally:
                os.close(child)
        elif entry.is_file(follow_symlinks=False):
            child = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                result[relative] = digest_fd(child)
            finally:
                os.close(child)
        else:
            raise ValueError('bundle contains a non-regular entry')
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify-against", type=Path, help="compare with a preceding build manifest")
    parser.add_argument("--binary", type=Path, action="append", default=[])
    parser.add_argument("--frontend-dir", type=Path)
    args = parser.parse_args()
    root = args.source_root.resolve()
    checks: list[dict] = []
    if args.output.resolve().is_relative_to(root):
        raise ValueError("build evidence must be written outside the source tree")
    if os.path.lexists(args.output):
        print(json.dumps({'status': 'BLOCKED', 'product_gate_effect': 'NONE',
                          'reason': 'build evidence already exists; refusing to overwrite'}, ensure_ascii=False))
        return 20
    try:
        snapshot = source_manifest(root, DEFAULT_EXCLUDES)
        head = snapshot['head']
        valid = snapshot.get('inventory_complete') and snapshot.get('worktree_state') == 'CLEAN'
        checks.append({'name': 'source_snapshot', 'status': 'PASS' if valid else 'INCONCLUSIVE',
                       'manifest_sha256': snapshot.get('manifest_sha256'), 'worktree_state': snapshot.get('worktree_state'),
                       'inventory_complete': snapshot.get('inventory_complete'), 'reason': snapshot.get('inventory_error')})
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        snapshot, head = {}, None
        checks.append({'name': 'source_snapshot', 'status': 'INCONCLUSIVE', 'reason': str(exc)})
    lockfiles = {relative: digest(root / relative) for relative in ("Cargo.lock", "console/package-lock.json")}
    checks.append({"name": "lockfiles", "status": "PASS" if all(lockfiles.values()) else "FAIL", "digests": lockfiles})
    tools = {}
    for name in ("cargo", "rustc", "node", "npm"):
        try:
            tools[name] = executable_identity(name, root)
            checks.append({'name': 'tool.' + name, 'status': 'PASS', 'version': tools[name]['version']})
        except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as exc:
            tools[name] = None
            checks.append({'name': 'tool.' + name, 'status': 'INCONCLUSIVE', 'reason': str(exc)})
    overrides = ('RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_RUSTC',
                 'CARGO_BUILD_RUSTC_WRAPPER', 'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER',
                 'BASH_ENV', 'ENV', 'LD_PRELOAD', 'NODE_OPTIONS')
    present_overrides = [key for key in overrides if os.environ.get(key)]
    checks.append({'name': 'compiler_override', 'status': 'INCONCLUSIVE' if present_overrides else 'PASS',
                   'present': present_overrides,
                   'reason': 'compiler or wrapper overrides cannot be identified by PATH observation' if present_overrides else None})
    # Hash, never disclose, selected environment values that can alter toolchain
    # selection or compilation. This is not a complete environment attestation.
    environment_keys = ('PATH', 'HOME', 'RUSTUP_HOME', 'CARGO_HOME', 'RUSTUP_TOOLCHAIN',
                        'LD_LIBRARY_PATH', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS',
                        'CARGO_BUILD_TARGET', 'CARGO_BUILD_RUSTFLAGS', 'CFLAGS', 'CPPFLAGS', 'LDFLAGS')
    environment = {key: hashlib.sha256(os.environ[key].encode('utf-8', errors='surrogateescape')).hexdigest()
                   if key in os.environ else None for key in environment_keys}
    if args.verify_against:
        try:
            before = json.loads(args.verify_against.read_text(encoding='utf-8'))
            if not isinstance(before, dict):
                raise ValueError('previous build manifest must be a JSON object')
            same = (before.get('status') == 'PASS' and before.get('source_sha') == head
                    and before.get('source_manifest_sha256') == snapshot.get('manifest_sha256')
                    and before.get('lockfiles') == lockfiles and all(tools.values())
                    and before.get('tool_identity') == tools and before.get('tool_environment') == environment
                    and not present_overrides)
            binding_status = 'INCONCLUSIVE' if not all(tools.values()) or present_overrides else 'PASS' if same else 'FAIL'
            checks.append({'name': 'source_binding', 'status': binding_status,
                           'previous_manifest_sha256': digest(args.verify_against),
                           'reason': 'same source, lockfiles and observed tools' if same else 'source, lockfile or observed tool identity changed or missing'})
        except (OSError, ValueError, TypeError) as exc:
            checks.append({'name': 'source_binding', 'status': 'FAIL', 'reason': str(exc)})
    artifacts = {}
    for binary in args.binary:
        key = str(binary)
        if key in artifacts:
            checks.append({'name': 'binary:' + key, 'status': 'FAIL', 'reason': 'duplicate binary path'})
        try:
            fd = open_artifact(root, binary)
            try:
                value = digest_fd(fd)
            finally:
                os.close(fd)
            reason = None
        except (OSError, ValueError) as exc:
            value, reason = None, str(exc)
        artifacts[key] = value
        checks.append({'name': 'binary:' + key, 'status': 'PASS' if value else 'FAIL', 'sha256': value, 'reason': reason})
    if args.frontend_dir:
        try:
            fd = open_artifact(root, args.frontend_dir, directory=True)
            try:
                files = bundle_inventory(fd)
            finally:
                os.close(fd)
        except (OSError, ValueError):
            files = {}
        if not files:
            checks.append({'name': 'frontend_bundle', 'status': 'FAIL', 'reason': 'bundle missing, empty or contains symlinks'})
        else:
            artifacts['frontend'] = files
            checks.append({'name': 'frontend_bundle', 'status': 'PASS', 'file_count': len(files)})
    migration_root = root / 'migrations'
    migration_paths = sorted(migration_root.glob('*.sql')) if migration_root.is_dir() and not migration_root.is_symlink() else []
    migrations = {p.relative_to(root).as_posix(): digest(p) for p in migration_paths if p.is_file() and not p.is_symlink()}
    migration_ok = bool(migration_paths) and len(migrations) == len(migration_paths)
    checks.append({'name': 'migrations', 'status': 'PASS' if migration_ok else 'FAIL', 'file_count': len(migrations)})
    status = "FAIL" if any(c["status"] == "FAIL" for c in checks) else "BLOCKED" if any(c["status"] == "BLOCKED" for c in checks) else "INCONCLUSIVE" if any(c["status"] == "INCONCLUSIVE" for c in checks) else "PASS"
    report = {
        "schema_version": "forgeflow.ecp-build-manifest.v1",
        "product_gate_effect": "NONE",
        "status": status,
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source_root": str(root),
        "source_sha": head,
        "source_manifest_sha256": snapshot.get('manifest_sha256'),
        "lockfiles": lockfiles,
        "tool_identity": tools,
        "tool_environment": environment,
        "migrations": migrations,
        "artifacts": artifacts,
        "binding_scope": "Observed selected executable files and selected environment before and after commands; does not attest command execution, effective compiler settings, shared libraries, transitive tool dependencies or binary provenance",
        "checks": checks,
        "build_performed": False,
        "publish_performed": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        print(json.dumps({'status': 'BLOCKED', 'product_gate_effect': 'NONE',
                          'reason': 'build evidence already exists; refusing to overwrite'}, ensure_ascii=False))
        return 20
    with os.fdopen(fd, 'w', encoding='utf-8') as output:
        output.write(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, ensure_ascii=False))
    return {"PASS": 0, "FAIL": 10, "BLOCKED": 20, "INCONCLUSIVE": 20}[status]


if __name__ == "__main__":
    raise SystemExit(main())
