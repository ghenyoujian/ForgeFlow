"""In-process regressions for the unadmitted standalone runner.

Only mock calls and private temporary canaries are used. Passing these tests
does not authenticate a source, execute P003, or grant a product Gate.
"""
from __future__ import annotations

import argparse
import builtins
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "ops" / "ecp"))
import verify

SPEC = importlib.util.spec_from_file_location("unadmitted_p003_runner", ROOT / "verification" / "ecp" / "runner.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class BlockedRunnerTests(unittest.TestCase):
    def call(self, args, *, guard_paths=True, module_entry=False):
        out, err = io.StringIO(), io.StringIO()
        source = (ROOT / "verification" / "ecp" / "runner.py").read_bytes() if module_entry else None
        sensitive = []
        for flag in ("--source-root", "--output"):
            if flag in args and args.index(flag) + 1 < len(args):
                sensitive.append(args[args.index(flag) + 1])

        def guard_path(original, *, two_paths=False):
            def guarded(path, *extra, **kwargs):
                paths = (path, extra[0]) if two_paths and extra else (path,)
                for candidate in paths:
                    if isinstance(candidate, (str, bytes, os.PathLike)):
                        value = os.fsdecode(candidate)
                        if any(value == item or value.startswith(item.rstrip("/") + "/") or
                               (value not in ("", "/", "/tmp") and item.startswith(value.rstrip("/") + "/"))
                               for item in sensitive):
                            raise AssertionError("attempt to access supplied source/output path")
                return original(path, *extra, **kwargs)
            return guarded

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", ["ecp-runner", *args]))
            stack.enter_context(contextlib.redirect_stdout(out))
            stack.enter_context(contextlib.redirect_stderr(err))
            deny = AssertionError("disallowed process, network or output/source path operation")
            for obj, names in ((subprocess, ("run", "Popen", "call", "check_call", "check_output")),
                               (socket, ("socket", "create_connection")),
                               (os, ("system", "fork", "forkpty", "execv", "execve", "execvp", "execvpe",
                                     "execl", "execle", "execlp", "execlpe", "spawnv", "spawnve", "posix_spawn"))):
                for name in names:
                    if hasattr(obj, name):
                        stack.enter_context(mock.patch.object(obj, name, side_effect=deny))
            stack.enter_context(mock.patch.object(runner, "source_sha", side_effect=deny, create=True))
            if guard_paths:
                stack.enter_context(mock.patch.object(builtins, "open", side_effect=guard_path(builtins.open)))
                for name in ("open", "stat", "lstat", "unlink", "mkdir", "listdir", "scandir", "readlink",
                             "access", "remove", "rmdir", "chmod", "chown"):
                    stack.enter_context(mock.patch.object(os, name, side_effect=guard_path(getattr(os, name))))
                for name in ("rename", "replace", "link", "symlink"):
                    stack.enter_context(mock.patch.object(os, name,
                        side_effect=guard_path(getattr(os, name), two_paths=True)))
                for name in ("resolve", "open", "stat", "lstat", "exists", "is_dir", "unlink", "mkdir",
                             "read_bytes", "read_text", "write_bytes", "write_text", "symlink_to", "readlink",
                             "chmod", "rmdir", "rename", "replace", "touch", "iterdir", "glob", "rglob",
                             "hardlink_to"):
                    stack.enter_context(mock.patch.object(Path, name, side_effect=deny))
            try:
                if module_entry:
                    exec(compile(source, "<private-runner>", "exec"),
                         {"__name__": "__main__", "__file__": str(ROOT / "verification" / "ecp" / "runner.py")})
                    code = None
                else:
                    code = runner.main()
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def assert_blocked(self, code, stdout, stderr):
        self.assertEqual((code, stderr), (20, ""))
        result = json.loads(stdout)
        self.assertEqual(result["schema_version"], "forgeflow.ecp-verification.v1")
        self.assertEqual((result["status"], result["qualification"], result["product_gate_effect"]),
                         ("BLOCKED", "NOT_RUN", "NONE"))
        self.assertIs(result["workload_invoked"], False)
        self.assertIs(result["workload_confinement_verified"], False)
        self.assertIs(result["independent_execution_authority_verified"], False)
        self.assertIsNone(result["database_connections_attempted"])
        self.assertIsNone(result["source_sha"])
        self.assertEqual(result["checks"][0]["name"], "execution_authority")
        self.assertEqual(result["checks"][0]["status"], "BLOCKED")
        self.assertEqual(result["denominator"], {"total": 1, "passed": 0, "failed": 0,
                                                "blocked": 1, "not_run": 0, "inconclusive": 0})
        self.assertIn("check", result["reason"].lower())
        self.assertIn("no test", result["reason"].lower())
        self.assertNotIn("forgeflow.ecp-test-receipt.v1", stdout)
        self.assertLess(len(stdout.encode("utf-8")), 8192)
        return result

    def test_every_valid_suite_and_command_is_blocked_before_side_effects(self):
        for suite, command, flag, timeout in (
                ("ECP-P0-03", '["/fake"]', True, "1"),
                ("UNKNOWN", '["/fake"]', True, "300"),
                ("ECP-P0-03", "not-json", True, "0"),
                ("ECP-P0-03", '["/fake"]', False, "-1"),
                ("s" * 100000, '["secret-token-123"]', True, "1")):
            with self.subTest(suite=suite[:20], command=command[:20], flag=flag, timeout=timeout):
                args = ["--suite-id", suite, "--source-root", "/private/secret-source",
                        "--command-json", command, "--timeout", timeout,
                        "--output", "/private/secret-output"]
                if flag:
                    args.append("--allow-execution")
                code, stdout, stderr = self.call(args)
                self.assert_blocked(code, stdout, stderr)
                self.assertNotIn("/private/", stdout)
                self.assertNotIn("secret-token-123", stdout)
                self.assertNotIn("s" * 256, stdout)

    def test_owned_output_canaries_are_never_changed(self):
        with tempfile.TemporaryDirectory(prefix="p003-runner-canaries-") as tmp:
            base = Path(tmp)
            target = base / "target"
            target.write_bytes(b"owned original output canary\n")
            before = target.lstat()
            link = base / "link"
            link.symlink_to(target.name)
            fifo = base / "fifo"
            os.mkfifo(fifo)
            subdir = base / "directory"
            subdir.mkdir()
            missing = base / "missing-parent" / "receipt.json"
            locked = base / "nonwritable-parent"
            locked.mkdir()
            locked.chmod(0o500)
            probe = locked / "write-probe"
            try:
                try:
                    fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                except PermissionError:
                    write_probe = "DENIED"
                else:
                    os.close(fd)
                    os.unlink(probe)
                    write_probe = "ALLOWED"
                print("PRIVATE_PARENT_WRITE_PROBE=" + write_probe, file=sys.stderr)
                for output in (target, link, fifo, subdir, missing, locked / "receipt.json"):
                    with self.subTest(output=output.name):
                        code, stdout, stderr = self.call(["--suite-id", "ECP-P0-03", "--command-json", '["/fake"]',
                                                         "--allow-execution", "--output", str(output)])
                        self.assert_blocked(code, stdout, stderr)
                self.assertEqual(list(locked.iterdir()), [])
            finally:
                locked.chmod(0o700)
            self.assertEqual(target.read_bytes(), b"owned original output canary\n")
            after = target.lstat()
            self.assertEqual((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
                             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns))
            self.assertTrue(link.is_symlink())
            self.assertEqual(os.readlink(link), target.name)
            self.assertTrue(fifo.exists())
            self.assertEqual(list(subdir.iterdir()), [])
            self.assertFalse(missing.parent.exists())

    def test_canonical_blocked_check_semantics_match_verify(self):
        code, stdout, stderr = self.call(["--suite-id", "ECP-P0-03", "--output", "/unused"])
        current = self.assert_blocked(code, stdout, stderr)
        with contextlib.redirect_stdout(io.StringIO()):
            canonical, status = verify.run_phase0_offline_suite(argparse.Namespace(profile="isolated"),
                                                               Path("/unused"), None, {})
        self.assertEqual(code, status)
        for field in ("schema_version", "status", "qualification", "product_gate_effect", "workload_invoked",
                      "workload_confinement_verified", "independent_execution_authority_verified",
                      "database_connections_attempted", "denominator"):
            self.assertEqual(current[field], canonical[field], field)
        self.assertEqual(current["checks"][0]["name"], canonical["checks"][0]["name"])
        self.assertEqual(current["checks"][0]["status"], canonical["checks"][0]["status"])

    def test_module_entry_and_missing_command_are_blocked(self):
        for flag in (False, True):
            args = ["--suite-id", "ECP-P0-03", "--output", "/unused"]
            if flag:
                args.append("--allow-execution")
            code, stdout, stderr = self.call(args, module_entry=True)
            self.assert_blocked(code, stdout, stderr)

    def test_help_and_syntax_errors_never_execute_or_touch_output(self):
        for args, expected in ((["--source-root", "/secret", "--output", "/secret", "--help"], 0),
                               (["--output", "/secret"], 2),
                               (["--suite-id", "ECP-P0-03", "--timeout", "invalid", "--output", "/secret"], 2),
                               (["--suite-id", "ECP-P0-03", "--timeout", "SECRET密钥" + "界" * 100000,
                                 "--output", "/secret"], 2),
                               (["--suite-id", "ECP-P0-03", "--output", "/secret", "--unknown=SECRET"], 2)):
            with self.subTest(args=args[0]):
                code, stdout, stderr = self.call(args)
                self.assertEqual(code, expected)
                self.assertNotIn("/secret", stdout + stderr)
                self.assertNotIn("SECRET", stdout + stderr)
                self.assertLess(len((stdout + stderr).encode("utf-8")), 8192)


if __name__ == "__main__":
    unittest.main(verbosity=2)
