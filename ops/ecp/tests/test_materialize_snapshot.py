from __future__ import annotations

import os
import signal
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import copy
import stat
import threading
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "ops" / "ecp"))
from materialize_snapshot import materialize_snapshot, materialize_snapshot_v3, _v3_hash, _v3_inventory
import source_snapshot
from source_snapshot import DEFAULT_EXCLUDES, build_manifest


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, text=True,
        capture_output=True,
    ).stdout.strip()


class MaterializeSnapshotTests(unittest.TestCase):
    def make_source(self, parent: Path) -> Path:
        source = parent / "source"
        (source / "app").mkdir(parents=True)
        (source / "app" / "main.txt").write_text("baseline\n", encoding="utf-8")
        git_init = subprocess.run(["git", "init", "-q", str(source)], check=False)
        self.assertEqual(git_init.returncode, 0)
        git(source, "config", "user.email", "test@example.invalid")
        git(source, "config", "user.name", "ECP materialization test")
        git(source, "add", ".")
        git(source, "commit", "-qm", "baseline")
        return source

    def test_materializes_tracked_patch_and_untracked_symlink_without_mutating_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            source = self.make_source(temp)
            (source / "app" / "main.txt").write_text("updated\n", encoding="utf-8")
            (source / "app" / "new.txt").write_text("new source\n", encoding="utf-8")
            os.symlink("main.txt", source / "app" / "alias.txt")
            manifest = build_manifest(source, DEFAULT_EXCLUDES)
            before_status = git(source, "status", "--porcelain=v1")
            candidate = temp / "isolated" / "candidate"

            report = materialize_snapshot(source, manifest, candidate)

            self.assertEqual(report["status"], "PASS")
            self.assertTrue(report["source_unchanged"])
            self.assertEqual((candidate / "app" / "main.txt").read_text(encoding="utf-8"), "updated\n")
            self.assertEqual((candidate / "app" / "new.txt").read_text(encoding="utf-8"), "new source\n")
            self.assertEqual(os.readlink(candidate / "app" / "alias.txt"), "main.txt")
            self.assertFalse((candidate / ".git").exists())
            self.assertEqual(git(source, "status", "--porcelain=v1"), before_status)
            self.assertEqual((source / "app" / "main.txt").read_text(encoding="utf-8"), "updated\n")

    def test_rejects_stale_snapshot_and_preserves_existing_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            source = self.make_source(temp)
            manifest = build_manifest(source, DEFAULT_EXCLUDES)
            (source / "app" / "main.txt").write_text("drifted after snapshot\n", encoding="utf-8")
            destination = temp / "candidate"
            with self.assertRaisesRegex(ValueError, "source changed"):
                materialize_snapshot(source, manifest, destination)
            self.assertFalse(destination.exists())

            destination.mkdir()
            marker = destination / "preserve.txt"
            marker.write_text("user data\n", encoding="utf-8")
            fresh = build_manifest(source, DEFAULT_EXCLUDES)
            with self.assertRaises(FileExistsError):
                materialize_snapshot(source, fresh, destination)
            self.assertEqual(marker.read_text(encoding="utf-8"), "user data\n")

    def test_prunes_tracked_excluded_evidence_before_inventory_without_mutating_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            source = self.make_source(temp)
            evidence_dir = source / "evidence"
            evidence_dir.mkdir()
            tracked_evidence = evidence_dir / "old-run.json"
            tracked_evidence.write_text('{"status":"PASS"}\n', encoding="utf-8")
            excluded_log = source / "app" / "build.log"
            excluded_log.write_text("generated output\n", encoding="utf-8")
            git(source, "add", "evidence/old-run.json", "app/build.log")
            git(source, "commit", "-qm", "add tracked generated outputs")
            manifest = build_manifest(source, DEFAULT_EXCLUDES)
            before_status = git(source, "status", "--porcelain=v1")
            destination = temp / "candidate"

            receipt = materialize_snapshot(source, manifest, destination)

            self.assertEqual(receipt["status"], "PASS")
            self.assertEqual(receipt["excluded_paths"], ["app/build.log", "evidence"])
            self.assertEqual(receipt["excluded_path_count"], 2)
            self.assertFalse((destination / "evidence").exists())
            self.assertFalse((destination / "app" / "build.log").exists())
            self.assertTrue((source / "evidence" / "old-run.json").is_file())
            self.assertEqual((source / "app" / "build.log").read_text(encoding="utf-8"), "generated output\n")
            self.assertEqual(git(source, "status", "--porcelain=v1"), before_status)

    def test_rejects_path_traversal_and_destination_inside_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            source = self.make_source(temp)
            manifest = build_manifest(source, DEFAULT_EXCLUDES)
            from materialize_snapshot import _safe_relative_path
            with self.assertRaisesRegex(ValueError, "unsafe manifest path"):
                _safe_relative_path("../escape.txt")

            clean_manifest = build_manifest(source, DEFAULT_EXCLUDES)
            with self.assertRaisesRegex(ValueError, "outside the source tree"):
                materialize_snapshot(source, clean_manifest, source / "candidate")


class MaterializeSnapshotV3Tests(MaterializeSnapshotTests):
    def test_v3_materializes_tracked_business_formats_and_rejects_legacy_policy(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source = self.make_source(temp)
            payloads = {
                'asset.png': b'png\x00fixture',
                'events.log': b'log fixture\n',
                'bundle.tar.gz': b'archive\x00fixture',
                'module.pyc': b'bytecode\x00fixture',
            }
            for name, data in payloads.items():
                (source/'app'/name).write_bytes(data)
            git(source, 'add', '-f', *('app/' + name for name in payloads))
            git(source, 'commit', '-qm', 'add business resources')
            manifest = source_snapshot.build_manifest_v3(source)
            candidate = temp/'candidate'
            receipt = materialize_snapshot_v3(source, manifest, candidate)
            self.assertEqual((receipt['status'], receipt['product_gate_effect']), ('OBSERVED_NOT_GATE', 'NONE'))
            for name, data in payloads.items():
                with self.subTest(name=name):
                    self.assertEqual((candidate/'app'/name).read_bytes(), data)
            legacy = copy.deepcopy(manifest)
            legacy['exclude_patterns'] = list(source_snapshot.DEFAULT_EXCLUDES)
            legacy['directory_projection']['exclusion_policy_sha256'] = _v3_hash(list(source_snapshot.DEFAULT_EXCLUDES))
            legacy['projection_sha256'] = _v3_hash(legacy['directory_projection'])
            legacy['manifest_sha256'] = _v3_hash({k:v for k,v in legacy.items() if k not in
                                                  ('manifest_sha256', 'created_at', 'release_qualifiable')})
            with self.assertRaisesRegex(ValueError, 'unregistered source exclusion policy'):
                module._v3_expected_projection(legacy)

    def test_v3_mount_backing_identifies_subdirectory_bind_alias(self) -> None:
        import materialize_snapshot as materializer
        table = ('10 1 8:1 / / rw - ext4 /dev/a rw\n'
                 '11 10 8:1 /tmp/source/docs /alias\\040space rw - ext4 /dev/a rw\n')
        self.assertEqual(materializer._v3_backing_path(Path('/tmp/source'),table),('8:1','/tmp/source'))
        self.assertEqual(materializer._v3_backing_path(Path('/alias space/sub'),table),('8:1','/tmp/source/docs/sub'))
        with patch.object(Path,'read_text',return_value=table):
            self.assertTrue(materializer._v3_parent_mount_aliases_source(Path('/tmp/source'),Path('/alias space/sub')))
            self.assertFalse(materializer._v3_parent_mount_aliases_source(Path('/tmp/source'),Path('/elsewhere')))
        with self.assertRaises(ValueError):
            materializer._v3_backing_path(Path('/tmp/source'),'malformed\n')

    def test_v3_rejects_candidate_parent_mount_alias_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source,manifest = self.v3_fixture(temp)
            with patch('materialize_snapshot._v3_parent_mount_aliases_source',return_value=True):
                with self.assertRaisesRegex(ValueError,'aliases the source tree'):
                    materialize_snapshot_v3(source,manifest,temp/'candidate')
            self.assertFalse((temp/'candidate').exists())

    def test_v3_pinned_output_parent_fd_is_not_closed_or_repositioned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory);source,manifest=self.v3_fixture(temp)
            parent=temp/'parent';parent.mkdir()
            fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
            try:
                before=os.fstat(fd);offset=os.lseek(fd,0,os.SEEK_CUR)
                receipt=materialize_snapshot_v3(source,manifest,parent/'candidate',candidate_parent_fd=fd)
                self.assertTrue(receipt['candidate_parent_fd_bound'])
                self.assertEqual((os.fstat(fd).st_dev,os.fstat(fd).st_ino),(before.st_dev,before.st_ino))
                self.assertEqual(os.lseek(fd,0,os.SEEK_CUR),offset)
                self.assertEqual((parent/'candidate/app/main.txt').read_text(),'baseline\n')
            finally:os.close(fd)

    def test_v3_pinned_output_parent_replacement_is_rejected_without_touching_either(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory);source,manifest=self.v3_fixture(temp)
            parent=temp/'parent';parent.mkdir();moved=temp/'moved'
            fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
            try:
                parent.rename(moved);parent.mkdir();(parent/'foreign').write_text('preserve')
                with self.assertRaisesRegex(RuntimeError,'no longer binds'):
                    materialize_snapshot_v3(source,manifest,parent/'candidate',candidate_parent_fd=fd)
                self.assertFalse((parent/'candidate').exists());self.assertFalse((moved/'candidate').exists())
                self.assertEqual((parent/'foreign').read_text(),'preserve')
                self.assertEqual(os.fstat(fd).st_ino,moved.stat().st_ino)
            finally:os.close(fd)

    def test_v3_pinned_parent_rejects_non_directory_or_opath_without_closing_caller(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory);source,manifest=self.v3_fixture(temp)
            regular=temp/'regular';regular.write_text('preserve');fd=os.open(regular,os.O_RDONLY)
            try:
                with self.assertRaisesRegex(ValueError,'readable directory'):
                    materialize_snapshot_v3(source,manifest,temp/'candidate',candidate_parent_fd=fd)
                self.assertEqual(os.read(fd,32),b'preserve')
            finally:os.close(fd)
            if hasattr(os,'O_PATH'):
                fd=os.open(temp,os.O_PATH|os.O_DIRECTORY)
                try:
                    with self.assertRaisesRegex(ValueError,'readable directory'):
                        materialize_snapshot_v3(source,manifest,temp/'candidate',candidate_parent_fd=fd)
                    self.assertTrue(stat.S_ISDIR(os.fstat(fd).st_mode))
                finally:os.close(fd)

    def make_draft(self, source: Path) -> dict:
        # Isolated synthetic producer for materializer safety tests; the full
        # producer/oracle integration must additionally test real source facts.
        manifest = build_manifest(source, DEFAULT_EXCLUDES)
        directories, _, _ = _v3_inventory(source)
        rows = []
        for entry in directories:
            origin = "source_root" if entry["path"] == "." else (
                "excluded_container" if entry["path"].startswith("docs") else "git_ancestor")
            rows.append({**entry, "origin": origin})
        boundaries = []
        for path in (".git", "docs/idea/ForgeFlow_ECP_完整开发规划/evidence"):
            if not (source / path).is_dir():
                continue
            pattern = next(p for p in source_snapshot.V3_EXCLUDES if source_snapshot.matches_exclude(path + "/", (p,)))
            boundaries.append({"path": path, "kind": "directory", "excluded_by": pattern})
        boundaries.sort(key=lambda item: item["path"].encode())
        projection = {"version": "forgeflow.ecp-directory-projection.v1", "mode_availability": "VERIFIED",
                      "exclusion_policy_sha256": _v3_hash(list(source_snapshot.V3_EXCLUDES)), "directories": rows,
                      "excluded_directory_boundaries": boundaries}
        manifest.update(schema_version="forgeflow.ecp-source-manifest.v3", worktree_state="CLEAN",
                        exclude_patterns=list(source_snapshot.V3_EXCLUDES),
                        tracked_changes=[], untracked_business_files=[], excluded_generated_files=[],
                        inventory_complete=True, inventory_error=None, index_visibility_exceptions=[],
                        release_qualifiable=False, directory_projection=projection,
                        projection_sha256=_v3_hash(projection))
        manifest["manifest_sha256"] = _v3_hash({k:v for k,v in manifest.items() if k not in
                                                 ("manifest_sha256", "created_at", "release_qualifiable")})
        return manifest

    def v3_fixture(self, parent: Path) -> tuple[Path, dict]:
        source = self.make_source(parent)
        evidence = source / "docs/idea/ForgeFlow_ECP_完整开发规划/evidence"
        evidence.mkdir(parents=True)
        (evidence / "old.json").write_text("historical evidence remains here\n")
        os.chmod(source / "docs", 0o751)
        return source, self.make_draft(source)

    def producer_patch(self, value):
        return patch.object(source_snapshot, "build_manifest_v3", create=True, side_effect=value)

    def test_v3_inventory_rejects_private_env_fifo_and_socket(self) -> None:
        import socket
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); env = root / '.env'
            os.mkfifo(env)
            with self.assertRaisesRegex(ValueError, 'unsupported source entry'):
                _v3_inventory(root)
            env.unlink()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(str(env))
                with self.assertRaisesRegex(ValueError, 'unsupported source entry'):
                    _v3_inventory(root)
            finally:
                listener.close()

    def test_v3_tracked_env_file_is_not_opened_or_requested_as_git_blob(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source = self.make_source(temp)
            private = source / '.env'; private.write_bytes(b'synthetic private fixture')
            git(source, 'add', '-f', '.env')
            git(source, 'commit', '-qm', 'track synthetic private fixture')
            oid = git(source, 'rev-parse', 'HEAD:.env').encode('ascii')
            info = private.stat(); private_identity = (info.st_dev, info.st_ino)
            manifest = source_snapshot.build_manifest_v3(source)
            real_open, real_capture = os.open, module._v3_git_capture
            opened_private, requests = [], []
            def checked_open(path, flags, *args, **kwargs):
                fd = real_open(path, flags, *args, **kwargs)
                info = os.fstat(fd)
                if (info.st_dev, info.st_ino) == private_identity:
                    opened_private.append(True)
                    os.close(fd)
                    raise AssertionError('private fixture opened by Python')
                return fd
            def checked_capture(command, env, payload=b'', **kwargs):
                if payload:
                    requests.append(payload.splitlines())
                return real_capture(command, env, payload, **kwargs)
            with patch.object(module.os, 'open', side_effect=checked_open), \
                 patch.object(module, '_v3_git_capture', side_effect=checked_capture):
                materialize_snapshot_v3(source, manifest, temp / 'candidate')
            self.assertEqual(opened_private, [])
            self.assertGreaterEqual(len(requests), 2)
            self.assertTrue(all(oid not in request for request in requests))
            self.assertFalse((temp / 'candidate/.env').exists())

    def test_v3_env_directory_is_materialized_and_env_symlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source = self.make_source(temp)
            env = source / '.env'; env.mkdir()
            (env / 'input.txt').write_bytes(b'business directory input')
            git(source, 'add', '-f', '.env/input.txt')
            git(source, 'commit', '-qm', 'track env directory input')
            manifest = source_snapshot.build_manifest_v3(source)
            materialize_snapshot_v3(source, manifest, temp / 'candidate')
            self.assertEqual((temp / 'candidate/.env/input.txt').read_bytes(), b'business directory input')
            git(source, 'rm', '-f', '.env/input.txt')
            git(source, 'commit', '-qm', 'remove env directory input')
            if env.exists(): env.rmdir()
            env.symlink_to('app', target_is_directory=True)
            git(source, 'add', '-f', '.env')
            git(source, 'commit', '-qm', 'track env symlink')
            fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
            try:
                import materialize_snapshot as module
                with self.assertRaisesRegex(ValueError, 'symlink'):
                    module._v3_git_objects_pinned(fd, git(source, 'rev-parse', 'HEAD'))
            finally:
                os.close(fd)

    def test_v3_excluded_git_entries_honor_enumeration_deadline(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            source = self.make_source(Path(directory))
            fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
            oid = 'a' * 40
            raw = b''.join(f'100644 blob {oid}\tevidence/{name}\0'.encode() for name in ('a', 'b'))
            try:
                with patch.object(module, '_v3_git_capture', return_value=raw), \
                     patch.object(module, '_v3_require_boundary_directory') as boundary, \
                     patch.object(module.time, 'monotonic', side_effect=[0.0, 0.0, 61.0]):
                    with self.assertRaisesRegex(TimeoutError, 'Git tree enumeration exceeded deadline'):
                        module._v3_git_objects_pinned(fd, oid)
                    self.assertEqual(boundary.call_count, 1)
            finally:
                os.close(fd)

    def test_v3_materializes_directory_named_files_and_nested_business(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source = self.make_source(temp)
            names = ('evidence', 'target', 'node_modules', 'crates/demo/src/evidence/verification.rs',
                     'console/src/assets/node_modules/spec.json', 'console/src/__pycache__/golden.pyc')
            for name in names:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(('business:' + name).encode())
                path.chmod(0o644)
            (source / 'evidence-link').symlink_to('evidence')
            git(source, 'add', '-f', *names, 'evidence-link')
            git(source, 'commit', '-qm', 'add business files')
            manifest = source_snapshot.build_manifest_v3(source)
            destination = temp / 'candidate'
            receipt = materialize_snapshot_v3(source, manifest, destination)
            self.assertEqual(receipt['product_gate_effect'], 'NONE')
            for name in names:
                with self.subTest(name=name):
                    self.assertEqual((destination / name).read_bytes(), ('business:' + name).encode())
            self.assertEqual(os.readlink(destination / 'evidence-link'), 'evidence')
            self.assertEqual((destination / 'evidence-link').read_bytes(), b'business:evidence')

    def test_v3_rejects_replaced_boundary_symlink_before_materializing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source = self.make_source(temp)
            boundary = source / 'evidence'; boundary.mkdir()
            excluded = boundary / 'history'; excluded.write_bytes(b'history')
            git(source, 'add', '-f', 'evidence/history')
            git(source, 'commit', '-qm', 'record excluded boundary')
            manifest = source_snapshot.build_manifest_v3(source)
            excluded.unlink(); boundary.rmdir()
            boundary.symlink_to('app', target_is_directory=True)
            with self.assertRaises((ValueError, OSError)):
                materialize_snapshot_v3(source, manifest, temp / 'candidate')
            self.assertFalse((temp / 'candidate').exists())

    def test_v3_preserves_nondefault_regular_file_modes_from_source(self) -> None:
        from materialize_snapshot import _v3_file_modes_digest
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source = self.make_source(temp)
            script = source / "app/run.sh"
            script.write_text("#!/bin/sh\nexit 0\n")
            script.chmod(0o750)
            git(source, "add", "app/run.sh"); git(source, "commit", "-qm", "add executable")
            (source / "app/main.txt").chmod(0o640)
            manifest = self.make_draft(source)
            expected = _v3_file_modes_digest(_v3_inventory(source)[1])
            with self.producer_patch(lambda *args: copy.deepcopy(manifest)):
                receipt = materialize_snapshot_v3(source, manifest, temp / "candidate", expected_file_modes_sha256=expected)
            self.assertEqual(receipt["status"], "OBSERVED_NOT_GATE")
            self.assertEqual(receipt["external_file_modes_sha256"], expected)
            for name, mode in (("main.txt", 0o640), ("run.sh", 0o750)):
                self.assertEqual(stat.S_IMODE((temp / "candidate/app" / name).stat().st_mode), mode)
                self.assertEqual((temp / "candidate/app" / name).read_bytes(), (source / "app" / name).read_bytes())

    def test_v3_rejects_privileged_regular_file_mode_without_publishing(self) -> None:
        from materialize_snapshot import _v3_file_modes_digest
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source, _ = self.v3_fixture(temp)
            (source / "app/main.txt").chmod(0o4644)
            manifest = self.make_draft(source)
            expected = _v3_file_modes_digest(_v3_inventory(source)[1])
            with self.producer_patch(lambda *args: copy.deepcopy(manifest)):
                with self.assertRaisesRegex(ValueError, "special permission bits"):
                    materialize_snapshot_v3(source, manifest, temp / "candidate", expected_file_modes_sha256=expected)
            self.assertFalse((temp / "candidate").exists())
            self.assertEqual(stat.S_IMODE((source / "app/main.txt").stat().st_mode), 0o4644)

    def test_v3_external_file_mode_pin_rejects_later_mode_change(self) -> None:
        from materialize_snapshot import _v3_file_modes_digest
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source, manifest = self.v3_fixture(temp)
            expected = _v3_file_modes_digest(_v3_inventory(source)[1])
            (source / "app/main.txt").chmod(0o600)
            with self.producer_patch(lambda *args: copy.deepcopy(manifest)):
                with self.assertRaisesRegex(ValueError, "independently pinned digest"):
                    materialize_snapshot_v3(source, manifest, temp / "candidate", expected_file_modes_sha256=expected)
            self.assertFalse((temp / "candidate").exists())

    def test_v3_external_file_mode_pin_rejects_malformed_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source, manifest = self.v3_fixture(temp)
            for value in ("not-a-digest", "A" * 64, "0" * 64, True):
                with self.subTest(value=value), self.producer_patch(lambda *args: copy.deepcopy(manifest)):
                    with self.assertRaisesRegex(ValueError, "independently pinned digest"):
                        materialize_snapshot_v3(source, manifest, temp / "candidate", expected_file_modes_sha256=value)
                    self.assertFalse((temp / "candidate").exists())

    def test_v3_external_mode_pin_rejects_file_type_disagreement(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source = self.make_source(temp)
            other = source / "app/other.txt"; other.write_text("other\n")
            git(source, "add", "app/other.txt"); git(source, "commit", "-qm", "second file")
            manifest = self.make_draft(source)
            (source / "app/main.txt").unlink()
            (source / "app/main.txt").symlink_to("other.txt")
            expected = module._v3_file_modes_digest(_v3_inventory(source)[1])
            with self.producer_patch(lambda *args: copy.deepcopy(manifest)):
                with self.assertRaisesRegex(ValueError, "source file type differs from Git"):
                    materialize_snapshot_v3(source, manifest, temp / "candidate", expected_file_modes_sha256=expected)
            self.assertFalse((temp / "candidate").exists())

    def test_v3_rechecks_source_modes_before_publication(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source, manifest = self.v3_fixture(temp)
            expected = module._v3_file_modes_digest(_v3_inventory(source)[1])
            write_objects = module._v3_write_git_objects
            def change_source_after_apply(*args, **kwargs):
                write_objects(*args, **kwargs)
                (source / "app/main.txt").chmod(0o600)
            with self.producer_patch(lambda *args: copy.deepcopy(manifest)), \
                 patch.object(module, "_v3_write_git_objects", side_effect=change_source_after_apply):
                with self.assertRaisesRegex(ValueError, "source inventory changed"):
                    materialize_snapshot_v3(source, manifest, temp / "candidate", expected_file_modes_sha256=expected)
            self.assertFalse((temp / "candidate").exists())

    def test_v3_external_mode_pin_rejects_git_executable_disagreement(self) -> None:
        import materialize_snapshot as module
        for source_mode, git_executable in ((0o755, False), (0o644, True)):
            with self.subTest(source_mode=source_mode, git_executable=git_executable), tempfile.TemporaryDirectory() as directory:
                temp = Path(directory); source = self.make_source(temp)
                path = source / "app/main.txt"
                if git_executable:
                    path.chmod(0o755)
                    git(source, "add", "app/main.txt"); git(source, "commit", "-qm", "executable")
                git(source, "config", "core.filemode", "false")
                path.chmod(source_mode)
                manifest = self.make_draft(source)
                expected = module._v3_file_modes_digest(_v3_inventory(source)[1])
                with self.producer_patch(lambda *args: copy.deepcopy(manifest)):
                    with self.assertRaisesRegex(ValueError, "executable bits differ"):
                        materialize_snapshot_v3(source, manifest, temp / "candidate", expected_file_modes_sha256=expected)
                self.assertFalse((temp / "candidate").exists())

    def test_v3_pinned_modes_with_real_producer_and_independent_oracle(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source = self.make_source(temp)
            script = source / "app/run.sh"
            script.write_text("#!/bin/sh\nexit 0\n")
            script.chmod(0o750)
            git(source, "add", "app/run.sh"); git(source, "commit", "-qm", "add executable")
            (source / "app/main.txt").chmod(0o640)
            manifest = source_snapshot.build_manifest_v3(source, source_snapshot.V3_EXCLUDES)
            self.assertEqual(manifest["worktree_state"], "CLEAN")
            self.assertEqual(manifest["directory_projection"]["mode_availability"], "VERIFIED")
            expected = module._v3_file_modes_digest(_v3_inventory(source)[1])
            candidate = temp / "candidate"
            receipt = materialize_snapshot_v3(source, manifest, candidate, expected_file_modes_sha256=expected)
            manifest_path, receipt_path = temp / "manifest.json", temp / "receipt.json"
            manifest_path.write_text(json.dumps(manifest))
            receipt_path.write_text(json.dumps(receipt))
            oracle = ROOT / "verification/ecp/p005_snapshot_oracle.py"
            result = subprocess.run([sys.executable, "-I", "-S", str(oracle), "--manifest-version", "3",
                "--source", str(source), "--candidate", str(candidate), "--source-sha", git(source, "rev-parse", "HEAD"),
                "--manifest-sha256", manifest["manifest_sha256"], "--manifest", str(manifest_path),
                "--receipt", str(receipt_path)], text=True, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            observed = json.loads(result.stdout)
            self.assertEqual(observed["status"], "OBSERVED_NOT_GATE")
            self.assertEqual(observed["product_gate_effect"], "NONE")
            self.assertEqual(observed["candidate_inventory_v3_sha256"], receipt["candidate_inventory_v3_sha256"])

    def test_v3_pinned_mode_fails_closed_under_restrictive_umask(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source = self.make_source(temp)
            (source / "app/main.txt").chmod(0o640)
            script = '''import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import source_snapshot as s, materialize_snapshot as m
source=Path(sys.argv[2]); candidate=Path(sys.argv[3])
manifest=s.build_manifest_v3(source,s.V3_EXCLUDES)
pin=m._v3_file_modes_digest(m._v3_inventory(source)[1])
os.umask(0o077)
try:
 m.materialize_snapshot_v3(source,manifest,candidate,expected_file_modes_sha256=pin)
except ValueError as exc:
 assert 'umask or filesystem policy' in str(exc), str(exc)
 assert not candidate.exists()
 print('EXPECTED_BLOCKED')
else:
 raise AssertionError('restrictive umask unexpectedly accepted')
'''
            result = subprocess.run([sys.executable, "-I", "-B", "-S", "-c", script,
                str(ROOT / "ops/ecp"), str(source), str(temp / "candidate")], text=True,
                capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("EXPECTED_BLOCKED", result.stdout)

    def test_v3_observation_preserves_projection_and_historical_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source, manifest = self.v3_fixture(temp)
            destination = temp / "candidate"
            with self.producer_patch(lambda *args: copy.deepcopy(manifest)):
                receipt = materialize_snapshot_v3(source, manifest, destination)
            self.assertEqual(receipt["status"], "OBSERVED_NOT_GATE")
            self.assertEqual(receipt["qualification"], "NOT_RUN")
            self.assertFalse(receipt["release_qualifiable"])
            self.assertEqual(receipt["product_gate_effect"], "NONE")
            self.assertTrue(receipt["git_metadata_removed"])
            self.assertEqual(receipt["source_root"], str(source))
            self.assertTrue((destination / "docs/idea/ForgeFlow_ECP_完整开发规划").is_dir())
            self.assertFalse((destination / "docs/idea/ForgeFlow_ECP_完整开发规划/evidence").exists())
            self.assertEqual(stat.S_IMODE((destination / "docs").stat().st_mode), 0o751)
            self.assertEqual((source / "docs/idea/ForgeFlow_ECP_完整开发规划/evidence/old.json").read_text(),
                             "historical evidence remains here\n")
            dirs, files, size = _v3_inventory(destination)
            self.assertEqual(receipt["candidate_inventory_v3_sha256"], _v3_hash({"directories":dirs, "files":files}))
            self.assertEqual((receipt["candidate_directory_count"], receipt["candidate_file_count"], receipt["candidate_tree_bytes"]),
                             (len(dirs), len(files), size))

    def test_v3_refuses_unverified_modes_wrong_policy_and_unsorted_or_duplicate_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source, original = self.v3_fixture(temp)
            cases = []
            unavailable = copy.deepcopy(original); unavailable["directory_projection"]["mode_availability"] = "UNAVAILABLE"; cases.append(unavailable)
            wrong_policy = copy.deepcopy(original); wrong_policy["exclude_patterns"].append("app/"); cases.append(wrong_policy)
            duplicate = copy.deepcopy(original); duplicate["directory_projection"]["directories"].append(copy.deepcopy(duplicate["directory_projection"]["directories"][-1])); cases.append(duplicate)
            unsorted = copy.deepcopy(original); unsorted["directory_projection"]["directories"].reverse(); cases.append(unsorted)
            unsafe = copy.deepcopy(original); unsafe["directory_projection"]["directories"][-1]["path"] = "../outside"; cases.append(unsafe)
            for index, manifest in enumerate(cases):
                projection = manifest["directory_projection"]
                manifest["projection_sha256"] = _v3_hash(projection)
                manifest["manifest_sha256"] = _v3_hash({k:v for k,v in manifest.items() if k not in ("manifest_sha256", "created_at", "release_qualifiable")})
                with self.subTest(index=index), self.producer_patch(lambda *args: copy.deepcopy(manifest)):
                    with self.assertRaises(ValueError):
                        materialize_snapshot_v3(source, manifest, temp / f"candidate-{index}")
                    self.assertFalse((temp / f"candidate-{index}").exists())

    def test_v3_rejects_source_drift_and_never_overwrites_concurrent_destination(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source, manifest = self.v3_fixture(temp)
            changed = copy.deepcopy(manifest); changed["manifest_sha256"] = "0" * 64
            with self.producer_patch([copy.deepcopy(manifest), changed]):
                with self.assertRaisesRegex(ValueError, "source changed"):
                    materialize_snapshot_v3(source, manifest, temp / "drifted")
            self.assertFalse((temp / "drifted").exists())
            with self.producer_patch([copy.deepcopy(manifest), RuntimeError("producer failed")]):
                with self.assertRaisesRegex(RuntimeError, "producer failed"):
                    materialize_snapshot_v3(source, manifest, temp / "producer-failed")
            self.assertFalse((temp / "producer-failed").exists())
            destination = temp / "contended"
            original_publish = module._v3_publish_noreplace
            def contend(stage, parentfd, name):
                destination.mkdir()
                (destination / "preserve.txt").write_text("user data")
                return original_publish(stage, parentfd, name)
            with self.producer_patch(lambda *args: copy.deepcopy(manifest)), patch.object(module, "_v3_publish_noreplace", side_effect=contend):
                with self.assertRaises(OSError):
                    materialize_snapshot_v3(source, manifest, destination)
            self.assertEqual((destination / "preserve.txt").read_text(), "user data")

    def test_v3_rejects_unrecorded_directory_and_escaping_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source, manifest = self.v3_fixture(temp)
            (source / "unrecorded-empty").mkdir()
            with self.producer_patch(lambda *args: copy.deepcopy(manifest)):
                with self.assertRaisesRegex(ValueError, "directories differ"):
                    materialize_snapshot_v3(source, manifest, temp / "unexpected")
            (source / "unrecorded-empty").rmdir()
            (temp / "outside.txt").write_text("not source")
            os.symlink("../../outside.txt", source / "app/out")
            with self.producer_patch(lambda *args: copy.deepcopy(manifest)):
                with self.assertRaisesRegex(ValueError, "escapes source"):
                    materialize_snapshot_v3(source, manifest, temp / "escape")

    def test_v3_inventory_rejects_open_race_and_limits_growing_file_reads(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            source = self.make_source(Path(directory)); target = source / "app/main.txt"
            original_open = os.open
            changed = False
            def change_mode(path, flags, *args, **kwargs):
                nonlocal changed
                fd = original_open(path, flags, *args, **kwargs)
                if path == "main.txt" and not changed:
                    changed = True
                    os.fchmod(fd, 0o600)
                return fd
            with patch.object(module.os, "open", side_effect=change_mode):
                with self.assertRaisesRegex(ValueError, "changed during inventory"):
                    module._v3_inventory(source)
            target.write_bytes(b"x" * (1024 * 1024 + 31))
            before_size = target.stat().st_size
            target_inode = target.stat().st_ino
            original_read = os.read; read_count = 0; appended = False
            def grow_during_read(fd, size):
                nonlocal read_count, appended
                data = original_read(fd, size)
                if os.fstat(fd).st_ino == target_inode:
                    read_count += len(data)
                    if not appended:
                        appended = True
                        with target.open("ab") as stream:
                            stream.write(b"growth")
                return data
            with patch.object(module.os, "read", side_effect=grow_during_read):
                with self.assertRaisesRegex(ValueError, "changed during inventory"):
                    module._v3_inventory(source)
            self.assertEqual(read_count, before_size)
            with patch.object(module, "_V3_MAX_SCAN_SECONDS", -1):
                with self.assertRaisesRegex(TimeoutError, "time budget"):
                    module._v3_inventory(source)

    def test_v3_git_environment_is_minimized_and_output_is_explicitly_unavailable(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source, manifest = self.v3_fixture(temp)
            original_run = module._v3_git_capture
            with self.producer_patch(lambda *args: copy.deepcopy(manifest)), \
                 patch.dict(os.environ, {"DATABASE_URL":"secret", "GIT_DIR":"malicious", "OPENAI_API_KEY":"secret"}), \
                 patch.object(module, "_v3_git_capture", wraps=original_run) as runner:
                receipt = materialize_snapshot_v3(source, manifest, temp / "candidate")
            self.assertEqual(receipt["git_output_capture"], "OBJECT_DATA_BOUNDED; STDERR_DISCARDED_UNAVAILABLE")
            self.assertEqual(runner.call_count, 3)
            for call in runner.call_args_list:
                command, env, *_ = call.args
                self.assertEqual(command[0], "/usr/bin/git")
                self.assertNotIn("DATABASE_URL", env)
                self.assertNotIn("OPENAI_API_KEY", env)
                self.assertNotIn("GIT_DIR", env)
                self.assertEqual(env["GIT_CONFIG_GLOBAL"], "/dev/null")

    def test_v3_git_output_is_bounded_and_timeout_stops_own_process_group(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            # A chatty child cannot grow this process's buffers or logs.
            script = "import os; os.write(1,b'x'*8000000); os.write(2,b'y'*8000000)"
            with self.assertRaisesRegex(ValueError, "byte budget"):
                module._v3_git_capture([sys.executable, "-c", script], {}, limit=1024)
            marker = Path(directory) / "escaped-child"
            child_script = ("import os,time\n"
                            "if os.fork()==0:\n time.sleep(0.6); open(%r,'w').write('alive'); os._exit(0)\n"
                            "time.sleep(10)\n") % str(marker)
            with patch.object(module, "_V3_GIT_TIMEOUT_SECONDS", 0.1):
                with self.assertRaisesRegex(TimeoutError, "stderr unavailable"):
                    module._v3_git_capture([sys.executable, "-c", child_script], {}, limit=1024)
            time.sleep(0.8)
            self.assertFalse(marker.exists())

    def test_v3_git_selector_setup_failures_reap_own_child(self) -> None:
        import materialize_snapshot as module
        class BrokenRegistration:
            def register(self, *_args):
                raise OSError('controlled selector registration failure')
            def close(self):
                pass
        for setup in ('initialization', 'registration'):
            with self.subTest(setup=setup):
                real_popen = subprocess.Popen
                sentinel = real_popen(['/usr/bin/sleep', '30'], start_new_session=True)
                children = []
                def spawn(*args, **kwargs):
                    process = real_popen(*args, **kwargs)
                    children.append(process)
                    return process
                selector_patch = (patch.object(module.selectors, 'DefaultSelector',
                    side_effect=OSError('controlled selector initialization failure')) if setup == 'initialization'
                    else patch.object(module.selectors, 'DefaultSelector', return_value=BrokenRegistration()))
                try:
                    with patch.object(module.subprocess, 'Popen', side_effect=spawn), selector_patch:
                        with self.assertRaisesRegex(OSError, 'controlled selector'):
                            module._v3_git_capture(['/usr/bin/sleep', '30'], {}, limit=1024)
                    self.assertEqual(len(children), 1)
                    self.assertEqual(children[0].returncode, -signal.SIGKILL)
                    self.assertIsNone(sentinel.poll())
                finally:
                    for process in [*children, sentinel]:
                        if process.poll() is None:
                            os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)

    def test_v3_git_timeout_stops_group_when_leader_already_exited(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); ready = temp/'child-ready'; marker = temp/'late-marker'
            program = ('import os,time\n'
                       'if os.fork(): os._exit(0)\n'
                       f'open({str(ready)!r},"w").write("ready")\n'
                       'time.sleep(1)\n'
                       f'open({str(marker)!r},"w").write("unexpected")\n'
                       'os._exit(0)\n')
            sentinel = subprocess.Popen(['/usr/bin/sleep', '30'], start_new_session=True)
            try:
                with patch.object(module, '_V3_GIT_TIMEOUT_SECONDS', 0.4):
                    with self.assertRaisesRegex(TimeoutError, 'stderr unavailable'):
                        module._v3_git_capture(['/usr/bin/python3', '-c', program], {}, limit=1024)
                self.assertTrue(ready.is_file(), 'descendant must have started before timeout')
                time.sleep(1.1)
                self.assertFalse(marker.exists(), 'same-group descendant outlived timeout')
                self.assertIsNone(sentinel.poll())
            finally:
                sentinel.terminate()
                sentinel.wait(timeout=5)

    def test_v3_git_signal_failure_marks_process_termination_unknown(self) -> None:
        import materialize_snapshot as module
        class BrokenSelector:
            def register(self, *_args):
                pass
            def get_map(self):
                return {1: True}
            def select(self, *_args):
                raise OSError('controlled selector failure')
            def close(self):
                raise OSError('controlled selector close failure')
        real_popen = subprocess.Popen; children = []
        sentinel = real_popen(['/usr/bin/sleep', '30'], start_new_session=True)
        def spawn(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            children.append(process)
            return process
        try:
            with patch.object(module.subprocess, 'Popen', side_effect=spawn), \
                 patch.object(module.selectors, 'DefaultSelector', return_value=BrokenSelector()), \
                 patch.object(module.os, 'killpg', side_effect=PermissionError('controlled signal denial')):
                with self.assertRaisesRegex(RuntimeError, 'process termination could not be confirmed'):
                    module._v3_git_capture(['/usr/bin/sleep', '30'], {}, limit=1024)
            self.assertEqual(len(children), 1)
            self.assertIsNone(children[0].poll())
            self.assertIsNone(sentinel.poll())
        finally:
            for process in [*children, sentinel]:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)

    def test_v3_git_signal_failure_remains_unknown_even_if_leader_exits(self) -> None:
        import materialize_snapshot as module
        class BrokenSelector:
            def register(self, *_args):
                pass
            def get_map(self):
                return {1: True}
            def select(self, *_args):
                raise OSError('controlled selector failure')
            def close(self):
                pass
        with patch.object(module.selectors, 'DefaultSelector', return_value=BrokenSelector()), \
             patch.object(module.os, 'killpg', side_effect=PermissionError('controlled signal denial')):
            with self.assertRaisesRegex(RuntimeError, 'process-group termination could not be confirmed'):
                module._v3_git_capture(['/usr/bin/python3', '-c', 'import time;time.sleep(0.1)'], {}, limit=1024)

    def test_v3_git_never_signals_pid_after_wait_reaped_then_raised(self) -> None:
        import materialize_snapshot as module
        real_popen = subprocess.Popen; children = []
        sentinel = real_popen(['/usr/bin/sleep', '30'], start_new_session=True)
        def spawn(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            wait = process.wait
            def wait_then_raise(*wait_args, **wait_kwargs):
                wait(*wait_args, **wait_kwargs)
                raise OSError('controlled failure after wait reaped leader')
            process.wait = wait_then_raise
            children.append((process, wait))
            return process
        try:
            with patch.object(module.subprocess, 'Popen', side_effect=spawn), \
                 patch.object(module.os, 'killpg') as kill_group:
                with self.assertRaisesRegex(RuntimeError, 'process-group termination could not be confirmed'):
                    module._v3_git_capture(['/usr/bin/python3', '-c', 'print("fixture")'], {}, limit=1024)
                kill_group.assert_not_called()
            self.assertEqual(len(children), 1)
            self.assertEqual(children[0][0].returncode, 0)
            self.assertIsNone(sentinel.poll())
        finally:
            for process, wait in children:
                if process.returncode is None:
                    os.killpg(process.pid, signal.SIGKILL)
                wait(timeout=5)
            sentinel.terminate()
            sentinel.wait(timeout=5)

    def test_v3_git_nonzero_exit_preserves_code_without_signalling_reaped_process(self) -> None:
        import materialize_snapshot as module
        with patch.object(module.os, 'killpg') as kill_group:
            with self.assertRaisesRegex(RuntimeError, 'Git object inspection exited 7; stderr unavailable'):
                module._v3_git_capture(['/usr/bin/python3', '-c', 'import sys;sys.exit(7)'], {}, limit=1024)
            kill_group.assert_not_called()

    def test_v3_does_not_checkout_excluded_large_git_blob(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source = self.make_source(temp)
            evidence = source / "docs/idea/ForgeFlow_ECP_完整开发规划/evidence"
            evidence.mkdir(parents=True)
            excluded = evidence / "generated.log"
            excluded.write_bytes(b"x" * (2 * 1024 * 1024))
            git(source, "add", "-f", "docs/idea/ForgeFlow_ECP_完整开发规划/evidence/generated.log")
            git(source, "commit", "-qm", "excluded large artifact")
            (evidence / "old.txt").write_text("preserve")
            manifest = self.make_draft(source)
            with self.producer_patch(lambda *args: copy.deepcopy(manifest)), \
                 patch.object(module, "_V3_MAX_GIT_BLOB_BYTES", 64):
                receipt = materialize_snapshot_v3(source, manifest, temp / "candidate")
            self.assertEqual(receipt["status"], "OBSERVED_NOT_GATE")
            self.assertFalse((temp / "candidate/docs/idea/ForgeFlow_ECP_完整开发规划/evidence/generated.log").exists())
            self.assertEqual(excluded.stat().st_size, 2 * 1024 * 1024)
            self.assertEqual((evidence / "old.txt").read_text(), "preserve")

    def test_v3_ignores_git_smudge_filters_and_rejects_projected_object_over_budget(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source = self.make_source(temp)
            (source / ".gitattributes").write_text("app/main.txt filter=trap\n")
            git(source, "add", ".gitattributes"); git(source, "commit", "-qm", "attributes")
            marker = temp / "filter-ran"
            git(source, "config", "filter.trap.smudge", f"touch {marker}; cat")
            evidence = source / "docs/idea/ForgeFlow_ECP_完整开发规划/evidence"
            evidence.mkdir(parents=True)
            manifest = self.make_draft(source)
            with self.producer_patch(lambda *args: copy.deepcopy(manifest)):
                receipt = materialize_snapshot_v3(source, manifest, temp / "candidate")
            self.assertEqual(receipt["status"], "OBSERVED_NOT_GATE")
            self.assertFalse(marker.exists())
            with self.producer_patch(lambda *args: copy.deepcopy(manifest)), \
                 patch.object(module, "_V3_MAX_GIT_TREE_BYTES", 1):
                with self.assertRaisesRegex(ValueError, "tree exceeds byte budget"):
                    materialize_snapshot_v3(source, manifest, temp / "oversized")
            self.assertFalse((temp / "oversized").exists())
            self.assertFalse(marker.exists())

    def test_v3_inventory_streams_and_enforces_entry_budget(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            source = self.make_source(Path(directory))
            for index in range(20):
                (source / "app" / f"item-{index}").write_text("x")
            with patch.object(module.os, "fwalk", side_effect=AssertionError("fwalk must not run")), \
                 patch.object(module, "_V3_MAX_ENTRIES", 4):
                with self.assertRaisesRegex(ValueError, "entry budget"):
                    module._v3_inventory(source)

    def test_v3_inventory_does_not_close_fd_reused_by_another_thread(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            source = self.make_source(Path(directory))
            original_open_directory = module._v3_open_directory
            original_close = os.close
            tracked = []; reused = []; closed = threading.Event(); reopened = threading.Event()
            def record_root(path):
                result = original_open_directory(path)
                tracked.append(result[1])
                return result
            def replace_closed_root():
                if not closed.wait(3):
                    reopened.set(); return
                root_fd = tracked[0]
                new_fd = os.open("/dev/null", os.O_RDONLY)
                if new_fd != root_fd:
                    os.dup2(new_fd, root_fd)
                    original_close(new_fd)
                reused.append(root_fd); reopened.set()
            def close_and_interleave(fd):
                original_close(fd)
                if tracked and fd == tracked[0] and not closed.is_set():
                    closed.set()
                    if not reopened.wait(3):
                        raise RuntimeError("FD reuse test worker did not respond")
            thread = threading.Thread(target=replace_closed_root)
            thread.start()
            try:
                with patch.object(module, "_v3_open_directory", side_effect=record_root), \
                     patch.object(module.os, "close", side_effect=close_and_interleave):
                    module._v3_inventory(source)
                    self.assertTrue(reused)
                    os.fstat(reused[0])
            finally:
                thread.join(timeout=3)
                if reused:
                    original_close(reused[0])
            self.assertFalse(thread.is_alive())

    def test_v3_directory_open_does_not_retry_a_failed_close_or_leak_child(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            source = self.make_source(Path(directory))
            original_open, original_close = os.open, os.close
            opened = []; closes = []
            def track_open(*args, **kwargs):
                fd = original_open(*args, **kwargs); opened.append(fd); return fd
            def fail_first_close(fd):
                closes.append(fd); original_close(fd)
                if len(closes) == 1:
                    raise OSError("simulated close error after kernel close")
            with patch.object(module.os, "open", side_effect=track_open), \
                 patch.object(module.os, "close", side_effect=fail_first_close):
                with self.assertRaisesRegex(OSError, "simulated close error"):
                    module._v3_open_directory(source)
            self.assertEqual(len(opened), 2)
            self.assertEqual(closes, opened)
            for fd in opened:
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_v3_canonical_json_and_paths_have_explicit_shape_limits(self) -> None:
        import materialize_snapshot as module
        with self.assertRaisesRegex(ValueError, "string exceeds"):
            module._v3_hash({"value": "x" * 4097})
        cyclic = []
        cyclic.append(cyclic)
        with self.assertRaisesRegex(ValueError, "shape exceeds"):
            module._v3_hash(cyclic)
        with self.assertRaisesRegex(ValueError, "depth budget"):
            module._v3_path("/".join(["x"] * 128))

    def test_v3_rejects_live_regular_file_mode_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source, manifest = self.v3_fixture(temp)
            os.chmod(source / "app/main.txt", 0o600)
            # A forged unchanged producer observation cannot hide a physical
            # rw mode difference between live source and the Git candidate.
            with self.producer_patch(lambda *args: copy.deepcopy(manifest)):
                with self.assertRaisesRegex(ValueError, "candidate inventory differs"):
                    materialize_snapshot_v3(source, manifest, temp / "candidate")
            self.assertFalse((temp / "candidate").exists())

    def test_v3_rechecks_git_blob_object_identity(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            source = self.make_source(Path(directory))
            sha = git(source, "rev-parse", "HEAD")
            original = module._v3_git_capture
            def corrupt(command, env, payload=b"", *, limit, pass_fds=()):
                result = original(command, env, payload, limit=limit, pass_fds=pass_fds)
                if command[-1] == "--batch":
                    content = bytearray(result)
                    content[content.index(bytes([10])) + 1] ^= 1
                    return bytes(content)
                return result
            with patch.object(module, "_v3_git_capture", side_effect=corrupt):
                with self.assertRaisesRegex(ValueError, "object identity"):
                    module._v3_git_objects(source, sha)

    def test_v3_rejects_candidate_hardlink_to_source_even_when_bytes_and_mode_match(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source, manifest = self.v3_fixture(temp)
            original_writer = module._v3_write_git_objects
            def link_instead(stagefd, entries, blobs, expected_names):
                original_writer(stagefd, entries, blobs, expected_names)
                appfd = module._v3_open_relative_directory(stagefd, "app")
                try:
                    os.unlink("main.txt", dir_fd=appfd)
                    os.link(source / "app/main.txt", "main.txt", dst_dir_fd=appfd, follow_symlinks=False)
                finally:
                    os.close(appfd)
            with self.producer_patch(lambda *args: copy.deepcopy(manifest)), \
                 patch.object(module, "_v3_write_git_objects", side_effect=link_instead):
                with self.assertRaisesRegex(ValueError, "hardlinks"):
                    materialize_snapshot_v3(source, manifest, temp / "candidate")
            self.assertFalse((temp / "candidate").exists())
            self.assertEqual((source / "app/main.txt").read_text(), "baseline\n")

    def test_v3_candidate_inventory_rejects_hardlinked_symlink(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            source = self.make_source(Path(directory))
            os.symlink("main.txt", source / "app/link-a")
            os.link(source / "app/link-a", source / "app/link-b", follow_symlinks=False)
            with self.assertRaisesRegex(ValueError, "hardlinks"):
                module._v3_inventory(source, require_single_links=True)

    def test_v3_supports_internal_symlink_chain_but_rejects_cycles(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source = self.make_source(temp)
            os.symlink("main.txt", source / "app/link-a")
            os.symlink("link-a", source / "app/link-b")
            git(source, "add", "app/link-a", "app/link-b"); git(source, "commit", "-qm", "internal chain")
            evidence = source / "docs/idea/ForgeFlow_ECP_完整开发规划/evidence"
            evidence.mkdir(parents=True)
            manifest = self.make_draft(source)
            with self.producer_patch(lambda *args: copy.deepcopy(manifest)):
                receipt = materialize_snapshot_v3(source, manifest, temp / "candidate")
            self.assertEqual(receipt["status"], "OBSERVED_NOT_GATE")
            self.assertEqual((temp / "candidate/app/link-b").read_text(), "baseline\n")
            os.symlink("cycle-b", source / "app/cycle-a")
            os.symlink("cycle-a", source / "app/cycle-b")
            with self.assertRaisesRegex(ValueError, "40 links or has a cycle"):
                module._v3_inventory(source)

    def test_v3_symlink_limit_counts_outer_link(self) -> None:
        import errno
        for internal, usable in ((39, True), (40, False)):
            with self.subTest(internal_links=internal), tempfile.TemporaryDirectory() as directory:
                temp = Path(directory); source = self.make_source(temp); app = source/'app'
                for i in range(internal):
                    target = f'link-{i+1:02d}' if i+1 < internal else 'main.txt'
                    (app/f'link-{i:02d}').symlink_to(target)
                (app/'outer').symlink_to('link-00')
                if usable:
                    self.assertEqual((app/'outer').read_bytes(), b'baseline\n')
                else:
                    with self.assertRaises(OSError) as error:
                        (app/'outer').read_bytes()
                    self.assertEqual(error.exception.errno, errno.ELOOP)
                git(source, 'add', 'app'); git(source, 'commit', '-qm', 'link limit fixture')
                manifest = source_snapshot.build_manifest_v3(source)
                candidate = temp/'candidate'
                if usable:
                    result = materialize_snapshot_v3(source, manifest, candidate)
                    self.assertEqual(result['status'], 'OBSERVED_NOT_GATE')
                    self.assertEqual((candidate/'app/outer').read_bytes(), b'baseline\n')
                else:
                    with self.assertRaisesRegex(ValueError, '40 links or has a cycle'):
                        materialize_snapshot_v3(source, manifest, candidate)
                    self.assertFalse(candidate.exists())

    def test_v3_source_root_swap_is_rejected_before_writing_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source, manifest = self.v3_fixture(temp)
            moved = temp / "moved-source"
            def swap_root(*args):
                source.rename(moved)
                source.mkdir()
                (source / "foreign.txt").write_text("foreign data")
                return copy.deepcopy(manifest)
            with self.producer_patch(swap_root):
                with self.assertRaisesRegex(ValueError, "no longer binds"):
                    materialize_snapshot_v3(source, manifest, temp / "candidate")
            self.assertFalse((temp / "candidate").exists())
            self.assertEqual((source / "foreign.txt").read_text(), "foreign data")
            self.assertEqual((moved / "app/main.txt").read_text(), "baseline\n")

    def test_v3_output_parent_replacement_before_publish_rejects_without_touching_foreign_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source, manifest = self.v3_fixture(temp)
            output_parent = temp / "output"; output_parent.mkdir()
            moved_parent = temp / "moved-output"; calls = 0
            def change_parent(*args):
                nonlocal calls
                calls += 1
                if calls == 2:
                    output_parent.rename(moved_parent)
                    output_parent.mkdir()
                    (output_parent / "foreign.txt").write_text("preserve foreign")
                return copy.deepcopy(manifest)
            with self.producer_patch(change_parent):
                with self.assertRaisesRegex(RuntimeError, "before publication; no candidate was published"):
                    materialize_snapshot_v3(source, manifest, output_parent / "candidate")
            self.assertEqual((output_parent / "foreign.txt").read_text(), "preserve foreign")
            self.assertFalse((output_parent / "candidate").exists())
            self.assertFalse((moved_parent / "candidate").exists())

    def test_v3_output_parent_replacement_after_publish_retains_created_candidate(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source, manifest = self.v3_fixture(temp)
            output_parent = temp / "output"; output_parent.mkdir()
            moved_parent = temp / "moved-output"
            publish = module._v3_publish_noreplace
            def swap_after_publish(*args):
                publish(*args)
                output_parent.rename(moved_parent)
                output_parent.mkdir()
                (output_parent / "foreign.txt").write_text("preserve foreign")
            with self.producer_patch(lambda *args: copy.deepcopy(manifest)), \
                 patch.object(module, "_v3_publish_noreplace", side_effect=swap_after_publish):
                with self.assertRaisesRegex(RuntimeError, "after publication; candidate state is uncertain") as observed:
                    materialize_snapshot_v3(source, manifest, output_parent / "candidate")
            self.assertIn(str(moved_parent), str(observed.exception))
            self.assertEqual((output_parent / "foreign.txt").read_text(), "preserve foreign")
            self.assertFalse((output_parent / "candidate").exists())
            self.assertEqual((moved_parent / "candidate/app/main.txt").read_text(), "baseline\n")

    def test_v3_published_candidate_replacement_is_reported_without_cleanup(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source, manifest = self.v3_fixture(temp)
            output_parent = temp / "output"; output_parent.mkdir()
            publish = module._v3_publish_noreplace
            def swap_after_publish(*args):
                publish(*args)
                (output_parent / "candidate").rename(output_parent / "retained")
                (output_parent / "foreign").mkdir()
                (output_parent / "foreign/marker").write_text("preserve foreign")
                os.symlink("foreign", output_parent / "candidate")
            with self.producer_patch(lambda *args: copy.deepcopy(manifest)), \
                 patch.object(module, "_v3_publish_noreplace", side_effect=swap_after_publish):
                with self.assertRaisesRegex(RuntimeError, "candidate path identity is uncertain"):
                    materialize_snapshot_v3(source, manifest, output_parent / "candidate")
            self.assertTrue((output_parent / "candidate").is_symlink())
            self.assertEqual((output_parent / "foreign/marker").read_text(), "preserve foreign")
            self.assertEqual((output_parent / "retained/app/main.txt").read_text(), "baseline\n")

    def test_v3_hash_failure_precedes_publication(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source, manifest = self.v3_fixture(temp)
            original_hash = module._v3_hash
            def fail_candidate_hash(value, **kwargs):
                if isinstance(value, dict) and set(value) == {"directories", "files"}:
                    raise TimeoutError("candidate digest timed out")
                return original_hash(value, **kwargs)
            with self.producer_patch(lambda *args: copy.deepcopy(manifest)), \
                 patch.object(module, "_v3_hash", side_effect=fail_candidate_hash):
                with self.assertRaisesRegex(TimeoutError, "candidate digest timed out"):
                    materialize_snapshot_v3(source, manifest, temp / "candidate")
            self.assertFalse((temp / "candidate").exists())
            self.assertEqual((source / "app/main.txt").read_text(), "baseline\n")

    def test_v3_post_publication_stage_mutation_is_reported_and_retained(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source, manifest = self.v3_fixture(temp)
            original_publish = module._v3_publish_noreplace
            def mutate_then_publish(stage_parent_fd, parent_fd, name):
                stage_fd = os.open("candidate", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                   dir_fd=stage_parent_fd)
                try:
                    app_fd = module._v3_open_relative_directory(stage_fd, "app")
                    try:
                        file_fd = os.open("main.txt", os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, dir_fd=app_fd)
                        try:
                            os.write(file_fd, b"tampered\n")
                        finally:
                            os.close(file_fd)
                    finally:
                        os.close(app_fd)
                finally:
                    os.close(stage_fd)
                original_publish(stage_parent_fd, parent_fd, name)
            with self.producer_patch(lambda *args: copy.deepcopy(manifest)), \
                 patch.object(module, "_v3_publish_noreplace", side_effect=mutate_then_publish):
                with self.assertRaisesRegex(module.V3PublicationUncertain, "candidate inventory changed after publication"):
                    materialize_snapshot_v3(source, manifest, temp / "candidate")
            self.assertEqual((temp / "candidate/app/main.txt").read_text(), "tampered\n")
            self.assertEqual((source / "app/main.txt").read_text(), "baseline\n")

    def test_v3_post_publication_cleanup_failure_is_reported_and_retained(self) -> None:
        import materialize_snapshot as module
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); source, manifest = self.v3_fixture(temp)
            original_tempdir = module.tempfile.TemporaryDirectory
            class CleanupFailure:
                def __init__(self, *args, **kwargs):
                    self.delegate = original_tempdir(*args, **kwargs)
                def __enter__(self):
                    return self.delegate.__enter__()
                def __exit__(self, *args):
                    self.delegate.__exit__(*args)
                    raise OSError("simulated tempdir cleanup failure")
            with self.producer_patch(lambda *args: copy.deepcopy(manifest)), \
                 patch.object(module.tempfile, "TemporaryDirectory", CleanupFailure):
                with self.assertRaisesRegex(module.V3PublicationUncertain, "may already be published"):
                    materialize_snapshot_v3(source, manifest, temp / "candidate")
            self.assertEqual((temp / "candidate/app/main.txt").read_text(), "baseline\n")


if __name__ == "__main__":
    unittest.main()
