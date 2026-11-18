import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backup_manifest_check import verify_backup


def seal(root: Path, *, symlink: bool = False) -> None:
    dump = root / "postgres.dump"
    dump.write_bytes(b"pg-dump")
    (root / "data").mkdir()
    (root / "data" / "state.json").write_text("{}\n", encoding="utf-8")
    hashes = {}
    links = {}
    for child in sorted(root.rglob("*")):
        if child.is_file():
            hashes[str(child.relative_to(root))] = hashlib.sha256(child.read_bytes()).hexdigest()
    if symlink:
        (root / "data" / "current").symlink_to("state.json")
        links["data/current"] = "state.json"
    manifest = {
        "schema_version": "forgeflow.backup.v1",
        "dispatch_paused": True,
        "unsettled_attempts": 0,
        "file_quiescence_checked": True,
        "sha256": hashes,
        "symlinks": links,
        "projects": [],
        "repositories": [],
    }
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


class BackupManifestCheckTests(unittest.TestCase):
    def test_exact_inventory_and_symlink_are_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            seal(root, symlink=True)
            report = verify_backup(root)
            self.assertEqual(report["status"], "VERIFIED")
            self.assertEqual(report["file_count"], 2)
            self.assertEqual(report["symlink_count"], 1)

    def test_unexpected_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            seal(root)
            (root / "unexpected.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unexpected"):
                verify_backup(root)

    def test_tampered_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            seal(root)
            (root / "postgres.dump").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "mismatched"):
                verify_backup(root)

    def test_manifest_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            seal(root)
            manifest = json.loads((root / "manifest.json").read_text())
            manifest["sha256"]["../escape"] = "0" * 64
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "unsafe"):
                verify_backup(root)

    def test_unverified_file_quiescence_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            seal(root)
            manifest = json.loads((root / "manifest.json").read_text())
            manifest["file_quiescence_checked"] = False
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "quiescent"):
                verify_backup(root)


if __name__ == "__main__":
    unittest.main()
