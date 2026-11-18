#!/usr/bin/env python3
"""A10 consumer test for the actual DSH-authored finite indexer artifact."""
import argparse
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True


def run(args):
    candidate = Path(args.candidate).resolve()
    initial = candidate.read_bytes()
    checks = []
    def check(name, condition):
        checks.append({"name": name, "status": "PASS" if condition else "FAIL"})
    def index_files(root):
        wrapper = "import json,pathlib,sys; p=pathlib.Path(sys.argv[1]); n={'__name__':'candidate_api','__file__':str(p)}; exec(compile(p.read_bytes(),str(p),'exec'),n); print(json.dumps(n['index_files'](sys.argv[2]),ensure_ascii=False))"
        response = subprocess.run([sys.executable, "-I", "-B", "-c", wrapper, str(candidate), str(root)],
                                  env={"PATH": "/usr/bin:/bin"}, capture_output=True, timeout=30)
        if response.returncode:
            raise RuntimeError("actual candidate API call failed")
        return json.loads(response.stdout)
    rng = random.Random(args.seed)
    with tempfile.TemporaryDirectory(prefix="forgeflow-independent-indexer-") as directory:
        root = Path(directory) / "root"
        root.mkdir()
        known = {}
        for index in range(100):
            name = f"层级{index % 7}/文件 {index:03d}.bin"
            size = (0, 1, 65535, 65536, 65537, 150000)[index % 6]
            data = rng.randbytes(size)
            path = root / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(data)
            known[name] = {"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        (root / "空目录").mkdir()
        external = Path(directory) / "external.txt"
        external.write_text("must not follow symlink")
        (root / "file-link").symlink_to(external)
        external_dir = Path(directory) / "external-dir"
        external_dir.mkdir()
        (external_dir / "secret.txt").write_text("must not traverse")
        (root / "dir-link").symlink_to(external_dir, target_is_directory=True)
        (root / "dangling-link").symlink_to(root / "missing")
        for name in (".git", "层级1/.git"):
            directory_path = root / name
            directory_path.mkdir()
            (directory_path / "excluded").write_bytes(b"git metadata")
        os.mkfifo(root / "fifo")
        expected = [known[name] for name in sorted(known)]
        actual = index_files(str(root))
        check("exact_100_regular_file_records_against_known_bytes", actual == expected)
        check("deterministic_repeat", index_files(str(root)) == actual)
        check("paths_lexicographic_sorted", [r["path"] for r in actual] == sorted(known))
        check("file_symlink_excluded", all(r["path"] != "file-link" for r in actual))
        check("directory_symlink_excluded", all(not r["path"].startswith("dir-link/") for r in actual))
        check("dangling_symlink_excluded", all(r["path"] != "dangling-link" for r in actual))
        check("fifo_excluded", all(r["path"] != "fifo" for r in actual))
        check("nested_git_directories_excluded", all(".git" not in r["path"].split("/") for r in actual))
        check("chunk_boundary_lengths", {r["size"] for r in actual} == {0, 1, 65535, 65536, 65537, 150000})
        cli = subprocess.run([sys.executable, str(candidate), str(root)], capture_output=True, timeout=30)
        check("actual_cli_exit_zero", cli.returncode == 0)
        check("actual_cli_complete_reference_match", json.loads(cli.stdout) == expected)
        check("actual_cli_utf8_without_ascii_escape", "文件".encode() in cli.stdout and b"\\u6587" not in cli.stdout)
        no_args = subprocess.run([sys.executable, str(candidate)], capture_output=True, timeout=10)
        check("usage_error_nonzero", no_args.returncode != 0)
        empty = Path(directory) / "empty"
        empty.mkdir()
        check("empty_directory_exact_empty_list", index_files(str(empty)) == [])
    check("candidate_immutable_during_verification", candidate.read_bytes() == initial)
    report = {"status": "FAIL" if any(c["status"] == "FAIL" for c in checks) else "PASS", "author_id": "DSH-native-probe",
              "verifier_id": "A10-independent", "candidate_path": str(candidate), "candidate_sha256": hashlib.sha256(initial).hexdigest(),
              "attempted_assertions": len(checks), "failed": sum(c["status"] == "FAIL" for c in checks), "skipped": 0,
              "files": 100, "seed": args.seed, "checks": checks, "g2_status": "INCONCLUSIVE",
              "not_proven": ["platform admission", "managed Worker launch", "DSH completed lifecycle", "controlled Git integration"],
              "reproduce": f"{sys.executable} verification/verify_indexer.py --candidate {candidate} --seed {args.seed} --output {args.output}"}
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("status", "attempted_assertions", "failed", "candidate_sha256", "g2_status")}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--seed", type=int, default=20261009)
    run(parser.parse_args())
