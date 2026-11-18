#!/usr/bin/env python3
"""Trusted external finite indexer oracle for the registered Rust evidence runner.

No candidate imports write bytecode. Cases and gold bytes are defined here,
outside candidate worktrees, and must be pinned in each registered command.
"""
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
ORACLE = "a10-file-indexer-reference.v1"
CASES = {
    "author": [("author_empty_directory", "positive"), ("author_one_file", "positive")],
    "consumer": [("consumer_json_cli", "positive"), ("consumer_usage_error", "negative")],
    "independent": [("independent_recursive_reference", "positive"),
                    ("independent_symlink_and_git_exclusion", "negative"),
                    ("independent_fifo_not_indexed", "negative"),
                    ("independent_chunk_boundary_hashes", "positive")],
}


def index_api(candidate, root):
    # Candidate code executes in a separate process, so it cannot accidentally
    # monkeypatch the reference's hashlib, JSON or filesystem functions.
    wrapper = "import json,pathlib,sys; p=pathlib.Path(sys.argv[1]); n={'__name__':'candidate_api','__file__':str(p)}; exec(compile(p.read_bytes(),str(p),'exec'),n); print(json.dumps(n['index_files'](sys.argv[2]),ensure_ascii=False))"
    result = subprocess.run([sys.executable, "-I", "-B", "-c", wrapper, str(candidate), str(root)],
                            env={"PATH": "/usr/bin:/bin"}, capture_output=True, timeout=20)
    if result.returncode != 0:
        raise RuntimeError("candidate API subprocess failed: " + result.stderr.decode(errors="replace")[:300])
    return json.loads(result.stdout)


def main():
    role = os.environ["FORGEFLOW_VERIFICATION_ROLE"]
    if role not in CASES:
        raise ValueError("unknown registered role")
    binding = json.loads(os.environ["FORGEFLOW_EVIDENCE_BINDING"])
    candidate = Path.cwd() / "indexer.py"
    code = candidate.read_bytes()
    index_files = lambda root: index_api(candidate, root)
    results = {name: False for name, _ in CASES[role]}
    errors = []
    env = {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        with tempfile.TemporaryDirectory(prefix="forgeflow-a10-oracle-") as directory:
            root = Path(directory) / "dataset"
            root.mkdir()
            if role == "author":
                results["author_empty_directory"] = index_files(str(root)) == []
                data = b"deterministic file index\n"
                (root / "simple.txt").write_bytes(data)
                results["author_one_file"] = index_files(str(root)) == [{"path": "simple.txt", "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}]
            elif role == "consumer":
                data = "文件索引 consumer\n".encode()
                (root / "文件.txt").write_bytes(data)
                cli = subprocess.run([sys.executable, str(candidate), str(root)], env=env, capture_output=True, timeout=20)
                expected = [{"path": "文件.txt", "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}]
                results["consumer_json_cli"] = cli.returncode == 0 and json.loads(cli.stdout) == expected and "文件".encode() in cli.stdout
                usage = subprocess.run([sys.executable, str(candidate)], env=env, capture_output=True, timeout=10)
                results["consumer_usage_error"] = usage.returncode != 0
            else:
                rng = random.Random(20261009)
                known = {}
                for index in range(36):
                    name = f"层级{index % 4}/文件 {index:03d}.bin"
                    size = (0, 1, 65535, 65536, 65537, 150000)[index % 6]
                    data = rng.randbytes(size)
                    path = root / name
                    path.parent.mkdir(exist_ok=True)
                    path.write_bytes(data)
                    known[name] = {"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                expected = [known[name] for name in sorted(known)]
                plain = index_files(str(root))
                results["independent_recursive_reference"] = plain == expected and index_files(str(root)) == expected
                results["independent_chunk_boundary_hashes"] = plain == expected and {row["size"] for row in plain} == {0, 1, 65535, 65536, 65537, 150000}
                outside = Path(directory) / "outside"
                outside.mkdir()
                (outside / "secret").write_bytes(b"excluded")
                (root / "file-symlink").symlink_to(outside / "secret")
                (root / "dir-symlink").symlink_to(outside, target_is_directory=True)
                (root / "missing-symlink").symlink_to(outside / "missing")
                for name in (".git", "层级1/.git"):
                    path = root / name
                    path.mkdir()
                    (path / "objects").write_bytes(b"excluded git")
                results["independent_symlink_and_git_exclusion"] = index_files(str(root)) == expected
                os.mkfifo(root / "fifo")
                results["independent_fifo_not_indexed"] = index_files(str(root)) == expected
    except Exception as exc:
        errors.append(type(exc).__name__ + ":" + str(exc))
    if candidate.read_bytes() != code:
        results = {name: False for name in results}
        errors.append("candidate mutated during verification")
    report = {"binding": binding, "oracle_id": ORACLE,
              "cases": [{"name": name, "kind": kind, "outcome": "passed" if results[name] else "failed"} for name, kind in CASES[role]]}
    report_path = Path(os.environ["FORGEFLOW_REPORT_PATH"])
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False) + "\n")
    print(json.dumps({"role": role, "executed": len(results), "failed": sum(not v for v in results.values()), "errors": errors}))
    return 0 if all(results.values()) and not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
