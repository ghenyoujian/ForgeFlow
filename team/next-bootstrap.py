#!/usr/bin/env python3
"""Read-only live identity capture and conservative review of Next draft cards.

Never updates the supplied design package, production services or databases.
The resulting Next ledger is separate from legacy tasks and product Gates.
"""
from __future__ import annotations

import collections
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT.parent / "docs/idea/ForgeFlow_Next_设计改造交付包"
EXCLUDED = {".git", "target", "node_modules", "dist", "qualification", "__pycache__"}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def run(destination: Path, name: str, argv: list[str], timeout: int = 30) -> dict:
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    try:
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=timeout)
        raw = result.stdout + result.stderr
        code = result.returncode
    except subprocess.TimeoutExpired as error:
        raw = (error.stdout or b"") + (error.stderr or b"")
        code = 124
    path = destination / (name + ".txt")
    path.write_bytes(raw)
    return {"id": name, "argv": argv, "started_at": started, "exit_code": code,
            "log": str(path.relative_to(ROOT)), "sha256": digest(path)}


def main() -> None:
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = ROOT / "evidence/next" / f"{stamp}-{head[:10]}"
    output.mkdir(parents=True, exist_ok=False)
    declarations = json.loads((PACKAGE / "FILES_SHA256.json").read_text())
    package_files = [{"path": path, "sha256": digest(PACKAGE / path),
                      "matches": digest(PACKAGE / path) == value["sha256"]}
                     for path, value in declarations.items()]
    assert all(row["matches"] for row in package_files), "Supplied package hash mismatch"
    inventory = {}
    for top in ["crates", "migrations", "contracts", "console/src", "deploy", "ops"]:
        for here, directories, names in os.walk(ROOT / top):
            directories[:] = [name for name in directories if name not in EXCLUDED]
            for name in names:
                path = Path(here) / name
                if path.is_file() and not path.is_symlink():
                    inventory[str(path.relative_to(ROOT))] = digest(path)
    for relative in ["Cargo.toml", "Cargo.lock", "console/package.json",
                     "console/package-lock.json", "AGENTS.md", "team/ownership.json"]:
        inventory[relative] = digest(ROOT / relative)
    save(output / "source-files.json", inventory)
    commands = [
        ("git-head", ["git", "show", "-s", "--format=fuller", "HEAD"]),
        ("git-tracked-status", ["git", "status", "--porcelain=v1", "-uno"]),
        ("toolchain", ["bash", "-c", "cargo --version; rustc --version; node --version; npm --version; git --version"]),
        ("resources", ["bash", "-c", "uname -a; free -b; df -B1 / /mnt/e; ss -ltn; ps -eo pid,ppid,comm,rss"]),
        ("claude-version", ["claude", "--version"]),
        ("claude-help", ["claude", "--help"]),
        ("dsh-help", ["/usr/bin/node", "/home/chenyoujian/.local/share/dsh-wsl/source/apps/cli/lib/bin.js", "--help"]),
        ("postgres-version", ["/home/chenyoujian/.cache/forgeflow-postgres/root/usr/lib/postgresql/16/bin/postgres", "--version"]),
    ]
    results = [run(output, name, argv) for name, argv in commands]
    identities = []
    for path in [Path("/usr/bin/node"), Path("/home/chenyoujian/.local/bin/claude"),
                 Path("/home/chenyoujian/.npm-global/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe"),
                 Path("/home/chenyoujian/.local/share/dsh-wsl/source/apps/cli/lib/bin.js")]:
        identities.append({"path": str(path), "resolved": str(path.resolve()),
                           "exists": path.is_file(), "sha256": digest(path) if path.is_file() else None})
    snapshot = {"schema_version": "forgeflow.next.baseline.v1", "at": stamp, "head": head,
                "branch": subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT, text=True).strip(),
                "root": str(ROOT), "package": package_files, "executables": identities,
                "source_manifest": str((output / "source-files.json").relative_to(ROOT)),
                "commands": results, "new_model_calls": 0,
                "limitations": ["Version/help do not qualify model calls, Team, Workflow, cancellation or recovery.",
                                "Existing production server, Workers and port55432 remain untouched.",
                                "No inherited product Gate. Dirty source is hashed independently from HEAD.",
                                "No complete credential/profile or OS-resource qualification for paid sessions."]}
    save(output / "baseline.json", snapshot)
    draft = json.loads((PACKAGE / "实施任务矩阵_DRAFT.json").read_text())
    ownership = json.loads((ROOT / "team/ownership.json").read_text())
    reviewed = []
    path_users: dict[str, list[str]] = collections.defaultdict(list)
    for task in draft["tasks"]:
        for path in task["write_set"]:
            path_users[path.rstrip("/")].append(task["id"])
    for task in draft["tasks"]:
        row = dict(task)
        path_review = []
        issues = []
        for path in task["write_set"]:
            owners = sorted({owner for owner, paths in ownership.items()
                             for territory in paths if path == territory
                             or path.startswith(territory.rstrip("/") + "/")})
            path_review.append({"path": path, "exists": (ROOT / path).exists(),
                                "current_owners": owners, "base_sha256": digest(ROOT / path)
                                if (ROOT / path).is_file() else None})
            if owners != [task["owner"]]:
                issues.append({"kind": "OWNER_RECONCILIATION", "path": path, "owners": owners})
            if path.startswith("tests/next"):
                issues.append({"kind": "UNREGISTERED_TEST_TARGET", "path": path,
                               "decision": "Use verification/next for orchestration or owning crate tests; root tests are not a Cargo target."})
            if len(path_users[path.rstrip("/")]) > 1:
                issues.append({"kind": "SHARED_PATH_MUST_SERIALIZE", "path": path,
                               "tasks": path_users[path.rstrip("/")]})
            if "/src/" in path and path.endswith(".rs") and not (ROOT / path).exists():
                issues.append({"kind": "MODULE_AND_CALLER_BINDING_REQUIRED", "path": path})
        row.update(status="DRAFT_NOT_ADMITTED", source_head=head, live_baseline=str((output / "baseline.json").relative_to(ROOT)),
                   path_review=path_review, review_issues=issues, admission=None,
                   exact_write_set=None, qualification="NOT_RUN")
        reviewed.append(row)
    ledger = {"schema_version": "forgeflow.next.reviewed-drafts.v1", "source_package_sha256": digest(PACKAGE / "实施任务矩阵_DRAFT.json"),
              "baseline": str((output / "baseline.json").relative_to(ROOT)), "status": "DRAFT_NOT_ADMITTED",
              "policy": "Implementation grants are separate and explicit in team/next-admissions.json; no runtime lease or product Gate is issued by this ledger.",
              "tasks": reviewed}
    target = ROOT / "planning/next-tasks.json"
    if target.exists():
        raise RuntimeError("Preserve existing Next ledger; review/update deliberately")
    save(target, ledger)
    docs = ROOT / "docs/next"
    docs.mkdir(parents=True, exist_ok=True)
    (docs / "baseline.md").write_text(
        "# ForgeFlow Next 现场基线\n\n"
        f"Git HEAD `{head}`，main，工作区非干净；当前源码逐文件哈希见 [现场记录](../../{output.relative_to(ROOT)}/baseline.json)。\n\n"
        "用户提供设计包的全部声明SHA匹配，30张原卡与派生卡全部保持DRAFT_NOT_ADMITTED。原审计是唯一缺陷起点，历史PASS不继承。\n\n"
        "本机DSH0.2.0-rc.2、Claude Code2.1.287与Node22.22.1已查版本／help；这不证明模型、团队、Workflow、恢复可用。Claude入口是本机wrapper→ELF，不能按.exe扩展名判断Windows。\n\n"
        "现有8787服务、55432数据库与8个Worker保留；本轮尚未执行新模型调用。Docker不在PATH。只允许一个协调Cargo槽、2jobs；测试使用独立数据库与随机loopback端口。\n\n"
        "新增Capsule必须引用现有ExecutionEnvelope和AttemptState；不新建CanonicalTask第二状态机，不把native completed或退出0当业务成功。\n")
    rows = ["# 30张拟新增卡准入复核\n", "原稿不变，原卡和派生卡均DRAFT_NOT_ADMITTED。开发准入记录与产品运行租约分开。\n",
            "| 卡 | Owner | 路径核对问题 |\n|---|---|---|\n"]
    for row in reviewed:
        rows.append(f"| {row['id']} | {row['owner']} | " + ("；".join(sorted({x['kind'] for x in row['review_issues']})) or "领地初核匹配；仍需实际契约与调用链核验") + " |\n")
    rows.append("\n两项跨Owner修改（FFN-002 catalog、FFN-014 operations）必须由A00登记临时转交；同文件跨卡串行。新Rust文件必须含module导出与真实调用方，不能只创建孤立文件。tests/next草案必须映射到可执行测试入口。\n\n公共合同首先锁定canonical identity、只读native observation、Driver资格和write authorization；原方案中的work_unit_id/git_base_sha/validation_plan_id与示意状态不直接落库。\n")
    (docs / "admission-review.md").write_text("".join(rows))
    save(ROOT / "team/next-admissions.json", {"schema_version": "forgeflow.next.development-admissions.v1", "at": stamp,
         "source_head": head, "baseline": str((output / "baseline.json").relative_to(ROOT)),
         "note": "No product runtime lease. Original30draft statuses are unchanged; A00 records reviewed exact development scopes separately.",
         "grants": []})
    print(json.dumps({"baseline": str(output.relative_to(ROOT)), "cards": len(reviewed),
                      "cards_with_path_issues": sum(bool(x["review_issues"]) for x in reviewed),
                      "qualification": "NOT_RUN", "model_calls": 0}))


if __name__ == "__main__":
    main()
