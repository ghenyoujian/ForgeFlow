# Next 30 张草案卡现场核对（A10）

本目录当前只有独立静态核对结果，不授予开发、生产迁移、模型调用、清理或发布权限。所有卡保持 `DRAFT_NOT_ADMITTED`；开发准入必须由 A00 另行签发。当前未运行 Cargo、浏览器、模型或数据库变更，不得从本结果生成产品 PASS。

逐卡结果在 [card_review.json](card_review.json)，现场环境引用 [A00 bootstrap baseline](../../evidence/next/20261015T003541Z-00f024640b/baseline.json)。该基线包含版本/help/资源身份，不证明真实模型、Team、Workflow、取消和恢复能力。

真实 Git 根为 `control`，HEAD 为 `00f024640b9a4ad3f85b9a6d339291a9f4611963`。这是保留大量既有未提交内容的共享工作区；不能把相同 HEAD 当作相同源码。原独立审计的 tested 源身份为 `e155b213adda00d14d14b160178336eea50872a3820a521a444070b939088273`，本轮不能继承其资格。JSON 对输入文档和各已存在卡片路径记录 SHA-256；并行工作会使后续字节变化，准入时必须再次核对。

## 逐卡核对计数

- 30 张卡、51 条路径声明、50 个不同路径；核对时 21 条路径已存在、30 条待新增。
- 11 张卡与旧 73 张任务的精确路径重叠。这是历史领地承接，不代表 11 个并发写冲突；需核对旧卡在途执行权并冻结当前 diff。
- 8 张卡的 12 条路径不在其原 Owner 领地。FFN-002 的 `catalog.rs` 已有 A00 登记的限范围临时转移；FFN-014 的 `operations.rs` 尚未转移；5 张 QA 卡的 9 条 `tests/next` 路径未登记；FFN-029 的 `release-receipt.md` 需登记。
- 新矩阵唯一显式同文件重叠为 FFN-012/025 的 `crates/api/src/lib.rs`。补齐模块导出之后，A01/A02/A03/A04 也会分别共享各 crate 的 `lib.rs`，必须同 Owner 串行接入。
- 9 类合同、权威、身份和 Gate 范围冲突或待证假设，详见 JSON `contract_conflicts`。30 卡均欠完整现场准入字段；没有一张可由 QA 自动变为 READY。

这里的存在性、所有权和源码结构属于可复查静态事实；所有运行 Gate 为 `NOT_RUN`。原审计 F01/F02/F03 等状态保留原证据，不因静态核对而升级。

## 必须先纠正的内容

1. **F01 优先**。API 原 `git_read` 能触发仓库配置的 fsmonitor。A05 在临时转移范围内接入安全只读包装，补 `crates/git/src/lib.rs` 导出和独立正负例。旧代码 canary 应能触发，新代码必须不触发；branch/dirty/路径检测不能丢失。不要仅验证命令退出码。
2. **合同不引入第二套状态权威**。Next §11 的 `CanonicalTask PLANNED/READY/ADMITTED/.../DONE` 只能是 UI 派生投影。现有任务规划态、AttemptState、租约和集成终态保持 canonical。Capsule 只能绑定已有 Attempt；其 native task completed 不得写正式 SUCCEEDED。
3. **Capsule 表不是默认答案**。FFN-006 先检查已有 `attempts`、`native_sessions`、`native_child_lifecycles` 和 documents。0003 的 opaque session 全局主键与单 attempt 唯一绑定，0009 的多 lifecycle 共同构成兼容约束；provider/profile/attempt/generation 的映射和当前活动身份须明确。不要用机械 1:1 覆盖历史或 resume。
4. **资源原子性在 Store**。FFN-011 只加 scheduler policy 不会让资源不超限。复用原有 Store 原子 admission、祖先额度、native grants、`UPFRONT_NATIVE_POOL` 与 stop proof。Capsule 不另扣、另放相同额度。A02 提需求，A01 修改其 Store 领地并提供事务反例。
5. **新增 Rust 文件必须接调用链**。Domain capsule、executor doctor/Claude/team、Worker supervisor、Store capsule/blob、scheduler policy/frontier 都缺原矩阵列明的模块导出或调用点。JSON 每卡 `extra_paths` 和 `proposed_extra_path_review` 给出建议范围及 Owner。这些是待 A00 注册的建议，不能直接作为允许写入清单。
6. **部署入口要能运行**。FFN-009 除 Dockerfile 还需 server `main.rs`、CLI `main.rs` 的 `up` 接入和 `.dockerignore`。当前 Cargo target 在 `/home/...`，Docker COPY 读 `/src/target`；海量 benchmarks 也不能进入镜像构建上下文。manifest/lock 和根文件仍由 A00 裁决。
7. **修复真正发起 404 的 UI**。FFN-025 后端路由归 A09；`UtilityPages.tsx` 的 `/recovery-items` 与 `/backups` 调用归 A06，需独立消费卡。备份要有持久 operation、quiescence、manifest/hash 和独立目标，不能用临时 shell/toast 伪装成功。
8. **轻量化先量空间再扩表**。FFN-023 优先评估 existing documents/blob refs 与 0012 冻结 profile 的复用，量化 TOAST/索引/WAL/文件对象成本。一个 blob PoC 不等于 F04 事件冷归档、F05 幂等精确重放、F06 大正文去重全部完成；没有生产迁移、GC 或工作树删除授权。

## 原生执行资格边界

`claude -p` 是 leaf/subagent 路径；不因实验 flag、help 或输出中出现子代理就成为交互式 Teammate Team。交互 Team 的 Lead+2、任务、消息、Hook、PTY 停止分别需要当前安装版本实证。内部 mailbox 不作稳定 RPC；无法证实的交互操作只读或禁用。

DSH Headless 没有原生浏览器服务器。预设内有 workflow/team-binding/managed-bridge 和已安装 UI 包，不证明当前 Native Team 已运行；保留已有桥和原始身份，不重造内部 task authority。58 岗位的专项策略不得不经版本化 profile 就套到通用 Claude leaf；也不能直接删除以放宽安全。

Next 文档中的 Claude Workflow 版本、16 内部并发等只是待本机验证的假设；本核对没有联网或调用执行器确认这些动态产品能力。Doctor 应分开 `documented`、`probed`、`verified`，A00/A04 的版本/help 基线只覆盖前置身份。

## 推荐实施顺序

1. A00 固定 dirty 源身份、资源和 Owner；A01 冻结四份合同；A04 零模型 Doctor；A10 准备隔离 runner。
2. 修 F01 并用旧/新 canary 双侧验证。在安全导入成立后进入真实项目和执行实验。
3. A01 Store 最小映射/资源事务、A04 Claude leaf、A03 Worker 原监督链接入，A09 Lite/受鉴权 API；F02/F03 保留原反例并修正确层次。
4. 获明确 Provider、额度和费用上限后，各跑一条真实 DSH/Claude leaf→独立验证→Git 集成。无授权记 BLOCKED。
5. A06 Shell/API consumer，A07 Flow，A08 Theater/Team，在不重叠领地并行。实际控制按钮以能力和租约证据解锁，不由 UI 状态猜测。
6. Native Team/Workflow、冷存储、frontier、故障注入和容量逐项独立资格。128 通道须当前源码 >=3600 秒；UI-2 含 3000 任务与冻结性能基线。原型或短 smoke 不能获完整 Gate。
7. FFN-029 先形成工程候选收据，FFN-030 独立冷启和完整人机操作后，A00 才裁决生产资格。不能以时间窗结束或“已发布”倒推 PASS。

FFN-012 建议增加安全 Git、Worker 和资源事务前置；FFN-015 增加 DSH 停止分类/额度约束；FFN-021/022 原生团队在单 leaf 真链成立后试验；FFN-024 调度优化先经过故障/不变量回归，再参加 RT-1。JSON 中附各卡补充依赖，尚未写回原矩阵。

## 测试入口与复查

这是虚拟 Cargo workspace，根 `Cargo.toml` 只有 `[workspace]`，没有 package/`[[test]]`。在根 `tests/next/*.rs` 写文件不会让 `cargo test --workspace` 自动执行它们；测试数量零也可能退出零。建议 A10 使用已登记 `verification/next` 的明确 Python/Playwright runner；Rust case 放在真实 crate 的 `tests/` 并由该 Owner 写入，或由 A00 注册独立 test harness。不得擅自增加 root package 解决发现问题。

下列命令仅检查交付结构，没有运行业务资格；在 `control` 根执行：

```bash
python3 -m json.tool verification/next/card_review.json >/dev/null
python3 - <<'PY'
import json
from pathlib import Path
r = json.loads(Path('verification/next/card_review.json').read_text())
p = json.loads(Path('../docs/idea/ForgeFlow_Next_设计改造交付包/实施任务矩阵_DRAFT.json').read_text())
assert len(r['cards']) == len(p['tasks']) == 30
assert {x['id'] for x in r['cards']} == {x['id'] for x in p['tasks']}
assert all(x['status'] == 'DRAFT_NOT_ADMITTED' for x in p['tasks'])
assert all(x['admission_status'] == 'DRAFT_NOT_ADMITTED' for x in r['cards'])
assert all(x['runtime_gate_result'] == 'NOT_RUN' for x in r['cards'])
print('30 cards covered; draft status preserved; no runtime Gate granted')
PY
```

初轮卡片核对只写 `verification/next/card_review.json` 与本文件；后续独立 F01 脚本见下节。没有修改原任务矩阵、业务源码、依赖或生产账本，没有复制大型实验材料，没有运行 Cargo、模型、浏览器或生产数据库实验。父设计的全篇结构和相关状态、执行、Git、合同、所有权、Gate 章节已核对；其他叙述性章节没有逐一实测，运行成熟度继续以原审计证据为起点。

## F01 独立边界脚本（A10，后续补充）

[f01_boundary.py](f01_boundary.py) 只使用 Python 标准库和固定 `/usr/bin/git`。默认创建一个全新的 0700 临时目录，建立 10 组真实普通、dirty、bare、linked、fsmonitor、clean/process filter、include、alternates、metadata symlink 仓库。所有可执行 canary 仅向这个临时目录写无害 marker；不会读真实项目、调用模型、启动服务或数据库、删除既有目录。没有 HTTP 默认地址。

```bash
python3 verification/next/f01_boundary.py
```

默认输出 `fixture-manifest.json` 的路径，API 状态为 `NOT_RUN`、网络请求数为 0。`commands.json` 保留实际 Git argv、退出码、标准输出、标准错误和耗时。旧 fsmonitor 和同字节长度改动的 clean-filter 用例必须实际触发 canary；process-filter 与 include 的 fixture 也先用未保护 Git 验证可触发。触发后的 marker 移入 `legacy-evidence/` 保存，API 测试使用原 marker 路径，不能混入旧触发结果。process canary 故意不实现完整 Git process-filter 协议；它仅证明 Git 曾启动配置的进程，不证明过滤协议成功。

本轮最终默认运行的证据为 `/tmp/forgeflow-f01-a10-si0ki428/fixture-manifest.json`，10 组 fixtures、4 条旧行为 canary 均成立，退出 0；API 未运行。首次脚本版本的 `/tmp/forgeflow-f01-a10-r3z3eq0n/` 也保留，不能替代最终脚本的源码指纹。临时目录可能受系统临时文件策略影响；A00 若需要长期保存，应只收录 manifest、commands、marker 与 API result 等小型证据，不复制整套运行账本。

A00 自行启动已构建的**隔离** API 和隔离配置后，显式运行：

```bash
python3 verification/next/f01_boundary.py \
  --fixture-manifest /tmp/forgeflow-f01-a10-si0ki428/fixture-manifest.json \
  --base-url http://127.0.0.1:18877 \
  --token-file /absolute/private/isolated-owner-token \
  --server-pid 12345
```

`18877` 和 PID 为示例，不表示该端口已有隔离服务。不得指向正式 API；脚本拒绝端口 8787、非 loopback、隐式端口、带账号/路径/query 的 URL、HTTP 重定向和环境代理。token 文件必须是当前用户拥有、group/other 不可读的普通文件，符号链接拒绝；token 不进入 argv、报告或异常输出。调用只使用源码实际存在的 `POST /api/v1/project-probes`，DTO 为 `{"root_path":"<fixture绝对路径>"}`，没有创建项目、导入或数据库写操作。

**环境注入必须作用于服务端**。fixture 根内 `server-environment.json` 给出恶意 `PATH/GIT_DIR/GIT_WORK_TREE/GIT_CONFIG_*/GIT_INDEX_FILE/objects/namespace` 等受控值，路径全部指向临时 fixtures。A00 应在启动隔离 API 时读取此 JSON 合并进子进程环境，绝不能写入系统环境配置或正式服务。绝对 server binary、隔离数据库/数据目录、认证配置由 A00 另行明确绑定。HTTP 客户端设置这些环境变量不构成服务端反证。

可选 `--server-pid` 会从 `/proc` 核对该进程实际环境中每个注入值，并确认该进程持有请求端口的 LISTEN socket，记录二进制 SHA；只导出逐键是否匹配，不导出其他环境值或凭据。未提供 PID 时环境注入为 `NOT_RUN`，即使 10 个 API 用例通过，总结果也只为 `PARTIAL`；PID/环境/端口不匹配为 `FAILED`。A00 仍需把构建源身份、binary、配置和隔离部署证据与报告绑定，不能由一个 PID 推断代码资格。

API 检查逐项核对真实 `git_repository/bare/head/branch/dirty`，其中配置 clean/process filter 必须返回 `dirty:null` 而非假 clean；include/alternates/metadata symlink 必须拒绝仓库。每次调用前检查 marker 是否已存在，存在则 `INCONCLUSIVE` 并保留；不会通过删除 marker 制造通过。所有 fixture 文件/元数据在请求前后比较 SHA，包括 index/config、linked worktree 双向元数据；任何新执行 marker 或其他变化导致失败。

API 结果以新名字 `api-result-<id>.json` 保留，含原始响应的脱敏表示、比较项、分母、耗时、marker 和 metadata 差异。不调用模型；不用 HTTP 200 独自判定通过。同 UID 并发恶意修改仓库元数据不在此包装的沙盒保证范围内；fixture 保持静止，运行时 metadata race 需要另行隔离设计。

本次额外实际验证了 `http://127.0.0.1:8787` 和 `http://192.0.2.1:18877` 均在读取 token/创建 fixture/发送网络请求之前拒绝，退出 2。隔离 API 正反例仍等待 A00 启动对应版本；没有用 mock HTTP 结果补齐。
