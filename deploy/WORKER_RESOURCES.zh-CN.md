# 独立 Worker 的物理资源委派

本入口用于 Linux/WSL2 的 cgroup v2 与用户级 systemd。必需物理限额的任务需要固定 Worker/runtime 和专用委派服务。当前工程版已完成一次有限进程的实际 CPU、内存、pids 限制及回收验证；完整业务链的验证范围见[当前交付状态](../docs/DELIVERY_STATUS.zh-CN.md)。

## 权威预算与物理限额

资源档案可声明 `physical_limits`，版本为 `forgeflow.physical-limits.v1`，包含必需标志、CPU单位映射、CPU周期、进程/线程上限、swap上限和整组OOM策略。控制面在原准入事务内冻结精确资源向量，并预留根会话与最大活动子会话的整体预算；原生子会话从已持有的池借用，不能在OS限额形成后才补记未批准资源。

`cpu_units` 不默认为CPU核心数。例如250单位、`cpu_units_per_cpu=1000`、周期100000微秒，对应 `cpu.max=25000 100000`。这是CPU带宽限制。`memory.max` 使用字节；`pids.max` 计入线程，和Agent人数不同。缺少显式物理政策的旧档案继续标明未验证；必需限额建立或回读失败时拒绝启动，不回退为无限额执行。

## 只有专用服务管理它自己的资源树

`ops/run-delegated-worker.py` 生成唯一服务 `forgeflow-worker-<UUID>.service`，交给已有用户管理器。服务使用：

```ini
[Service]
Type=exec
Slice=forgeflowresources<UUID>.slice
Delegate=cpu memory pids
DelegateSubgroup=supervisor
KillMode=control-group
Restart=no
UMask=0077
NoNewPrivileges=yes
```

唯一私有slice不经过共用 `app.slice`。服务的监督进程直接出生在 `supervisor` 叶组。bootstrap通过 `systemctl --user show UNIT -p ControlGroup --value` 发现实际私有root，并核对自己的 `/proc/self/cgroup`、UID、空内部节点和实际委派控制器；不将原 `/init.scope` 命令行进程迁入用户树，不写全局或其他任务的限额，也不使用sudo或重新挂载。

Worker私有配置副本增加 `cgroup_delegation: {unit_name, root_path}`；原配置及全部其他字段保留原摘要。运行时为独立项目/尝试准备叶组、写入与回读限额、记录绑定，并通过pre-exec把子进程放入该组后才运行命令。业务执行仍要求强沙箱，不能把可写宿主cgroup控制文件暴露给DSH。取消与恢复需要正向进程停止、wait/reap及 `cgroup.events populated=0`；状态不明保留隔离。

## 准备与审阅

以下命令只读取能力或生成新私有计划，不启动Actor：

```bash
python3 ops/run-delegated-worker.py capability
python3 ops/run-delegated-worker.py prepare --kind worker \
  --program /absolute/new-checkpoint/bin/forgeflow-worker \
  --program-sha256 WORKER_SHA256 \
  --config /absolute/private/worker.json \
  --env-file /absolute/private/worker-env.json \
  --output /absolute/fresh/private-delegated-worker
```

配置和环境文件必须属于当前UID、权限0600，输出目录新建为0700。`worker-env.json` 只接受 `FORGEFLOW_WORKER_TOKEN` 与可选 `RUST_LOG`，令牌不写入unit文本、不在输出显示；模型密钥继续使用原配置中的私有文件引用。Worker和解释器使用确切ELF路径与摘要。

准备结果返回plan/unit摘要。先执行dry-run审阅：

```bash
python3 ops/run-delegated-worker.py start \
  --plan /absolute/private-delegated-worker/launch-plan.json \
  --plan-sha256 PLAN_SHA256 --unit-sha256 UNIT_SHA256
```

确认计划引用的是所选版本的固定二进制和私有配置后，对同一命令添加 `--execute`，启动这个专用服务。bootstrap读取实际委派root，生成0600派生配置及发现收据，随后exec固定Worker。该命令不创建任务；任务仍经控制面的合法准入执行。

## 一次有限真实进程证明

有限helper验证真实Rust `supervise_physical`，不启动API、不调用模型、不连接业务Worker。固定限额为0.25 CPU带宽、64MiB内存、swap0、pids8、整组OOM；实际helper先确认membership和限额，再运行8秒CPU忙循环、最多16次fork以观察EAGAIN，回收子进程后按页触碰最多128MiB内存。整轮runtime超时20秒。监督进程始终位于不受该叶组限额影响的 `supervisor` 组。

需要在新机器验证内核限额时，使用所选固定版本准备无密钥probe；已有机器的同版本结果无需重复运行：

```bash
python3 verification/physical_resource_check.py prepare \
  --runtime-program /absolute/new-checkpoint/bin/forgeflow-worker \
  --receipt /absolute/new-checkpoint/receipt.json \
  --output /absolute/fresh/private-physical-proof
python3 ops/run-delegated-worker.py prepare --kind probe \
  --program /absolute/new-checkpoint/bin/forgeflow-worker \
  --program-sha256 WORKER_SHA256 \
  --config /absolute/private-physical-proof/probe-input.json \
  --output /absolute/fresh/private-physical-unit
```

使用上面的 `start --execute` 启动这个新probe服务。它调用 `forgeflow-worker --physical-resource-probe`，经真实资源监督接口执行固定helper，写入原始launch/stop/stdout/stderr及限额事件；Worker令牌不参与此证明。等待该确切unit/进程的终态，保留失败；观察超时时先处理原进程，不重复启动同类试验。

最后仅收集已有实际证据：

```bash
python3 verification/physical_resource_check.py collect \
  --prepared /absolute/private-physical-proof/prepared.json \
  --prepared-sha256 PREPARED_SHA256 \
  --output /absolute/control/evidence/physical-resource-fencing-r1/oracle-report.json
```

通过条件是：实际launch身份与工作前membership匹配；CPU有正 `nr_throttled/throttled_usec`，实际CPU用量符合预先固定的两周期容差；fork出现EAGAIN且 `pids.events max` 增长，全部fork子进程被回收；本地 `memory.events` 出现OOM及oom_kill，原helper实际SIGKILL/reap；叶组正向确认空，外部监督进程仍存活。内存峰值可能暂时超过 `memory.max`，不能凭单次peak较高伪造失败或改写限额。宿主饥饿导致未观察CPU节流时标为INCONCLUSIVE。

这里最多证明这个内核/UID/unit/固定二进制下的一次有限可信进程CPU、内存和pids限额。它不证明已取得控制面准入、原生整体池、恶意代码隔离、模型/GPU/费用硬限制或100+真实DSH生产资格。

## 控制面验证器的物理限额入口

控制服务默认不启用委派。需要执行带必需物理政策的独立验证时，在所选新版本安装入口添加 `--verifier-cgroups`：

```bash
python3 ops/manage-service.py install \
  --name forgeflow-control \
  --release-dir /absolute/installed/release \
  --runtime-env /absolute/private/runtime-env.json \
  --verifier-cgroups
```

该选项只接受 `forgeflow-control` 或 `forgeflow-control-<32位小写十六进制>` 名称，不能与 `--worker-config` 共用。服务使用自己的私有 slice、`Delegate=cpu memory pids` 和 `DelegateSubgroup=supervisor`；安装不带 `--start` 时不启动进程。已存在的不同版本 unit 会被拒绝覆盖，按部署手册的停机切换步骤处理。

固定 launcher 在启动时核对实际 unit、cgroup v2、UID、空内部节点、控制器以及自己的 `supervisor` membership，再动态注入 `FORGEFLOW_VERIFIER_CGROUP_DELEGATION`。不要在私有环境文件中设置这个变量；launcher 会拒绝预选委派配置，也不会沿用同名继承环境。HTTP 请求不能提供 cgroup 路径或扩大限额。

验证器的 CPU、内存和 pids 上限来自任务准入时冻结的物理资源绑定。作者和原生子进程正向停止后，同一任务按权威登记串行借用已持有的池，候选与集成验证不再次计费。必需政策缺少合法委派、阶段互斥或正向停止证据时拒绝启动；组未确认空时保留资源与恢复记录。部署入口和配置存在不代表实际验证器限额已取得资格，运行证据范围仍以交付状态为准。

## 原始参考

内核的继承、内部节点、迁移权限、带宽、OOM与进程限额语义见 [Linux cgroup v2文档](https://docs.kernel.org/admin-guide/cgroup-v2.html)。专用service/scope委派和 `DelegateSubgroup` 见 [systemd委派说明](https://systemd.io/CGROUP_DELEGATION/)。本机systemd255的实际manpage也包含该配置；版本与只读权限观察不代替新服务的真实执行。
