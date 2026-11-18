# ForgeFlow 本地部署与首次使用

交付包把固定 Rust 二进制、控制台、数据库迁移、API/Schema、DSH 协作预设、完整源码和选定证据放在同一目录。实际资格和未完成项查看 `planning/gates.json`、`planning/known-risks.json` 与 `evidence/index.json`。安装本身不改变这些结论。

## 1. 安装到新目录

使用 Linux/WSL2 的 Linux 文件系统。先选择交付包和一个尚不存在的安装目录：

```bash
python3 /absolute/forgeflow-package/ops/package-checkpoint.py verify \
  --package /absolute/forgeflow-package --require-complete-source
FORGEFLOW_INSTALL_ROOT=/absolute/fresh/forgeflow-version \
  /absolute/forgeflow-package/ops/install-local.sh \
  --package /absolute/forgeflow-package
```

安装会核对原始构建收据、4 个二进制、源码归档和每个文件的 SHA256，并复制现有文件。持久数据和项目源码放在安装目录之外。服务器和 Worker 分别运行。

## 2. 配置并启动服务器

准备 PostgreSQL 16 数据库；已有 PostgreSQL 可以直接使用。用户自有的本机集群可通过安装目录的 `ops/postgres-local.sh start` 启动。数据库迁移在服务器启动时执行，迁移原文位于 `migrations/`。

创建只允许服务账号读取的 JSON 环境文件，例如 `/absolute/private/runtime-env.json`，权限设为 `0600`。以下占位值需要替换，密码、连接凭据和不同服务令牌写入这个文件：

```json
{
  "DATABASE_URL": "postgresql://forgeflow:REPLACE@127.0.0.1:5432/forgeflow",
  "FORGEFLOW_BIND": "127.0.0.1:8787",
  "FORGEFLOW_DATA_ROOT": "/absolute/ff-data",
  "FORGEFLOW_CONSOLE_DIR": "/absolute/forgeflow-version/console",
  "FORGEFLOW_OWNER_PASSWORD": "REPLACE_WITH_AT_LEAST_12_CHARACTERS",
  "FORGEFLOW_OWNER_TOKEN": "REPLACE_WITH_RANDOM_OWNER_TOKEN_AT_LEAST_24_CHARACTERS",
  "FORGEFLOW_WORKER_TOKEN": "REPLACE_WITH_DISTINCT_RANDOM_WORKER_TOKEN_AT_LEAST_24_CHARACTERS",
  "FORGEFLOW_WORKER_CREDENTIALS_FILE": "/absolute/private/worker-credentials.json"
}
```

多项目部署为每个 Worker 配置独立令牌。创建由服务账号拥有的普通文件 `/absolute/private/worker-credentials.json`，权限为 `0600`，内容如下；Worker 与项目 ID 使用实际已创建的身份，令牌使用分别生成的随机值：

```json
{
  "schema_version": "forgeflow.worker-credentials.v1",
  "workers": [
    { "worker_id": "worker-a", "project_id": "project-a", "token": "REPLACE_WITH_DISTINCT_RANDOM_TOKEN_A_AT_LEAST_24_BYTES" },
    { "worker_id": "worker-b", "project_id": "project-b", "token": "REPLACE_WITH_DISTINCT_RANDOM_TOKEN_B_AT_LEAST_24_BYTES" }
  ]
}
```

Worker ID 和令牌各自唯一，令牌与负责人令牌及原共享令牌不同；同一项目可以登记多个 Worker。服务拒绝符号链接、不安全权限和无效清单。配置该文件后，原共享 Worker 令牌不能登录；每个 Worker 的私有环境 `FORGEFLOW_WORKER_TOKEN` 应填写自己的清单令牌，`worker.json` 中的 Worker／项目 ID 必须相符。修改清单后，先停止新派发、结算活动尝试，再重启控制服务使新清单生效。未配置该文件的旧单服务部署仍可使用原共享令牌与部署作用域。

原生受管 DSH 使用短数据根，例如 `/home/your-user/ff-data`，其 Unix socket 完整路径必须不超过 100 字节。创建数据目录后，使用下面的命令加载私有配置并启动；命令不会打印配置值：

```bash
python3 - /absolute/private/runtime-env.json \
  /absolute/forgeflow-version/bin/forgeflow-server <<'PY'
import json, os, pathlib, stat, sys
config_path = pathlib.Path(sys.argv[1])
if stat.S_IMODE(config_path.stat().st_mode) != 0o600:
    raise SystemExit("runtime-env.json must have mode 0600")
values = json.loads(config_path.read_text())
if not isinstance(values, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in values.items()):
    raise SystemExit("runtime environment must map string keys to string values")
program = sys.argv[2]
os.execve(program, [program], dict(os.environ, **values))
PY
```

在另一终端执行 `curl --fail http://127.0.0.1:8787/healthz`。打开 <http://127.0.0.1:8787>，用负责人密码登录。复用同一数据库和数据根重启后，负责人身份、项目和历史保持原身份。

需要持续运行时，先停止上述前台服务器，使用用户级 systemd 托管：

```bash
python3 /absolute/forgeflow-version/ops/manage-service.py install \
  --release-dir /absolute/forgeflow-version \
  --runtime-env /absolute/private/runtime-env.json --start
systemctl --user status forgeflow-control.service
```

服务使用交付清单核对二进制摘要，并加载权限为 `0600` 的私有配置；凭据不写入 unit 文件。进程失败后自动重启，停止使用 `systemctl --user stop forgeflow-control.service`。运行期间需要用户级 systemd 管理器；退出登录后是否持续运行取决于系统的用户服务策略，WSL 关闭后需重新启动系统。更换版本前先停止派发、结算活动尝试并停止服务，再核对和更新 unit。旧 unit 与新配置不同时，安装脚本拒绝覆盖。

## 3. 接入项目和真实 DSH

从 **总览 → 接入项目** 创建受管项目，选择实际已提交且工作区干净的 Git 仓库。控制面为普通源码仓库建立独立 bare Git 权威仓库。只读观察项目用于读取历史，不授予执行权。

在 **团队与队列** 建立根团队和子团队，登记 Owner 的精确代码领地。在 **资源** 配置已批准容量。执行前还需登记该项目的执行器、模型路由、资源档案和作者/消费者/独立验证计划。通用登记入口为 `POST /api/v1/projects/{project_id}/documents/{collection}`，请求为 `{ "id": "...", "value": { ... } }`；集合使用 `executor_profiles`、`model_routes`、`resource_profiles`、`verification_plans`。这些值必须来自当前实际配置及其文件摘要，不能把示例 ID 当作已配置档案。

DSH 协作预设位于 `executors/presets/forgeflow/`，模式为 `forgeflow-collaboration-v2`，包含 Lead/Owner/Implementer/Verifier、Workflow、Agent Teams、Subagent、规划、任务、目标、会话查询、检查点及上下文压缩。每个根会话、子会话和模型请求均通过 Worker 向唯一控制面申请。外部 DSH、Node.js、模型配置及沙箱工具由部署环境提供。个人 DSH 配置不会作为尝试的可写共享目录。

按 `crates/worker/README.md` 准备私有 `worker.json`；`project_id` 对应已创建项目，`data_root` 与服务器相同，`profile` 和 `managed_dsh` 引用当前固定文件、私有模型配置和真实 Doctor 收据。执行器配置迁移到不同机器或路径后需要重新建立文件 pins 和 Doctor。初次验证使用小并发，再依据实测增加。

先运行本地身份检查：

```bash
/absolute/forgeflow-version/bin/forgeflow executor doctor \
  --profile-json /absolute/private/headless-profile.json \
  --workspace /absolute/managed-project.git
```

Worker 从私有环境读取 `FORGEFLOW_WORKER_TOKEN`，启动命令为：

```bash
/absolute/forgeflow-version/bin/forgeflow-worker \
  --config /absolute/private/worker.json
```

可复用第 2 步的私有 JSON 加载方式，以 `os.execve(program, [program, "--config", config], environment)` 启动 Worker。其凭据不进入监督子进程。安装目录 `crates/worker/README.md` 给出完整字段、受管模式、取消及恢复语义。

为 Worker 单独准备权限为 `0600` 的 `/absolute/private/worker-env.json`，其中 `FORGEFLOW_WORKER_TOKEN` 使用该 Worker 的清单令牌。Worker 也可使用 `manage-service.py install --name forgeflow-worker-main --release-dir /absolute/forgeflow-version --runtime-env /absolute/private/worker-env.json --worker-config /absolute/private/worker.json --start` 建立独立用户服务；该操作只启动已配置的 Worker，不自动创建任务。

资源档案声明必需 `physical_limits` 时，使用[专用资源委派服务](WORKER_RESOURCES.zh-CN.md)启动 Worker。普通前台命令和上述普通服务没有资源委派；必需物理限额的任务会拒绝在这种 Worker 上启动。先准备私有配置及固定二进制，再通过 `run-delegated-worker.py prepare` 和 `start --execute` 启动专用服务。

## 4. 完成一个用户交付闭环

1. 在项目 **需求** 导入原文，核对来源 SHA 和需求锚点。
2. 选择根 Owner、预算团队、已登记执行器、资源及独立验证计划，提交真实 DSH 规划操作；失败时查看真实尝试、原始产物和验证错误，再用新尝试修正。
3. 在 **Flow** 审阅有限结果、依赖、Owner、读写集和验证；配置真实执行，运行检查，审定当前版本。
4. 在 **团队/任务** 分工并入队；从 **执行** 查看实际尝试、日志、资源与取消结果。
5. 在 **排程** 维护三点工作量、容量预览、甘特、日程和里程碑；计划日期与实际运行事实各自保存。
6. 在 **证据/集成** 核对作者、消费者和独立验证的真实分母、原始文件摘要、候选及集成 SHA。由控制面串行集成后，再判断对应需求的验收。

详细页面操作见 `docs/USER_GUIDE.zh-CN.md`。核心对象使用稳定 ID，刷新和深链接读取数据库事实；模型回复成功、退出零和规划草案不代表业务交付完成。

## 5. 更新、备份与恢复

更新使用新的版本目录。先停止新派发，等待或合法取消活动尝试，保留候选和原始证据，再按 `deploy/RUNBOOK.md` 执行协调备份。对同一数据根只运行一个服务器权威。

`ops/backup.py` 导出数据库、数据根及显式指定仓库并记录 SHA；`ops/restore.py` 恢复到新的空数据库和新目录，随后使用离线路径迁移、轮换身份并以暂停模式核对历史。恢复步骤及取消不明、数据库故障、磁盘不足的处理见 Runbook。归档源码中的 `ops/prune-build-cache.py` 可清理可再生成构建缓存，同时保护运行二进制和原始收据。

128 受控通道与 100+ 真实 DSH 的资格分别记录。生产百级模型并发需要实际机器、服务配额、费用及稳定性证据；当前交付清单中的 FAIL/INCONCLUSIVE 保持可见。

## 原生模型出口与事件保留

严格模型出口的 Worker 配置见 `crates/worker/README.md` 的 `managed_dsh.model_relay`。原生 DSH 和工具使用禁止直接联网的沙箱，只持有占位凭据；固定 Node 加载器通过本次尝试的私有 Unix socket 转交已批准请求。真实提供商密钥只保存在控制服务账号的私有文件中。控制服务环境通过 `FORGEFLOW_GATEWAY_CONFIG` 指向权限0600的配置文件，固定 `route_id`、`model`、`upstream_messages_url`、`upstream_secret_file`、`limits` 和 `timeout_seconds`，详情见 Gateway 与 Worker 文档。该配置不允许调用者选择任意上游地址，也不允许重试同一派发授权。

执行器 Doctor 必须包含当前加载器及桥接文件摘要；不要将旧 Doctor 用于变更后的预设。SDK 自动追加思考预算时，加载器将实际发送预算向下约束到单次授权上限，摘要绑定最终发送字节。提前结算会被拒绝；未知传输结果保持隔离，不能据进程退出直接释放模型资源。实际 SDK 路由验证与所有工具、远程委派、100+真实并发资格分别记录，不要手工将未获证据的 `gateway_coverage_verified` 改为 true。

服务器默认保留30天的实时事件窗口，每小时最多归档1000条旧事件；私有环境中的 `FORGEFLOW_EVENT_RETENTION_SECONDS` 和 `FORGEFLOW_EVENT_ARCHIVE_INTERVAL_SECONDS` 可调整该政策，范围均为1..315360000秒。归档通过数据库标记保留完整历史，最新一条项目事件始终留在实时窗口；它不清理历史存储，也不代替备份。过期或还原后超前的游标返回409 `SNAPSHOT_REQUIRED`；客户端重新拉取当前快照，再按其项目游标续传。原始历史继续通过分页接口读取并包含在数据库备份中。
