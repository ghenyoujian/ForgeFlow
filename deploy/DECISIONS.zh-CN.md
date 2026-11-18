# 资源暂停决策接口

所有路径以 `/api/v1` 为前缀。接口仅接受 Owner 会话或 Owner 服务令牌；Worker 返回 403。项目和决策身份由路径指定，正文不接受调用者提供的状态、授权者、预算或尝试状态。

| 方法与路径 | 正文或结果 |
|---|---|
| `GET /projects/{project}/decisions` | `data: Decision[]`，仅真实类型化 v1 决策 |
| `GET /projects/{project}/decisions/{decision}` | `data: Decision` |
| `POST /projects/{project}/decisions` | `{scope_id, expected_policy_revision, note}` |
| `POST /projects/{project}/decisions/{decision}/acknowledgments` | `{expected_revision, note}` |
| `POST /projects/{project}/decisions/{decision}/deferrals` | `{expected_revision, revisit_at, reason}` |
| `POST /projects/{project}/decisions/{decision}/resolutions` | `{expected_revision, expected_policy_revision, reason}` |
| `GET /decisions?project_id={project}` | 兼容项目列表；不带项目时汇总真实项目的类型化决策 |

所有 POST 必须提供 `Idempotency-Key`。重复同一请求保留该键；改变正文须使用新键。成功响应为 `{data: {decision, policy, created, policy_changed}, operation_id, replayed, source: "postgres"}`。这是已完成的 Store 事务结果，不是异步执行成功声明。

列表默认 100 条、最多 500 条，支持 `limit` 和 `cursor`，继续使用响应中的 `next_cursor`。项目列表的游标是决策 ID；跨项目列表的游标是 JSON 项目／决策二元组，须作为一个 URL 编码的参数传回。跨页读取不是冻结快照；界面不得将一页当作完整分母。历史任意 JSON 决策不进入此类型化列表。

`Decision.schema_version` 为 `forgeflow.decision-inbox.v1`；`cause` 固定为 `PAUSED_RESOURCE_POLICY`。记录包含项目／决策 ID、状态、打开时的 `policy` 快照、实际排队阻塞任务 `blocked_tasks`（任务 ID、任务版本和队列版本）、说明、创建／更新时刻、确认与解决人员和时刻、延后时刻、解决理由及行版本。`policy` 包含真实 `scope_id`、项目／团队绑定、`limits`、`paused` 和 `revision`；它不是实时占用量。当前策略从项目资源接口读取，分配量从项目快照读取，不将未知余量显示成零。

创建只能绑定本项目真实暂停的 ResourcePolicy 与精确版本；全局、Worker、跨项目策略不受此决策授权。Store 从真实排队任务派生阻塞项，调用者不能捏造阻塞列表。

`OPEN` 可确认成 `ACKNOWLEDGED`，或延后成 `DEFERRED`；确认后的决策也可延后。`revisit_at` 必须是未来一年内的 UTC 时间。延后不自动授权、恢复任务或解除暂停。只有 `ACKNOWLEDGED` 可解决；Store 在同一个事务中核对决策版本和打开时绑定的策略版本，将该策略的 `paused` 改为 false，同时保存决策与事件。预算保持原值；不会创建 Attempt、伪造成功或自动增预算。解除暂停后仍须由正常调度器重新检查当前准入条件。

说明和理由必须非空、最多 4096 字节且不含 NUL。`DEFERRED` 不会自动重新打开；后续决策仍须基于真实现状单独审阅。规范类型见 `contracts/decision-inbox.v1.json`。

版本或绑定过期返回 409 `REVISION_CONFLICT`，状态冲突为 409 `DECISION_STATE_CONFLICT`；越界策略为 422 `DECISION_SCOPE_DENIED`，无真实排队阻塞为 422 `DECISION_CAUSE_NOT_OBSERVED`；缺少幂等键返回 400；非法正文或转移返回验证错误。解决前应重新读取决策和当前策略；发生冲突后不得静默替换版本重试。请求结果未知时使用原幂等键查询式重试，保留原始失败信息。

本文件描述实现契约。编译、实际 Owner／Worker 授权、事务回放及 UI 闭环由主 Agent 统一验证；文档本身不提升 Gate。
