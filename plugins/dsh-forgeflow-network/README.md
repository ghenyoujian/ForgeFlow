# ForgeFlow × DSH

此插件把每个用户自己的 DSH Agent 连接到共同项目，提供六个原生工具：
`forgeflow_identity`、`forgeflow_agents`、`forgeflow_send`、`forgeflow_inbox`、`forgeflow_ack`、`forgeflow_workflow_preview`。

支持已核对的官方 DSH **0.2.1-rc.5**。插件使用实际 DSH `agent.id` 和 scoped tools；模型不能选择发送者身份。
连接凭证仅授予当前账号、工作区、项目的通讯权限，有效期 8 小时。成员被移除、降为查看者、连接撤销或密码更新后立即失效。

在项目的 Agent 通讯页签发凭证，通过环境变量 `FORGEFLOW_CONNECTOR_TOKEN` 或本人拥有的 0600 文件提供。
不要把 Owner 令牌、Worker 令牌或模型 API Key 传给插件。配置文件与 `--dump-config` 不包含凭证明文。

```sh
node bin/forgeflow.mjs install --directory /absolute/new-plugin-directory \
  --dsh-node-modules /absolute/DSH/node_modules --url http://127.0.0.1:8787 \
  --workspace WORKSPACE_ID --project PROJECT_ID --token-file /absolute/private-token-file
node /absolute/new-plugin-directory/bin/forgeflow.mjs doctor --directory /absolute/new-plugin-directory
```

将生成的 `cordis.patch.json` 作为 `--patch /absolute/new-plugin-directory/cordis.patch.json` 加到现有 DSH 启动参数。
安装器只写入一个新目录，不改 DSH_HOME、不重启服务、不安装另一份 DSH、不启动模型。
回退时去掉此 `--patch`，撤销连接凭证，再删除安装目录。已有消息与执行历史保留。

```sh
node /absolute/new-plugin-directory/bin/forgeflow.mjs workflow \
  --directory /absolute/new-plugin-directory --output /absolute/personal-site.request.json
```

此命令准备 DSH 原生 `workflow` 工具请求。向该工具传入 JSON 中的 `meta`、`script`、`args`，
默认 `execute=false`：只校验和展示编排，不创建 Agent。引擎应为官方 workflow-ptc；不把 `export const meta` 写在脚本里。
真实执行必须通过 ForgeFlow 的受管准入、已审定 Flow、冻结档案、Worker 与模型约束；
`approvedFlowRef` 只是可追溯引用，不是授权凭证。插件不会增加运行、完成、验收或资源释放权限。

消息使用 `forgeflow.agent-network.v1`，持久游标读取＋显式接收回执，至少一次交付。
同一消息重试必须复用 `client_message_id`；不同内容复用会冲突。`thread_id/reply_to` 串联会话。
已保存消息在接收方撤销后仍可按原 ID 重试读取结果；发送方自身仍须具备当前权限。新消息不能发给已撤销身份。
凭证文件在打开时拒绝符号链接和命名管道，并校验所有者、0600 权限、普通文件及实际读取字节上限；HTTP 响应流达到 4 MiB 上限即取消，保留原 10 秒超时。原生 SDK 允许额外参数，插件仅转发声明的消息字段，发送者始终来自当前 Agent。
消息对项目成员可见，只分享经过选择的内容；收到消息不自动唤醒模型，也不表示任务通过验收。
DSH 内置 `send_message` 仍负责本地团队；`forgeflow_send` 用于跨用户的项目协作。

详细教程见站内「个人网站教程」及 `docs/ops/personal-website-tutorial.md`。
当前没有声称完整实现 A2A、MCP 或 ACP 服务端，也没有开放跨不相关工作区的联邦投递。
