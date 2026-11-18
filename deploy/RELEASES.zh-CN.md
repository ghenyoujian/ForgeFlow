# 项目 Release 与后续阶段

这些接口仅供 Owner，前缀为 `/api/v1`。Worker 返回 403。项目、Release 身份由路径指定；调用者不能提供 actor、状态、清单内容、导出文件路径或成功标记。所有 POST 必须提供 `Idempotency-Key`；正文改变时使用新键，结果未知时保留原键重试。

| 方法与路径 | 正文／结果 |
|---|---|
| `GET /projects/{project}/releases` | `data: Release[]` |
| `GET /projects/{project}/releases/{release}` | `data: Release` |
| `GET /projects/{project}/phases` | `data: ProjectPhase[]` |
| `POST /projects/{project}/releases` | `{expected_project_revision,title,milestone_refs,installation,not_proven,risk_dispositions}` |
| `POST /projects/{project}/releases/{release}/candidates` | `{expected_revision,expected_main_sha}` |
| `POST /projects/{project}/releases/{release}/acceptances` | `{expected_revision,expected_manifest_sha256,note}` |
| `POST /projects/{project}/releases/{release}/exports` | `{expected_revision}` |
| `GET /projects/{project}/releases/{release}/exports` | `data: ReleaseExportReceipt[]`，已登记时一条、否则为空 |
| `GET /projects/{project}/releases/{release}/bundle` | 实际交付 tar 包下载，ETag 为真实包 SHA256 |
| `GET /projects/{project}/releases/{release}/manifest` | 真实冻结 JSON 字节下载，ETag 为字节 SHA256 |
| `POST /projects/{project}/releases/{release}/archives` | `{expected_revision,expected_project_revision,reason}` |
| `POST /projects/{project}/releases/{release}/reopenings` | `{expected_revision,expected_project_revision,title,goal,reason}` |

`milestone_refs` 为 `{milestone_id,milestone_revision,baseline_version}[]`。声明安装说明、未证明范围和风险处置不等同于通过全局生产 Gate；验收范围明确为 Owner 指定的项目里程碑。

POST 返回普通已完成事务收据：`{data:{release,project,phase,export,accepted},operation_id,replayed,request_id,source:"postgres"}`。`export` 没有导出时为 null，导出时包含真实 `artifact:{artifact_id,sha256}`、`manifest_sha256`、清单 `bytes`、包 `bundle:{artifact_id,sha256}`／`bundle_bytes`、内部 `source_archive_sha256` 和操作者。可用现有认证接口 `/artifacts/{artifact_id}/content?project_id={project}` 读取登记产物。

状态依次为 `DRAFT`、`CANDIDATE`、`ACCEPTED`。候选事务绑定真实 main SHA／树、指定里程碑的已接受版本、独立验证证据及实际产物身份；原子校验版本后冻结清单。接受事务核对调用者期待的冻结清单 SHA，而不是接收调用者生成的清单。

清单下载可用于审阅候选或已接受版本，不会产生验收或导出收据。导出仅用于已接受 Release：服务从 Store 获取无尾换行的规范 JSON 字节，在服务器产物目录内按 SHA 保存和登记文件，再由 Store 校验该文件与冻结字节完全一致后记录导出。服务同时用系统 Git／tar 生成真正的项目交付包，范围为 `MANIFEST_SOURCE_AND_BOUND_ARTIFACTS_BUNDLE`：`manifest.json` 保持原规范字节，`INSTALLATION.txt` 保持安装说明 UTF8 字节且不添加换行，`source.tar` 来自冻结 main SHA 的实际 `git archive --format=tar`，`artifacts/{artifact_id}` 包含每份绑定产物的实际字节。Store 独立核对包内成员集合、清单／说明／产物字节，以及与新执行的规范 Git 归档一致的源码归档 SHA 后，才登记真实包收据。包最大 256 MiB。可在干净独立目录解包并校验关键身份；这是项目源码／证据最小交付包，不是跨机可执行安装器或生产资格。从 `/exports` 实际回读持久收据，再下载 `/bundle`；对包校验 `export.bundle.sha256`／`bundle_bytes`，对独立清单校验 `manifest_sha256`，不要混用。Release 版本不会因导出增加；部分产物登记成功而最终 CAS 失败时也不会伪称 Release 已导出，重试保留原键；已有真实导出收据时复用其冻结文件身份并由 Store 回放，不重复生成包。

归档要求已接受且有实际导出、项目／Release 版本匹配，以及尝试、租约、资源和原生模型托管全部静止。重新打开要求已归档，并创建序号加一的新 ProjectPhase；项目解除归档但保持暂停，Owner 须单独审阅后续任务和准入。历史 Release、清单、证据和导出不改写。

列表默认 100、最多 500 条，按 `next_cursor` 续页；跨页不是冻结快照。Release 游标为 ID，阶段游标为固定宽度序号；将服务给出的游标原样传回即可。版本／状态冲突为 409，证据缺失 `EVIDENCE_INCOMPLETE`、导出不匹配 `EXPORT_MISMATCH`、无法静止归档 `ARCHIVE_BLOCKED` 为 422。发生冲突时重新读取并明确重新审阅，不能静默改版本重试。

规范类型和 Store 状态规则见 `contracts/release.v1.json`。源码与契约就绪不代表实际 GUI 闭环或产品 Gate 已验证；主 Agent 统一构建并执行必要真实业务验证。
