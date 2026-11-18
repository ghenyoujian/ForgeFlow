# ForgeFlow 通用受管协作预设

该目录提供四种通用角色、Workflow、原生 Agent Teams、subagent、规划、技能、
上下文和受管模型桥。项目 ID、岗位名册、任务总数、模型和期限由显式项目包提供。
默认空名册是模板，不能直接申请执行权。

使用 `ops/project-pack.py` 为实际项目生成非空名册、专用预设、岗位映射、模式和摘要。
岗位数量由冻结名册决定，支持包括 128 在内的正整数规模；声明数量不代表真实并发。
默认128个上下文/岗位名称与活跃上限分开；Workflow默认32，可选1/4/10/32/64档。空闲上下文不驻留进程，实际准入仍受PostgreSQL、
祖先资源、provider、操作系统和当前机器约束。

`team-binding.mjs` 使用实际 `team/member` 记录在首轮执行前绑定精确岗位预设，
拒绝重复身份、未知成员和错误父会话。冷启动只恢复原有已记录预设，不能借此改岗。
组织团队与真实 Session 父子关系保持分离，原生任务完成不直接增加平台验收信用。

现有 Worker 继续冻结真实输入、租约、代次、精确写集合、模型 grant 和停止证明。
根会话通过固定 UDS 模型传输交给规范 Gateway；作者只获得 dummy 凭据。
强 sandbox、cgroup、精确文件叶写入与独立验证均保留，不因规模扩大而放宽。

当前 npm 安装使用 `ops/freeze-native-profile.py` 显式发现并固定运行文件，
不依赖旧源码检出或个人 DSH_HOME。零模型 Doctor 只证明实际配置解析和探测范围；
模型执行、团队消息、恢复、费用和100+上下文分档激活必须另外实测。

SplatForge 的原始 58 岗位预设与交付目标保存在可选
`project-packs/splatforge/presets/`，其 2,884 张卡和历史不受本目录泛化影响。
默认平台包不加载该项目包，旧冻结部署继续保留原字节。

详见 `docs/ops/project-packs.md`、`docs/ops/concurrency-acceptance.md` 与
`contracts/concurrency-readiness.md`。所有新规模资格保持 NOT_RUN，直至实际验收。
