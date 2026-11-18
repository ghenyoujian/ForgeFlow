# ECP P0-01 两阶段源码 bootstrap 研究草案

状态：DRAFT / NOT ADMITTED / NOT RUN。草案依据 A10 增量审查意见修订。本文只提出待审核研究方案；不授权操作、不创建或冒用 principal、grant、lease，不更改任务、阶段 Gate 或现有 v3 合同。OS 用户、PID、聊天身份、团队代号和本文件摘要仅为观察线索，不是正式业务身份。未证明的值用 null / UNKNOWN，不允许补造。用户已授权日常开发与独立研究并不自动建立控制面的正式身份或授权；本文也不凭空增加一项用户批准要求。所有实际动作遵循现有用户指令、隔离限制与平台权限。

## 依据及待决问题

规划要求任务准入绑定源码快照、principal、lease、项目、base SHA、generation、工作树、精确写集合和环境身份；P0-01 卡 blocked_if 明确缺少 snapshot、principal 或 lease 时阻塞，其路径与符号仍未解析。P0-01 又承担源码清单冻结，因而需要解释准入所依赖的基线快照和本卡最终产物之间的关系。下述两阶段仅是待 A00 和独立验证者审核的候选，不以 bootstrap 为名豁免准入；若其解释与权威计划冲突，须先形成经授权、可追溯的计划修订，否则继续 NOT ADMITTED。仅把 task 角色名或现有计划里的字段当成主体、租约均不可行。

## 首个可信主体与 G0 前信任根（未解决）

静态代码显示现有个人模式注册会在事务中创建账号、个人 workspace、OWNER 成员及相应 HUMAN principal；这是每次注册为新建个人 workspace 创建初始 OWNER 的已有路径，并非全局一次性的首 owner 初始化，也不证明某个当前运行部署、主体或凭据真实存在。部署 Owner 密码/服务凭据亦存在独立配置路径。这些事实不等于 G0 前已经建立可信外部信任根，也不自动赋予该 owner 对当前源码、P0-01、准入政策或独立核签的权限。应事先定义并验证首个权威主体的来源、身份凭据与范围、信任根配置及变更、撤销、审计和物理控制边界，或验证已有受信 owner 到目标 workspace/project 的授权链。不能只用聊天声明、自签摘要、团队代号、首次请求者或未验证的新建个人 workspace owner 建立业务信任。没有可核验主体及信任根时，保留未知，禁止正式核签或准入；本文不提出用一次性主体跳过该条件。

## 第一阶段：非正式工程观察

仅在现有授权和技术隔离范围内，以有限资源只读观察来源，在专属私有输出位置生成不可覆盖的待审候选；不修改原工作树或生产数据。预登记来源根、允许访问的实际对象与物理身份、纳入和排除规则、采集方法和工具摘要、资源上限、输出路径及观察范围。记录 Git commit 与 index 身份、实际纳入路径集合、类型、文件字节摘要、链接目标、未跟踪项、依赖锁，以及起止时间、错误和未知项；观察信息必须同时包含原始数据、计数与异常。接触 Git 或其他程序须另行满足其真实执行及隔离前提，本文件本身不授权执行。

UNAUTHENTICATED_CANDIDATE 仅是本文研究用标签，并非产品状态机、正式任务执行状态或授权记录；观察进程身份不构成 principal；principal_id、grant_id、lease_id 为 null。快照及输出不得标记为已批准或用于支撑正式 Gate。无可验证的完整路径覆盖、源根和链接约束、排除边界、资源边界、无覆盖或一致性窗口时，记录 BLOCKED/INCONCLUSIVE。起止摘要相等只表明端点相同，不能证明期间没有修改。不能确认来源文件 mode、ACL、owner 等事实时保留 UNKNOWN，Git executable 分类不得被当作这些属性；若后续考虑规范化，须依当前独立规范化研究合同另行固定和核验策略，不得声称保留源权限。

## 第二阶段：核验冻结与正式准入

真实、独立的授权主体通过受信认证和权限权威证明自身及针对 workspace/project、动作、资源、写集合、有效期的有效权限；核验主体、权限和复核者须有可审计证据，而不是由申请者自行声明。先确认基线政策、目标和完整性假设，独立地检查候选物理身份、完整路径/字节/类型、链接、排除项及可观察的属性与源数据映射；只有证明持续不可变及可信来源一致性的机制存在时，才可由授权主体核签绑定原始来源身份、候选清单与字节摘要、观察和独立复核证据、明确的规范化策略、工具和环境、精确作用域和有效期。核签是要求可验证的主体/授权及不可篡改记录，不预设现有系统已经提供密码学签名。不能确认事实时保持 UNKNOWN / INCONCLUSIVE，不得将候选升级为正式快照。核签与后续使用时均校验绑定和不可变性；证据必须能追溯具体工件。

正式 P0-01 准入前必须依据正式合同完成真实路径和符号解析、任务依赖、已核签准入基线、受信 principal/grant、workspace/project、期望 revision 和 authorization epoch、隔离工作树、精确读写集合、环境与预算的核对。候选设计以独立证明候选在完整使用窗口内物理冻结、以及外部核签和 DB 之间的绑定及失效处理成立为先决条件；其后，事务只原子验证并固定可事务化的权限、证据引用、版本与其他数据库条件，生成并绑定 attempt、在相应 project/task 的 fence 作用域内递增的 generation、有限 lease、worker 和已核验源码摘要，提交后且外部绑定仍有效才允许该代执行。DB 事务不原子锁定外部文件，也不能单凭提交证明外部对象不可变；如果冻结、跨系统绑定或事务内验权任一前提无法证明，必须继续 BLOCKED/INCONCLUSIVE，而不是将异步人工核签加 ID 拼接冒充原子准入。无主体、无快照、无有效 lease 或证明不足均保持 NOT ADMITTED。任务完成后以独立核验对比输出和已核签基线、变更范围及自身可复现证据；预采集结果不是 P0-01 自动通过。

## 物理不可变窗口和跨系统核签事务（未解决）

只读挂载、文件描述符、路径哈希、端点相等、文件权限或同 UID 隔离各自不能独立证明从核验、核签、DB 提交到任务读取完成整个窗口的持续不可变。候选方案必须先列明攻击者与写入者、源/目标存储和挂载身份、快照创建与撤销能力、时间窗口和特权边界，再证明受信不可变快照或等价机制在整个窗口有效；任何环节不可观察、控制或证实就保持 INCONCLUSIVE。针对物理根替换、同 UID/特权写者、硬链接、重挂载、核签后变更、打开后替换等故障，需由独立观察者持有证据或做受控反例。

文件系统快照、外部核签和 PostgreSQL 通常不共享单一原子提交，不能把同一事务写入 attempt/lease 当作已经原子锁住外部内容。必须先定义可信存储对象的不可变版本、精确清单与实体的绑定、签发者和撤销权威、提交前后验证、执行读取的对象身份及失效处理；可研究条件式发布或提交协议，但必须说明每个崩溃点、并发、撤权和 TOCTOU 的安全性，以及 DB 提交后外部对象丢失/替换时的 fail-closed 机制。若无法证明这种跨系统绑定覆盖整个执行窗口，则不准入、不将 DB 回执标成真实冻结证明。此处是待设计和验证的硬依赖，不表示已有实现或把问题交给未来阶段。

## 失效和竞争

主体失效/撤销、grant 到期或撤销、epoch/revision 变化、项目不匹配、候选来源或文件漂移、期望快照不符、写集合冲突、独立核验缺失、租约到期/撤销、旧 generation、数据库或可信认证不可用、无法确认执行器停止、状态和权威记录不一致，必须拒绝新准入或报告 BLOCKED/INCONCLUSIVE；已发生的外部后果须记录并按已批准的恢复协议处置。并发申请须以权威事务、任务级 generation 围栏和针对重叠 write-set 的排他机制，保证同一任务的有效代以及相互冲突的写入授权不同时生效，冲突方失败；generation 不是跨任务或全局序号，跨任务排他不得只靠比较 generation；重试和幂等重放前重新校验当前身份和授权，不能因旧回执而恢复撤权。任何未知不是 PASS。全过程保留各方日志、源/工具/策略摘要、失败与未解决事项，审计材料不视为授权本身。

## 已知实现事实和限制（静态读取）

现有 Store::register_account 的静态实现会为每次个人注册创建账号、个人 workspace、OWNER 成员及 HUMAN principal；API 注册后创建个人会话，但这不证明实际部署已有受信主体。现有 API auth::Principal 表示会话/服务 actor 与 worker 范围；identity() 从其 actor_id 和请求头生成命令身份及幂等键。workspaces::guard 对个人账号检查成员关系、项目归属及角色，故不能声称 API 完全没有认证授权。独立的 ECP identity/collaboration 代码和迁移包含 principal、grant 等对象及部分检查；尚无证据表明其与 P0-01 的 source snapshot 核验和 Store::admit 串成文中要求的完整权威事务。Store::admit 启动事务、取得协调锁并调用 admit_tx；admit_tx 靠前处理 replay，随后检查现有项目、任务和资源条件，生成 attempt、基于该 project/task 的 fence_epoch 递增 generation 和 lease 并在事务内写入，并检查活动或隔离 attempt 的重叠写集合。静态文件中未见 admit_tx 显式查询 ECP principals 或 capability_grants；该事实不是 HTTP 可越权的证明，也不是测试执行结果。现有 source-normalization-contract 自称研究草案，不授身份、租约和执行授权。数据表结构或草案合同存在不等于当前有经过认证的主体、运行数据库或合格准入链。

## 建议的可复验条件（未经执行）

先固定需求、失败分类、完整分母、来源/策略/工具/工件摘要、独立观察位置和原始日志。每项记录输入、预期状态、实际状态及权威回读；独立观察者不得仅复述作者结果。至少覆盖：未知首个信任根、仅凭自签或新个人 workspace 自称目标 owner、无主体和伪造主体；有效主体但错 workspace/grant/写集合；授权撤销后同键 replay；过期、撤销和旧 generation；同范围并发请求最多一个生效；来源采集中变化、核签后候选修改、同 UID/特权写入、物理根替换或重挂载、核签与 DB 提交之间的崩溃/撤权/对象替换及执行窗口漂移、不同 digest、链接逃逸与额外/缺失路径；源 mode 或 ACL 不可知；证据缺失和执行中断；认证、DB 或停止状态不可用；有效主体及真实冻结候选成功时回读同一摘要及 attempt/lease/generation。未知情况要求拒绝或 INCONCLUSIVE，不得归为成功；成功路径需要可验证、互不冲突的正式权威状态。

最终 P0-01 条件仍以正式卡为准：相同字节同 digest、任意业务输入改变改变 digest、不改原树、来源身份与可复现命令、精确写集合、真实非零分母及失败/跳过/未执行完整留存，且真实独立核验和所有依赖成立。G0 还须满足 P0-01 至 P0-08、隔离 PostgreSQL、完整套件、同一源码和独立审批等正式门槛；任何研究文档、合成测试或离线检查都不能改变其 NOT RUN 状态。

## 静态依据及端点摘要

以下路径均相对于 ForgeFlow 工作区根目录，SHA-256 为草案形成时对单个文件读取所得的端点摘要，仅用于定位和比较这些具体字节，不证明来源认证、完整源码快照、持续不可变或正式批准。团队登记文件摘要对应本草案整合前观察；后续登记可能使其发生预期变化，需另记录更新后的端点，不得伪称前后持续不变。早期 /tmp 草案不作为长期证据。

- `control/AGENTS.md`：`4604c1f47aa6a3a019a43b8ca28b81459834861069d234b59c21af5497455aca`
- `control/crates/api/src/auth.rs`：`d696d7ca1f62f51a982ecd5dab773c392a6960332279c2fed938ed2189dcec27`
- `control/crates/api/src/catalog.rs`：`66db9e4e4f0a483c5bdf01283aeb6b751b6621563ec7e109ec46db9e0439c767`
- `control/crates/api/src/lib.rs`：`348c88055989926887bf817eb1ded5302fd881c5061d0d7360220883eb65f57f`
- `control/crates/api/src/workspaces.rs`：`9aa435ce85434eb89ce08cc9c9ff85949ceeb0ca6dc271eb7af029440feae4dd`
- `control/crates/store/src/admission.rs`：`d728296247d41e2608c8ec56c40a3807d7e98614ed6ba294115d25cc0a726f7e`
- `control/crates/store/src/ecp_collaboration.rs`：`c47288fce7e1500bd8257a4fee99c9935b0ffd94f4fc1f06adb9e1d3fc9b607a`
- `control/crates/store/src/ecp_identity.rs`：`6b9bdf88fddc0025a7dbbea4ad27d6f21ef6250fe518429c587763770f11c968`
- `control/crates/store/src/lib.rs`：`bbdfb99df75ce0cddf3f586418d6e2945472c65d3e49f31f5745eaa8b6b79d7f`
- `control/crates/store/src/workspaces.rs`：`eae71381545a4e0ef454c6da374acaabff1a40f3b6af3e84f10ad2c6dd6aca2a`
- `control/docs/ecp/source-normalization-contract.md`：`ee54f19174299b06210e5a1fa758ba672c76f685886a87432dceef0a4ca96864`
- `control/migrations/0001_control.sql`：`28c6fa3e94b09f90cfb1f36b47ec3bf7850fb478d40c6218c1a95acc2de51787`
- `control/migrations/0015_ecp_principals_capabilities.sql`：`a7e27b41393d77ab71e5af52d6d84aa8aba688c95bf180015bf0fe5c7c2efcd3`
- `control/team/ecp-g0-work.json`：`25670538b1877e6dce13f3a9303f764fc7dac1636c9414050901c03e3d0be8d7`
- `docs/idea/ForgeFlow_ECP_完整开发规划/PLAN_PLAINTEXT.txt`：`1f7c379f66f4a6b3d7fe4d5e612f83033e6d3b69a59ef2f3392dd34590038163`
- `docs/idea/ForgeFlow_ECP_完整开发规划/planning/gates.json`：`d8c5f074efd364ef13e8fb3aac130b323ccb5eb47b4018390da0b5da7ca32f72`
- `docs/idea/ForgeFlow_ECP_完整开发规划/planning/tasks.json`：`5a2a8773659ddd5146a031a9976f0747de696a73a2d724bc55c81c8f17a29794`
