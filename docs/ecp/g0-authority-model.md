# G0 主体、撤销和租约：有限状态理论探针

本文件描述 CPU 小样本上的**抽象模型**，不证明 PostgreSQL、HTTP、Worker 或任何生产实现满足安全性，不是正式身份、租约、G0/G1 或发布验收。命令只输出 `product_gate_effect=NONE`；结果 `OBSERVED_NOT_GATE` 与退出码 0 仅表示本模型的有限图检查按预期完成。若检查条件失败则退出 10。完整结果可执行 `python3 verification/ecp/g0_authority_model.py --output /path/to/new-result.json`；输出文件必须不存在，且不会覆盖旧证据。结果记录工作树 HEAD 和模型本身 SHA-256，但不评估工作树是否干净，HEAD 不能单独证明模型文件来源。测试：`python3 -m unittest discover -s verification/ecp -p 'test_g0_authority_model.py' -v`。

## 依据与模型范围

计划 `../docs/idea/ForgeFlow_ECP_完整开发规划/PLAN_PLAINTEXT.txt` 第 10.1 节要求保留 I01–I08，E01–E08 单独编号；仓库 `docs/全链路情况审计说明.md` 第 14A 节和 `audit/full-chain/invariants.json` 给出 I01–I08 的定义和旧版审计状态。现有 `verification/ecp/independent_oracles.py` 检查输入快照，`invariant_campaign.py` 检查一组人工构造的正常/破坏快照；它们没有穷举本文件的并发状态。

这里固定两个主体 p0/p1、两个 workspace w0/w1、一个 task、一个符号 grant、两个 generation、两个 worker、两种 payload、一个记录过的幂等键和一个事件 ID。初始 grant 分别取 ABSENT/ACTIVE；ACTIVE 仅授权 p0/w0。一个待提交 admission 和一个撤销可交错，事件效果计数达到 2 后饱和，因为 2 已足以证明重复效果。系统只有离散动作，无真实 clock、超时、崩溃、网络、持久化、角色链、预算、外部副作用或多任务调度；不建模任意多并发 transaction、重授权或租约自动过期。第二次 admission 假定使用新幂等键，已记录的首个键仍可供重放。

状态包括 grant 状态、task 当前 generation、lease generation、fence epoch、已绑定主体与 workspace、活动 attempt、是否已经 claim、待提交请求和它先前读取的授权、首个 replay 请求、事件 payload 和效果数。generation 限为 0、1、2；每次新 admission 产生下一代，关闭 attempt 才能继续下一代。实际源码的 principal/grant/lease 绑定并不存在；这里的 binding 是候选策略需要满足的**模型变量**，不是现有数据库事实。

候选策略将授权检查、绑定与 admission 提交看作一个不可分割的抽象迁移；replay、claim 和事件效果前检查当前授权，事件必须在 claim 后才允许产生效果，并检查 attempt/lease/fence generation 与 worker，一次事件 ID 不重复产生效果，payload 冲突拒绝。这个原子迁移是假设，**不证明任何 SQL 锁或 isolation level 实现了该原子性**。模型从每个初始状态以 BFS 遍历所有可达状态和每条已生成边，包含自环；搜索没有深度截断，且结果的“完整”只指上述有限状态域内的可达图。

## 不变量映射和可达性

| 原编号 | 本模型检查的受限性质 | 未覆盖的原始含义 |
| --- | --- | --- |
| E01 租户与主体隔离 | 接受 admission 时存在授权 p0/w0 的 grant，不能接受缺授权或另一主体/workspace 的请求 | 多主体委托、数据库隔离和真实认证 |
| E02 授权撤销单调 | revoke 提交后不可新提交 admission、返回旧 replay 或产生事件效果 | 时间传播、重授权、真实进程停止与外部副作用 |
| I05 旧身份拒绝 | 事件的 attempt/lease/fence generation 与 worker 一致；旧 generation/错误 worker 拒绝 | 真实期限、token、调度及数据库或进程事实 |
| I06 重复事件无副作用 | 固定 event ID 同 payload 重放不产生第二次效果 | 多 ID、乱序、跨事务外部效果 |
| E06 幂等冲突拒绝 | 固定 key/event ID 不同 payload 不能当成功返回 | 多 key、哈希碰撞与真实持久化 |

I01–I04、I07–I08、E03–E05、E07–E08 未在此得到证明或验收；本模型没有能力代表其完整语义。`candidate` 不应因完全禁止操作而通过：模型要求存在合法 admission、合法 claim、第二代 admission、合法事件、合法同 payload replay、重复事件无新增效果，以及有其他条件成立时的错误主体/工作区、旧 generation、错误 worker、冲突 payload 和claim 前效果及撤销后 claim/replay/效果的拒绝见证。策略迁移本身不宣布违规；独立的边检查函数只读取前后状态与动作结果，判定受限安全性质，并拒绝无法识别的事件/replay 标签。模型记录最短反例路径及完整见证；测试重新逐步回放，独立 DFS 复算 BFS 的状态/边数和封闭性。

## 与源码的对应及反例性质

- `crates/store/src/admission.rs::admit_tx` 不查询 `principals`/`capability_grants`，而原 PostgreSQL 私有夹具曾直接观察空主体/授权下创建 lease 并完成 claim。`unbound_subject` 是这个 Store 信任边界的抽象反例；它不证明经 HTTP 的普通用户能绕过鉴权。原始夹具及边界见 `/home/chenyoujian/.cache/forgeflow-g0-principal-gap-evidence-20261116/counterexample-receipt.json`。
- `admit_tx` 在授权核对前处理 idempotency replay 的源码顺序，映射到 `replay_before_auth`。撤销后 replay 返回的轨迹是**抽象假设下的最短反例**，不是已实证的 HTTP 行为或已识别的产品可利用链。
- `unlocked_check_then_commit` 是候选设计中未持锁的假设变异，用于显式展示“读授权→撤销提交→旧请求提交”的 TOCTOU；不声称现有系统执行了这种授权检查。
- `missing_fence`、`effect_after_revoke`、`effect_before_claim`、`duplicate_effect`、`accept_payload_conflict` 是独立故障变异；每个必须被对应性质捕获；claim 前不得产生效果是额外的派发假设，并未改写 I05 的定义。I05 分别留下旧 generation 和错误 worker 反例，不能用新 generation 不匹配冒充旧代见证。
- `crates/store/src/lib.rs::valid_lease`、`crates/store/src/lifecycle.rs::attempt_control`、`heartbeat`、`claim_with_known_attempts` 及 `crates/store/src/ecp_identity.rs` 的真实锁、事务、数据库时钟和输入语义均未与本模型建立形式 refinement。此模型通过不证明任何生产路径正确或错误。

另一个独立的小图只含两个事务、两把排他锁、阻塞等待、提交时释放。反序取得锁可达相互等待；同序图中在无 abort/timeout/其他锁的这个模型下无死锁且存在两事务完成路径。它没有建模实际项目中的 workspace/member/principal/grant/worker/project/task/attempt/lease 或 PostgreSQL 锁兼容性，不证明候选锁序适用于生产、不证明公平性或活性；真实锁图审计和隔离 DB 并发回归仍是前置。

## 验收边界

模型运行必须报告每种策略的状态与边数、全部 mutation 的可重放反例、候选策略的非空见证、同序/反序锁图结果；任何分母为零、缺反例或缺见证均为模型检查失败。不能把模型验证升级为 ECP-G0 资格、ECP-G1 授权通过、I01–I08/E01–E08 全部成立或最终发布；未运行真实授权、性能及端到端验证均保持原状态。
