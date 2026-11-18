# P001 独立 dirty 目标 Oracle（研究组件）

状态：RESEARCH ONLY / NOT ADMITTED / NOT RUN。该模块读取调用者提供的已打开目标根目录 FD、声明及 blob，独立解析有限 Git 元数据和实际工作区，判断声明与目标端点观察是否一致；它不执行 Git、不导入采集器/重建器、不认证来源、调用者、声明完整性或忽略规则。成功标签为 OBSERVED_RESEARCH_ONLY，qualification=NOT_RUN，product_gate_effect=NONE，不是 P001/G0 PASS。

支持受限 SHA-1 loose objects、受限 HEAD/ref、index v2 无扩展，或唯一 TREE 扩展且载荷为失效根节点 `002d3120300a`。压缩对象、索引校验、路径、资源和 nofollow 约束见源码；pack、split/sparse index、其它缓存扩展及不支持格式保守拒绝，不得据此声称 Git 全格式兼容。端点比较不证明采集期间持续不变；调用者、运行时、内核和不存在恶意同 UID 并发写入为前提，目录的真实持久冻结、目录属主权限和 actor 身份不由此组件认证。

测试只允许显式绝对 `ECP_ORACLE_FIXTURES` 指向已创建的当前用户 0700 私有空目录，绝不回退系统临时目录。direct 和 discovery 使用独立新根；测试创建合成目标并保留 fixture，不运行 Git/数据库或主动清理。安装位置所在挂载的权限位在本次查看为 0777，不能依位权限声称主树私有或防并发替换。直接测试和 discovery 的结果只能说明被测样例，不能证明真实 Git、进程、来源、主体、lease、数据库或正式资格。

v6 现有 66 合成方法的观察绑定其当时测试源码和 oracle 原字节；本整合候选更改测试模块加载方式，须重新验证且不得把旧回执当新测试结果。一个新建私有真实 Git 合成目标的 v6 实验经独立复核为单样本 OBSERVED_SINGLE_SYNTHETIC_SAMPLE，回执 `/home/chenyoujian/.cache/forgeflow-g0-continuation-20261116/r45-dirty-oracle-real-git-v6-review-a10-v1/receipt.json`（SHA-256 `f4a09284dc2862e614b51af5f0c45ea13eb4dc4c967293c548df88ebc5572a6a`），绑定 v6 oracle 原字节，不能替代本整合候选测试或正式资格；此前 v5 实验仍为 INCONCLUSIVE。
