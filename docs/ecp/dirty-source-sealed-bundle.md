# Dirty-source 密封 bundle：研究组件

`verification/ecp/dirty_source/sealed_bundle/` 提供独立 writer 和 reader，用于研究如何将调用者提供的 dirty-source 声明、按 SHA-256 索引的 blob 集合和原始 HEAD commit 封装到一个匿名 memfd。它不是生产执行入口、来源认证或 P001/G0 准入机制。writer 和 reader 互不导入，reader 也不导入生产采集器、模型、重建器或 Git adapter；它检查调用者提供的 bundle 摘要、memfd seal、容器结构、规范声明、blob 摘要与 Git 形式的 commit/tree 内部关系。期望摘要本身仍是调用方声明，不证明来源。

容器使用固定版本魔数、网络字节序长度、规范 ASCII JSON、按 SHA-256 排序的 blob、原始 commit 和 SHA-256 尾摘要。支持 SHA-1 或 SHA-256 对象声明，长度、对象数、路径及总量受限；在 JSON 解码前按原始字节保守检查结构 token、字符串长度和嵌套深度，解码后按深度迭代验证，并拒绝重复键、非规范 JSON、缺失或多余 blob、路径碰撞、变更声明不一致和 commit/tree 不匹配。预检对对象键也计数、最多容器嵌套 16 层，可能保守拒绝较深输入；上限不是经实测的聚合内存或 cgroup 保证。

writer 对新匿名 memfd 设置 WRITE、GROW、SHRINK 和 SEAL，失败路径对已登记 FD 最多尝试关闭一次，关闭结果不明时不重试；异步中断可能落在获得 FD 与登记之间，故不能保证完整关闭账本。reader 借用 FD，调用者负责持有与防止 FD 号被并发关闭或复用；同进程 dup 不是独立身份。`reader.read()` 返回的 manifest 和 blobs 是**可变字典**，调用方可自行更改；只有受内核 seal 保护且仍被持有的对象字节具有所述不可写约束。读取结果、调用者期望摘要和端点身份不能代替可信身份或持续绑定。

此前私有候选的 [30 方法合成测试回执](/home/chenyoujian/.cache/forgeflow-g0-continuation-20261116/r44-sealed-dirty-bundle-v3/receipt.json)经独立核对；测试仅在同一进程创建匿名 memfd，写入拒绝按 `PermissionError` 类型断言，关闭错误由 mock 模拟，不记录所有内核 errno，也不证明最大输入内存峰值。封存对象不冻结来源目录或后续解包目录；所有 FD 关闭后对象可能消失，也未证明崩溃或重启后的持久性、真实 Git、忽略规则、完整源码采集、主体/lease 或数据库事务绑定。所有这些均保持 UNKNOWN/UNVERIFIED，任何结果均为 `qualification=NOT_RUN`、`product_gate_effect=NONE`。

该目录测试可直接运行 `python3 verification/ecp/dirty_source/sealed_bundle/test_bundle.py`，也可对该目录执行 `python3 -m unittest discover -s verification/ecp/dirty_source/sealed_bundle -p test_bundle.py -v`；运行前应按项目资源和隔离合同审核，具体路径及环境身份由执行者固定。此处没有隐含授权实际用户源码、数据库、Git 或构建，也不以代码存在或测试通过代替真实 Gate。
