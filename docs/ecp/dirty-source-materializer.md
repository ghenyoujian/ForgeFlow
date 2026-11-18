# Dirty-source materializer：研究候选

`verification/ecp/dirty_source/materializer.py` 是 P001 的研究组件，不是生产恢复入口或准入机制。它接收调用者提供的 dirty-source 声明、声明 SHA-256、按 SHA-256 索引的原始 blob 和原始 HEAD commit，借助同目录的 `model.py` 与 `head_object.py` 重新计算声明并验证对象一致性，再生成固定的 Git plumbing 计划。它拒绝不一致、缺失或多余的 blob、未知工作区模式和声明中的排除项；HEAD、index、工作区与忽略文件覆盖情况仍取决于声明者，不能据此认定源采集完整。调用者提供并约束 Git runner，不能把 runner 的返回值当成其身份或执行位置已被认证。

`materialize()` 只接受调用者声称新建、私有且为空的目录 FD；检查目录为空且权限受限后先执行 Git 计划，再用目录 FD、独占创建和禁止跟随符号链接的方式重建工作区，对常规文件 fsync 和读回，对符号链接执行 no-follow stat 与逐字节 readlink。空目录检查无法证明新建、与源隔离或免受同 UID 并发修改；调用者必须确保这些前提和 runner 始终绑定该目标。任何 Git 或工作区错误均可能留下部分目标，结果是 INCONCLUSIVE；组件不自动删除、清空、覆盖目标或回滚。符号链接内容按原样恢复，可能指向目标外部，后续使用者须单独约束是否跟随。

运行前检查目标文件名限制、进程打开 FD 数量与 `RLIMIT_NOFILE`。`PC_SYMLINK_MAX` 为正值时作为实际报告的预检上限，为 -1 时记为 UNKNOWN；4095 字节是独立输入预算，不是已认证的文件系统上限。逐项创建和回读成功仅观察当时该目标上的链接，不能推广到其他路径或时刻。同步异常时对已登记的显式 FD 逐个尝试关闭并记录结果，关闭失败为 UNKNOWN；中断异常会尽可能在其他已登记目录 FD 关闭后继续传播。异步中断可能发生在获取 FD 与登记之间或关闭记账期间，FD 状态和部分结果均可能 UNKNOWN；调用者的根 FD 和 runner 自有资源不在该账本内。

该实现没有证明进程树终止、调用者身份或 lease、原子快照、同设备 bind mount 排除、ACL/xattr/时间戳、索引扩展或冲突、配置与 hooks、分支名/ref、完整提交历史、大小写别名和任意文件系统行为。声明中的 exclusions 即使标为完整也仍为 UNVERIFIED；不完整则为 UNKNOWN。成功记录仅为 `OBSERVED_RESEARCH_ONLY`、`qualification=NOT_RUN`、`product_gate_effect=NONE`，不得据此声称 P001/G0 完成。

`test_materializer.py` 可直接执行，也可通过 `unittest` 按文件 discovery；每次导入后执行测试时由 `tempfile.mkdtemp` 新建独立测试根，显式设置 `TMPDIR` 时要求其为绝对路径，直接在其下创建，路径不可用时失败且不回退；未设置时才使用系统默认临时目录。测试向 stderr 报告其路径，并刻意保留以供检查，不自动清理。测试使用 fake runner 和模拟文件系统限额，不调用真实 Git、不读取用户仓库；测试通过不等于真实恢复或产品准入。真实 Git 合成实验如有记录也只能说明其固定 fixture 与环境下的观察，必须另行核对原始输出及独立审查结论。
