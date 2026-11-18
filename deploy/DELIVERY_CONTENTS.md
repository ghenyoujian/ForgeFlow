# 交付包清单与固定方式

`ops/package-checkpoint.py` 复用已有不可变构建收据与控制台产物，避免重复构建。每次输出到新目录，所有安装文件由 `delivery-manifest.json` 固定。原始失败证据和未验证范围保持原结论。

| 目录或文件 | 内容与用途 |
| --- | --- |
| `bin/` | server、Worker、CLI、sandbox guard 4 个固定 Linux 二进制 |
| `build/` | 原始构建收据、构建日志及二进制摘要 |
| `console/` | 实际构建的 React 静态资源；独立记录文件摘要 |
| `source/forgeflow-source.tar.gz` | 固定 Git 源码归档；逐项核对原始 Rust 编译输入、前端源码及交付文档 |
| `source-support/archive/` | 原始 Python 编排器归档，供实际对照实验独立复现 |
| `source-support/docs/idea/` | 原始完整设计 Markdown，保留源码引用的父目录输入 |
| `migrations/` | 从构建快照复制的 SQL 数据库迁移 |
| `contracts/` | 执行信封、上下文、规划输入/场景、任务估计 Schema 和领域接口 |
| `crates/api/` | HTTP 合同、OpenAPI 和实际路由清单 |
| `executors/presets/forgeflow/` | DSH 角色、Workflow/Teams/Subagent、桥接、沙箱和自定义模式 |
| `planning/` | 原始任务书、需求/任务矩阵、Gate、UI 方向、企业交互要求和已知风险 |
| `docs/`、`crates/*/README.md` | 架构、中文用户指南、Worker/DSH/证据接入说明 |
| `deploy/`、`ops/` | 原生安装、Compose 源构建入口、配置示例、运维、备份与恢复 |
| `evidence/index.json` | 本次选定原始证据的路径、SHA、结论和限定范围 |
| `evidence/files/` | 按索引复制的实际证据；原路径作为该目录下的相对路径 |

完整归档包含 Rust/React 源码、锁文件、自动测试、确定性负载、真实 DSH 适配与故障复现工具。任务与合同模板以当前 Schema、任务矩阵及源码中的执行配置装配器为准。私有运行配置、模型凭据、数据库和实时状态由部署者单独保管。

## 制作完整交付

主 Agent 先合并本次明确源码文件并固定提交，再从该提交生成源码归档。源码前缀使用实际归档中的 Control 路径。构建收据必须来自同一组 Rust 编译输入；脚本逐项检查，不能用当前代码包装旧二进制。

```bash
git archive --format=tar.gz --prefix=ForgeFlow/control/ FIXED_COMMIT \
  > /absolute/forgeflow-source.tar.gz
sha256sum /absolute/forgeflow-source.tar.gz
python3 ops/package-checkpoint.py create \
  --receipt /absolute/final-checkpoint/receipt.json \
  --console-dist /absolute/control/console/dist \
  --source-root /absolute/control \
  --source-archive /absolute/forgeflow-source.tar.gz \
  --source-archive-sha256 SOURCE_ARCHIVE_SHA256 \
  --source-prefix ForgeFlow/control \
  --evidence-index /absolute/selected-evidence-index.json \
  --evidence-index-sha256 EVIDENCE_INDEX_SHA256 \
  --evidence-root /absolute/control \
  --output /absolute/fresh/forgeflow-package
python3 ops/package-checkpoint.py verify \
  --package /absolute/forgeflow-package --require-complete-source
```

从仓库根目录执行 `git archive`；若 Control 本身是独立仓库，使用 `--prefix=ForgeFlow/control/`。源码归档无需把构建缓存、`node_modules`、数据库、私有配置或重复运行目录带入交付。构建日志不证明前端构建，静态资源摘要不证明全部交互。

制作时默认收录已固定的父目录 Python 归档和设计 Markdown，并核对原始 SHA。若来源路径不同，使用 `--legacy-archive PATH --legacy-archive-sha256 SHA` 和 `--design-plan PATH --design-plan-sha256 SHA` 明确绑定。独立源码复现保留三个相邻目录：

```bash
mkdir /absolute/fresh/source-checkout
tar -xzf /absolute/forgeflow-package/source/forgeflow-source.tar.gz \
  -C /absolute/fresh/source-checkout
cp -R /absolute/forgeflow-package/source-support/archive \
  /absolute/forgeflow-package/source-support/docs \
  /absolute/fresh/source-checkout/ForgeFlow/
```

结果为 `ForgeFlow/control`、`ForgeFlow/archive`、`ForgeFlow/docs/idea`，源码中的父目录设计引用和旧 Python 对照默认路径继续有效。PDF、DOCX 和离线设计预览不重复收录。

证据索引格式如下。每项指向 `--evidence-root` 下的普通文件，保留对应原始结论，不能使用绝对路径、越根路径或重复条目：

```json
{
  "schema_version": "forgeflow.delivery-evidence-index.v1",
  "entries": [
    {
      "path": "verification/evidence/actual-run/report.json",
      "sha256": "SHA256_OF_ORIGINAL_REPORT",
      "status": "PASS",
      "scope": "实际验证的输入、样本、版本与未证明范围"
    }
  ]
}
```

将所需原始日志、收据和原失败报告分别加入索引，文件摘要必须与现有证据相同。报告引用更大原始目录时，可保留在独立证据归档中并在索引注明定位方式。制作交付只复制已选定文件；它不重新运行验收。

## 安装与更新

新目录安装命令见 `deploy/QUICKSTART.zh-CN.md`。每次校验同时复核源码归档内的编译输入和交付资源。现有旧包仍可通过普通 `verify`；要求完整源码时使用 `--require-complete-source`。遇到 `.INCOMPLETE` 说明复制未完成，保留记录并选择新目录。

清单记录实际 `debug` 或 `release` 构建 Profile，资格为 `ENGINEERING_CHECKPOINT_ONLY`。实际 Cargo 构建与其原日志必须通过摘要检查；原收据中的失败检查保持失败，已覆盖或丢失的测试日志列入 `build.unavailable_test_logs`，`build.verification_status` 记录 `INCOMPLETE`。工作负载资格依据本次索引与 Gate 原始记录单独判定，完整文件交付不自动取得生产百级 DSH 资格。
