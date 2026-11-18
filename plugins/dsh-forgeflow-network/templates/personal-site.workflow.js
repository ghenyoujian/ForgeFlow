// Native DSH workflow body. meta is supplied separately, never exported here.
const tasks = [
  {
    "id": "brief",
    "title": "明确受众与网站目标",
    "role": "design",
    "depends_on": [],
    "write_set": [
      "design/brief.md"
    ],
    "outcome": "写清个人介绍、作品集、联系表单三个核心路径；明确不做的功能。",
    "acceptance": "受众、内容清单、成功标准均有可检验描述",
    "estimate_hours": 1
  },
  {
    "id": "ui",
    "title": "信息架构与 UI 规范",
    "role": "design",
    "depends_on": [
      "brief"
    ],
    "write_set": [
      "design/ui-spec.md",
      "design/tokens.json"
    ],
    "outcome": "设计首页、作品详情、联系页；定义黑白灰色板、字号、间距、组件状态和焦点。",
    "acceptance": "桌面与 390px 手机稿包含加载、空、错误、成功状态",
    "estimate_hours": 2
  },
  {
    "id": "api",
    "title": "前后端 API 合同",
    "role": "backend",
    "depends_on": [
      "brief"
    ],
    "write_set": [
      "server/contracts/openapi.yaml"
    ],
    "outcome": "约定 GET /api/projects 与 POST /api/contact；字段、错误码、请求限制、隐私和存储策略。",
    "acceptance": "前后端都评审请求响应样例；禁止把服务端密钥送到浏览器",
    "estimate_hours": 2
  },
  {
    "id": "shell",
    "title": "前端布局与路由",
    "role": "frontend",
    "depends_on": [
      "ui",
      "api"
    ],
    "write_set": [
      "web/src/App.tsx",
      "web/src/styles.css"
    ],
    "outcome": "根据 UI 规范建立首页、作品详情、联系页；提供骨架屏和错误重试。",
    "acceptance": "键盘可导航，路由可直接打开，语义标签和焦点可见",
    "estimate_hours": 2
  },
  {
    "id": "data",
    "title": "后端内容与联系接口",
    "role": "backend",
    "depends_on": [
      "api"
    ],
    "write_set": [
      "server/src/app.ts",
      "server/src/contact.ts"
    ],
    "outcome": "实现数据校验、联系表单限流、参数化数据库访问、健康检查与日志脱敏。",
    "acceptance": "错误请求被拒绝；邮件未配置时不能显示已发送成功",
    "estimate_hours": 2
  },
  {
    "id": "content",
    "title": "作品集与联系表单",
    "role": "frontend",
    "depends_on": [
      "shell",
      "data"
    ],
    "write_set": [
      "web/src/Portfolio.tsx",
      "web/src/Contact.tsx"
    ],
    "outcome": "按合同接入真实 API，表单显示提交中、成功与错误，防止重复提交。",
    "acceptance": "断网后保留输入，可重试且不会重复发送",
    "estimate_hours": 2
  },
  {
    "id": "motion",
    "title": "动效与响应式规范",
    "role": "motion",
    "depends_on": [
      "ui"
    ],
    "write_set": [
      "motion/spec.md",
      "motion/transitions.css"
    ],
    "outcome": "定义 120–220ms 过渡、抽屉进出和触控反馈；支持 prefers-reduced-motion。",
    "acceptance": "手机无横向溢出；减少动画时功能完整且不强制移动内容",
    "estimate_hours": 2
  },
  {
    "id": "motion-integrate",
    "title": "整合动效与无障碍",
    "role": "frontend",
    "depends_on": [
      "content",
      "motion"
    ],
    "write_set": [
      "web/src/motion.css"
    ],
    "outcome": "将经过评审的动效样式接入前端；检查 focus、hover、触摸和等待反馈。",
    "acceptance": "点击立即反馈，动画不拦截操作；键盘可关闭弹层并返回焦点",
    "estimate_hours": 2
  },
  {
    "id": "api-test",
    "title": "验证 API 与权限",
    "role": "quality",
    "depends_on": [
      "data"
    ],
    "write_set": [
      "tests/api.test.ts"
    ],
    "outcome": "针对输入边界、限流、错误恢复、数据库迁移和凭据泄露做独立测试。",
    "acceptance": "留下原始命令与结果，失败项有可复现步骤",
    "estimate_hours": 2
  },
  {
    "id": "browser-test",
    "title": "浏览器与性能验证",
    "role": "quality",
    "depends_on": [
      "motion-integrate",
      "api-test"
    ],
    "write_set": [
      "tests/browser.spec.ts"
    ],
    "outcome": "在桌面、手机、深浅色、缩放、键盘和减少动画设置下测试完整路径。",
    "acceptance": "页面截图、性能环境与真实接口证据可追溯",
    "estimate_hours": 2
  },
  {
    "id": "staging",
    "title": "准备预发布部署",
    "role": "delivery",
    "depends_on": [
      "browser-test"
    ],
    "write_set": [
      "deploy/Dockerfile",
      "deploy/compose.yaml",
      "deploy/README.md"
    ],
    "outcome": "构建前后端镜像，使用环境变量注入密钥；配置 HTTPS、健康检查与回滚。",
    "acceptance": "预发布 URL 可访问，构建可重复，敏感配置不进入 Git",
    "estimate_hours": 2
  },
  {
    "id": "release",
    "title": "发布审批与回滚演练",
    "role": "delivery",
    "depends_on": [
      "staging"
    ],
    "write_set": [
      "deploy/release-checklist.md"
    ],
    "outcome": "由用户确认域名、成本、公开内容与部署目标后发布；记录版本、探针和回滚步骤。",
    "acceptance": "公开发布取得明确授权；结果由实际部署探针确认",
    "estimate_hours": 2
  }
];
if (args?.execute !== true) {
  phase("预览个人网站编排");
  log("已装载 12 个任务；execute=false，本次不创建子 Agent。");
  return {mode: "preview", tasks: tasks.map(t => ({id:t.id, title:t.title, owner:t.role, dependencies:t.depends_on, write_set:t.write_set})), agentsStarted:0};
}
// This flag is a review reminder, not an authorization boundary. The managed
// ForgeFlow bridge must independently admit every child and model request.
if (typeof args.approvedFlowRef !== "string" || !args.approvedFlowRef) throw new Error("Provide the reviewed Flow reference and run through the managed ForgeFlow execution entry.");
const limit = Math.min(32, Math.max(1, Math.floor(args.concurrency || 4)));
const completed = [];
const results = {};
const pending = tasks.filter(t => t.id !== "release");
while (pending.length) {
  const ready = pending.filter(t => t.depends_on.every(d => completed.includes(d))).slice(0, limit);
  if (!ready.length) throw new Error("Dependency blocked or child failed; stop and ask the project owner.");
  phase(ready.map(t => t.title).join(" / "));
  const values = await parallel(ready.map(t => async () => {
    const value = await agent(JSON.stringify({task:t, approvedFlowRef:args.approvedFlowRef,
      policy:"Work only within the task write_set. Read upstream contracts. Report evidence and blockers. Use forgeflow_* tools for cross-user collaboration. Never publish a site, read another user's credentials, or claim acceptance from your own reply."}), {label:t.role+":"+t.id});
    if (value === null) throw new Error("Child did not complete");
    return {id:t.id, value};
  }));
  if (values.some(v => v === null)) throw new Error("A child failed. Preserve evidence and review before retrying.");
  for (const item of values) {
    completed.push(item.id); results[item.id] = item.value;
    pending.splice(pending.findIndex(t => t.id === item.id), 1);
  }
}
phase("等待发布审批与独立验收");
return {mode:"child_results_pending_verification", results, publicDeployment:"requires_explicit_owner_approval", gateEffect:false};
