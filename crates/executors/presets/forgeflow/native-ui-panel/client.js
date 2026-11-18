window.__ModuleLoader__.load({
  id: '@forgeflow/dsh-native-operation-panel',
  factory(require) {
    const React = require('react');
    const {
      Button, Input, Menu, SegmentedTabs, Tag,
      IconBranchOutlineRegular, IconRefreshOutlineRegular, IconPlayOutlineRegular,
      IconPauseOutlineRegular, IconUsersOutlineRegular,
    } = require('@deepseek-ai/dsh-client-ui-primitives');
    const h = React.createElement;
    const { useEffect, useMemo, useRef, useState } = React;
    const NS = 'forgeflow.panel';
    const PANEL_ID = 'forgeflow';
    const editorZh = { activateDraft: '启用发布版本', versionActivated: '已设为后续任务默认配置；点击恢复开发开始调度',
      presetEditor: '预设与插件配置', loadEditor: '重新读取配置', newPreset: '新建预设', presetName: '预设名称',
      presetDescription: '说明', personaPrefix: '角色指令', presetIdentity: '预设 ID', saveDraft: '保存草案',
      previewDraft: '预检查变更', publishDraft: '发布新版本', newDraft: '新建草案', draftVersions: '草案与已发布版本',
      editorNote: '编辑预设、插件参数及岗位绑定。发布生成新的执行版本，正在运行的任务保留其已准入的版本。发布后先暂停新增，再启用版本并恢复开发。',
      editorLoading: '正在读取可编辑配置…', draftSaved: '草案已保存', draftDirty: '有未保存的修改',
      previewRequired: '先保存并预检查当前修改，再发布。', versionPublished: '新预设版本已发布',
      nativeResolved: '原生配置解析已通过', activePreserved: '运行中的执行版本已保留',
      bindPreset: '绑定预设', requiredPlugin: '必需插件', chooseDraft: '选择草案或版本', sourcePreset: '复制当前选中的预设',
      draftStatus: '版本状态', nativeProfile: '执行版本', editorActions: '配置操作',
      workerCapacity: '每个 Worker 的独立编码任务并发上限',
      workerCapacityNote: '新草案读取当前容量。留空沿用各 Worker 原值；实际并发受就绪任务、模型与机器资源约束。',
      workerCapacityInvalid: '请输入 1 至 64 的整数，或留空沿用现有配置。',
    };
    const editorEn = { activateDraft: 'Activate published version', versionActivated: 'Default for future bindings; Resume Development starts scheduling',
      presetEditor: 'Presets and plugin configuration', loadEditor: 'Reload configuration', newPreset: 'Create preset', presetName: 'Preset name',
      presetDescription: 'Description', personaPrefix: 'Role instructions', presetIdentity: 'Preset ID', saveDraft: 'Save draft',
      previewDraft: 'Preview changes', publishDraft: 'Publish version', newDraft: 'New draft', draftVersions: 'Drafts and published versions',
      editorNote: 'Edit presets, plugin settings and position bindings. Publishing creates a new execution version; running tasks keep their admitted version. Pause new work before activating, then resume development.',
      editorLoading: 'Loading editable configuration…', draftSaved: 'Draft saved', draftDirty: 'Unsaved changes',
      previewRequired: 'Save and preview the current changes before publishing.', versionPublished: 'New preset version published',
      nativeResolved: 'Native configuration resolved', activePreserved: 'Running execution versions retained',
      bindPreset: 'Bound preset', requiredPlugin: 'Required plugin', chooseDraft: 'Select draft or version', sourcePreset: 'Clone the selected preset',
      draftStatus: 'Version status', nativeProfile: 'Execution version', editorActions: 'Configuration actions',
      workerCapacity: 'Concurrent independent coding tasks per Worker',
      workerCapacityNote: 'New drafts read current capacity. Leave blank to retain each Worker’s value; actual concurrency depends on ready tasks, model and machine resources.',
      workerCapacityInvalid: 'Enter an integer from 1 to 64, or leave blank to retain existing settings.',
    };
    const zh = {
      panel: '开发工作流', title: 'Workflow 与 Agent Teams', subtitle: '规划、专业预设、原生协作与受控交付。',
      project: '项目', chooseProject: '选择项目', refresh: '刷新', refreshing: '正在读取真实状态…', auto: '自动更新',
      prepare: '对齐并绑定', start: '启动开发', pause: '暂停新增', replan: '重新规划', retry: '重试任务', cancel: '停止尝试',
      actionPending: '正在提交动作…', actionReceipt: '权威动作回执', actionStatus: '动作状态', actionId: '动作身份',
      actionNote: '动作受理、实际启动和项目验收分别记录。', requestFailed: '请求失败', stale: '当前保留上次成功读取，请刷新。',
      noProject: '还没有可读取的项目', readOnly: '当前项目为只读来源', waiting: '等待权威数据', unknown: '尚未提供',
      catalog: '全部任务卡', dag: '任务 DAG', agents: 'Agent Teams', workflow: 'Native Workflow', presets: '插件与 Agent 预设', overview: '交付链',
      catalogCount: '正式登记任务卡', roleCount: '已登记专业岗位', runningCount: '实际执行 / Native 占用', acceptedCount: '目录验收完成',
      catalogNote: '权威 catalog 登记数量；列表读取单独显示', roleNote: '岗位规划身份，实际会话另计', runningNote: 'RUNNING 尝试 / 未停止的真实 Native 会话',
      acceptedNote: '原始目录卡的独立验收与 FINALIZED 集成', source: '来源', observed: '观察时间', revision: '权威版本', model: '实际模型绑定',
      planned: '目录登记', committed: '当前 Flow 覆盖', configured: '执行配置已绑定', executing: '实际执行', accepted: '正式验收',
      deadline: '完整交付窗口 · {days} 天', noDeadline: '交付窗口尚未登记', blockers: '当前解阻项', noBlockers: '此来源尚未提供阻塞清单',
      search: '搜索卡号、功能、岗位或 Owner', allOwners: '所有 Owner', task: '任务 / 功能', owner: 'Owner / 团队', state: '状态 / 绑定', details: '查看卡片',
      emptyCatalog: '尚未取得正式任务目录', emptyFilter: '没有匹配任务', previous: '上一页', next: '下一页', pagination: '第 {page} / {pages} 页 · {count} 张卡',
      currentFlow: '当前提交 Flow · R{revision}', noFlow: '等待进入当前提交 Flow', noEnvelope: '执行配置待绑定', envelope: '已冻结执行配置',
      requirements: '需求映射', readSet: '精确读集合', writeSet: '精确写集合', dependencies: '正式依赖', inputs: '输入与独立验收',
      predecessor: '直接前置', successor: '直接后继', dagNote: '完整目录 {cards} 张卡、{edges} 条依赖；当前显示选中卡的直接邻域。',
      dagMore: '展示 {shown} / {total}', unregisteredDependency: '未登记依赖卡', noPredecessor: '没有直接前置', noSuccessor: '没有直接后继',
      roster: '岗位名册', role: '岗位', parent: '父级', root: '根会话', preset: 'Agent 预设', presetHash: 'Preset SHA256', depth: '委派深度',
      workerContexts: 'Worker 的真实 Native 上下文', hostContexts: '原生 Web 会话', session: '会话', allocation: '分配', openSession: '打开原生会话',
      sessionLoading: '正在读取原生会话目录', noSession: '原生 Host 当前没有已登记会话', noNative: '当前项目没有 Native 生命周期记录',
      teamTasks: '原生团队共享任务', teamNote: '团队任务完成为 Native 观测状态；正式卡验收按控制面证据计算。',
      observedTeams: 'Worker Bridge 的原生团队事件', noTeam: '尚未观察到团队成员或共享任务', member: '成员', position: '岗位绑定',
      workflowNote: '运行、阶段与成员均来自实际持久事件；原生结束状态不直接完成正式任务。', noWorkflow: '尚无 Native Workflow 运行事件',
      phase: '阶段', outcome: '原生结果', nativeEvent: '原生事件', workflowMissing: '尚未取得 run-start 记录',
      resources: '实际资源准入', scope: '资源范围', dimension: '维度', allocated: '保留占用', hardLimit: '当前限额',
      models: '真实模型请求', modelPending: '模型在途', usageUnknown: '未知 / 隔离结算', inputTokens: '输入 Token', outputTokens: '输出 Token',
      executor: '执行器 Profile', plugins: '插件', capability: '冻结能力', qualification: '实际资格', qualifiedScope: '资格范围',
      noAudit: '插件审计尚未绑定当前执行档案', noPreset: '岗位预设尚未绑定', observationNote: '当前页面只读取原生事实；控制动作通过已授权 Bridge 执行。',
      replanReason: '重新规划理由', pollUnavailable: '服务器尚未提供自动刷新间隔', receipts: '近期原生操作', showMore: '继续显示',
      currentAttempt: '选中实际尝试', noAttempt: '当前没有尝试记录', close: '收起详情', planOnly: '已登记规划；执行绑定与验收继续推进',
      directoryUnavailable: '当前目录不可读，请刷新真实状态。读取失败的数量显示为 —。', sourceNotReady: '项目快照与已审核配置尚未就绪',
      nativePresets: 'DSH UI 宿主预设目录', nativePresetsNote: '这里显示当前 UI 宿主注册的预设。项目执行使用“配置”中激活的版本；岗位名册同步该版本的绑定。', presetRegistered: '已登记声明', presetUnavailable: '原生预设目录暂不可读', presetDiagnostic: '激活诊断',
      actionExecuting: '动作执行中', developmentRunning: '开发调度动作运行中', resumeDevelopment: '恢复开发',
      nativePlugins: '原生插件实际目录', pluginComposition: '预设配套插件', enabled: '启用', fiberPhase: '纤程状态', module: '模块',
      planningBlockers: '初始登记规划阻塞', executionBlockers: '当前执行解阻', blockedCards: '{count} 张卡存在已登记阻塞',
      reviewedConfiguration: '已审核工作流配置', configurationSource: '配置来源', configurationHash: '配置 SHA256',
      liveTarget: '实际 Native 会话 / 并发目标', desiredConcurrency: '目标并发', softwareCap: '软件活动上限', noSoftwareCap: '不设置额外软件上限',
      modelConfiguration: '已审核模型配置', providerModel: '提供商模型 ID', reasoningEffort: '推理档位', maxOutputTokens: '输出 Token 上限',
      roleAllocation: '实际岗位分配', roleAllocationCount: '登记岗位数', liveNote: '实际会话从未撤权、未关闭的 HELD 生命周期读取；配置和调度进程不增加会话计数。',
      configurationReadOnly: '此处回读已审核配置；修改需要新的权威配置版本。', admissionNote: '实际准入继续受当前资源与模型请求账本约束。',
      configuration: '审核配置', deliveryWindow: '完整交付窗口', modelRoute: '模型路由', exportBlueprint: '导出可复用工作流蓝图',
      sourceDetails: '展开配置来源与摘要', registeredListUnavailable: '已登记目录统计可读，卡片列表暂不可读。',
      reuse: '蓝图复用', uploadBlueprint: '上传 v2 工作流蓝图', targetProject: '目标项目 ID', loadContext: '读取真实目标上下文',
      targetCatalog: '目标规划目录 ID', taskPrefix: '新任务 ID 前缀', rolePrefix: '新岗位 ID 前缀', sourcePath: '来源路径前缀',
      targetPath: '目标路径前缀', executorMapping: '目标执行器 Profile', resourceMapping: '目标资源 Profile', modelMapping: '目标模型路由',
      requirementMapping: '需求映射', teamMapping: '团队映射', ownerMapping: '领地 Owner 映射', presetMapping: '预设名称映射',
      mappingDraft: '生成显式映射草案', advancedMapping: '全部逻辑映射 JSON', previewImport: '实际预检查', importReviewed: '确认审阅并登记规划',
      blueprintVersion: '请上传完整的 forgeflow.native-project-blueprint.v2 蓝图。', mappingMissing: '请读取目标上下文并补齐显式映射。',
      importCounts: '实际预检查数量', importFindings: '冲突与阻塞', importWarnings: '实际检查提示', planningOnly: '导入仅登记 NEEDS_REVIEW；执行配置、运行资格、Flow 与租约均需随后真实绑定。',
      importResult: '权威导入回执', targetSafetyPaused: '目标项目当前存在安全暂停', projectSafetyPaused: '项目安全暂停：新增尝试准入受阻，调度暂停单独记录。',
      previewChanged: '映射或目标上下文已改变，请重新实际预检查。', contextUnavailable: '目标上下文尚不可读',
      presetMappingNote: '预设映射为规划声明；目标执行器与岗位仍需真实准入。', selectedFile: '已读取蓝图文件',
      unmappedFields: '尚未补齐的映射字段', mappingIssueCount: '{count} 个字段需要明确目标', missingTarget: '目标尚未填写',
      missingSourceKey: '缺少来源映射键', extraSourceKey: '来源未声明此映射键', invalidMappingJson: '映射 JSON 尚不可解析',
      targetPresetChoices: '当前目标执行器的实际登记预设', targetPresetUnavailable: '目标预设目录尚未验证；请明确选择或填写目标预设 ID。',
      outcomeUnknown: '请求结果尚未确定：服务端可能仍在处理或已提交，请以权威回执为准。',
      retrySameRequest: '重试相同内容时将保留原请求编号。', requestIdentity: '请求编号',
      verificationRecovery: '候选复用与独立验收', verificationOnce: '复用已有候选，执行一次独立验收',
      verificationReuse: '复用已有候选，执行独立验收', verificationRecoveryNote: '正式完成以独立验收的权威回执与验收证据为准。',
      targetAttempt: '复用候选的目标尝试', priorVerification: '前次验收操作', repairKind: '验收修复类型', repairIdentity: '修复登记 ID',
      expectedCases: '必须执行的案例数', maxVerifications: '最多执行次数', runtimeFiles: '运行资产数', runtimeBytes: '运行资产总字节',
      originalPlanHash: '原始验收计划 SHA256', runtimeManifestHash: '运行资产清单 SHA256', interpreterHash: '解释器 SHA256',
      retainedCandidateReview: '保留候选的独立复核', retainedCandidateNote: '目标任务卡须在新验收与集成后正式登记完成。此复核不增加 Native 并发会话计数。',
      sourceAttempt: '原生产尝试', sourceRole: '原 Native 岗位', sourceTaskRevision: '原生产任务版本', targetCard: '目标原始任务卡',
      reviewTask: '独立复核任务', reviewAttempt: '实际复核尝试', reviewState: '复核状态', reviewNotStarted: '尚未启动',
      verificationPlan: '新验收计划', modelCallsBudget: '模型调用预算', readOnlyPolicy: '只读策略', deadlineAt: '截止时间',
      candidateHash: '候选 SHA256', provenanceHash: '生产来源 SHA256', retainedHistory: '原生产尝试与模型历史保留',
      resourceActive: '活动准入槽', resourceCoding: '编码准入槽', resourceCpu: 'CPU 准入额度', resourceMemory: '内存字节',
      resourceBuild: '构建许可', resourceGpu: 'GPU 许可', resourceModels: '模型在途额度',
      startReview: '启动独立复核', resumeReview: '恢复独立复核', reviewActionRunning: '独立复核操作运行中',
      sourceTask: '原生产任务', sourceGeneration: '原生产代次', sourceBase: '原生产 Base SHA', modelRequestLimit: '复核执行配置的模型请求上限',
    };
    const en = {
      panel: 'Development Workflow', title: 'Workflow & Agent Teams', subtitle: 'Planning, specialized presets, native collaboration and controlled delivery.',
      project: 'Project', chooseProject: 'Choose project', refresh: 'Refresh', refreshing: 'Reading authoritative state…', auto: 'Auto refresh',
      prepare: 'Align and bind', start: 'Start development', pause: 'Pause new work', replan: 'Replan', retry: 'Retry task', cancel: 'Stop attempt',
      actionPending: 'Submitting action…', actionReceipt: 'Authoritative action receipt', actionStatus: 'Action status', actionId: 'Action identity',
      actionNote: 'Accepted actions, actual starts and product acceptance are separate records.', requestFailed: 'Request failed', stale: 'Showing the last successful read; refresh to update.',
      noProject: 'No readable project', readOnly: 'This project is read only', waiting: 'Waiting for authoritative data', unknown: 'Not supplied',
      catalog: 'All task cards', dag: 'Task DAG', agents: 'Agent Teams', workflow: 'Native Workflow', presets: 'Plugins and Agent presets', overview: 'Delivery chain',
      catalogCount: 'Registered task cards', roleCount: 'Registered positions', runningCount: 'Running / Native held', acceptedCount: 'Accepted catalog cards',
      catalogNote: 'Authoritative catalog count; list reads are separate', roleNote: 'Planned identities; sessions are counted separately', runningNote: 'RUNNING attempts / actual live Native sessions',
      acceptedNote: 'Finalized independent acceptance for original catalog cards', source: 'Source', observed: 'Observed', revision: 'Authority revision', model: 'Actual model binding',
      planned: 'Registered', committed: 'Current Flow coverage', configured: 'Execution bound', executing: 'Executing', accepted: 'Accepted',
      deadline: 'Full delivery window · {days} days', noDeadline: 'Delivery window not registered', blockers: 'Current blockers', noBlockers: 'This source has not supplied blockers',
      search: 'Search card ID, feature, position or Owner', allOwners: 'All Owners', task: 'Task / feature', owner: 'Owner / team', state: 'State / binding', details: 'Inspect card',
      emptyCatalog: 'Registered catalog not available', emptyFilter: 'No matching task', previous: 'Previous', next: 'Next', pagination: 'Page {page} / {pages} · {count} cards',
      currentFlow: 'Current committed Flow · R{revision}', noFlow: 'Waiting for committed Flow', noEnvelope: 'Execution binding pending', envelope: 'Frozen execution configuration',
      requirements: 'Requirements', readSet: 'Exact reads', writeSet: 'Exact writes', dependencies: 'Dependencies', inputs: 'Inputs and independent verification',
      predecessor: 'Direct predecessors', successor: 'Direct successors', dagNote: 'Full catalog: {cards} cards, {edges} edges. Showing the selected card’s direct neighborhood.',
      dagMore: 'Showing {shown} / {total}', unregisteredDependency: 'Dependency card not registered', noPredecessor: 'No direct predecessor', noSuccessor: 'No direct successor',
      roster: 'Position roster', role: 'Position', parent: 'Parent', root: 'Root session', preset: 'Agent preset', presetHash: 'Preset SHA256', depth: 'Delegation depth',
      workerContexts: 'Actual Worker Native contexts', hostContexts: 'Native Web sessions', session: 'Session', allocation: 'Allocation', openSession: 'Open native session',
      sessionLoading: 'Reading native session catalog', noSession: 'No registered session on this native Host', noNative: 'No Native lifecycle record for this project',
      teamTasks: 'Native shared tasks', teamNote: 'Team completion is a Native observation. Formal cards require control-plane acceptance evidence.',
      observedTeams: 'Worker Bridge native Team events', noTeam: 'No observed Team member or shared task', member: 'Member', position: 'Position binding',
      workflowNote: 'Runs, phases and members come from durable events. Native completion does not accept formal tasks.', noWorkflow: 'No Native Workflow run event',
      phase: 'Phase', outcome: 'Native outcome', nativeEvent: 'Native event', workflowMissing: 'run-start record not available',
      resources: 'Actual resource admission', scope: 'Resource scope', dimension: 'Dimension', allocated: 'Retained', hardLimit: 'Current limit',
      models: 'Actual model requests', modelPending: 'Model in flight', usageUnknown: 'Unknown / quarantined usage', inputTokens: 'Input tokens', outputTokens: 'Output tokens',
      executor: 'Executor Profile', plugins: 'Plugins', capability: 'Frozen capabilities', qualification: 'Actual qualification', qualifiedScope: 'Qualified scope',
      noAudit: 'Audit not bound to this execution profile', noPreset: 'Position preset not bound', observationNote: 'This panel reads native facts; authorized actions use the Bridge.',
      replanReason: 'Replanning reason', pollUnavailable: 'Server has not supplied an auto-refresh interval', receipts: 'Recent native operations', showMore: 'Show more',
      currentAttempt: 'Selected actual attempt', noAttempt: 'No attempt record', close: 'Close details', planOnly: 'Planning registered; execution binding and acceptance continue',
      directoryUnavailable: 'The current catalog is unavailable. Refresh authoritative state; failed counts display —.', sourceNotReady: 'Project snapshot and reviewed configuration are not ready',
      nativePresets: 'DSH UI host preset catalog', nativePresetsNote: 'These presets are registered in the current UI host. Project execution uses the version activated in Reviewed config; the position roster follows that version.', presetRegistered: 'Declared registration', presetUnavailable: 'Native preset catalog is unavailable', presetDiagnostic: 'Activation diagnostic',
      actionExecuting: 'Action running', developmentRunning: 'Development scheduling action running', resumeDevelopment: 'Resume development',
      nativePlugins: 'Actual native plugin inventory', pluginComposition: 'Preset plugin composition', enabled: 'Enabled', fiberPhase: 'Fiber phase', module: 'Module',
      planningBlockers: 'Initial registered planning blockers', executionBlockers: 'Current execution blockers', blockedCards: '{count} cards have registered blockers',
      reviewedConfiguration: 'Reviewed workflow configuration', configurationSource: 'Configuration source', configurationHash: 'Configuration SHA256',
      liveTarget: 'Actual Native sessions / concurrency target', desiredConcurrency: 'Desired concurrency', softwareCap: 'Software active ceiling', noSoftwareCap: 'No additional software ceiling',
      modelConfiguration: 'Reviewed model configuration', providerModel: 'Provider model ID', reasoningEffort: 'Reasoning effort', maxOutputTokens: 'Output token limit',
      roleAllocation: 'Actual position allocation', roleAllocationCount: 'Registered positions', liveNote: 'Actual sessions come from non-revoked, open HELD lifecycles. Configuration and scheduler processes add no sessions.',
      configurationReadOnly: 'This view reads reviewed configuration. Changes require a new authoritative configuration version.', admissionNote: 'Actual admission remains constrained by current resource and model-request ledgers.',
      configuration: 'Reviewed config', deliveryWindow: 'Full delivery window', modelRoute: 'Model route', exportBlueprint: 'Export reusable workflow blueprint',
      sourceDetails: 'Show configuration source and digests', registeredListUnavailable: 'Registered catalog totals are available, but its card list is not.',
      reuse: 'Reuse blueprint', uploadBlueprint: 'Upload v2 workflow blueprint', targetProject: 'Target project ID', loadContext: 'Read actual target context',
      targetCatalog: 'Target planning catalog ID', taskPrefix: 'New task ID prefix', rolePrefix: 'New position ID prefix', sourcePath: 'Source path prefix',
      targetPath: 'Target path prefix', executorMapping: 'Target executor Profile', resourceMapping: 'Target resource Profile', modelMapping: 'Target model route',
      requirementMapping: 'Requirement mapping', teamMapping: 'Team mapping', ownerMapping: 'Territory Owner mapping', presetMapping: 'Preset name mapping',
      mappingDraft: 'Generate explicit mapping draft', advancedMapping: 'Complete logical mapping JSON', previewImport: 'Run actual preview', importReviewed: 'Confirm review and register planning',
      blueprintVersion: 'Upload a complete forgeflow.native-project-blueprint.v2 blueprint.', mappingMissing: 'Read target context and complete explicit mappings.',
      importCounts: 'Actual preview counts', importFindings: 'Conflicts and blockers', importWarnings: 'Actual check warnings', planningOnly: 'Import registers NEEDS_REVIEW only. Execution configuration, qualification, Flow and leases require later real binding.',
      importResult: 'Authoritative import receipt', targetSafetyPaused: 'The target project has a safety pause', projectSafetyPaused: 'Project safety pause blocks new attempt admission. Scheduling pause is a separate record.',
      previewChanged: 'Mapping or target context changed. Run a new actual preview.', contextUnavailable: 'Target context is not readable',
      presetMappingNote: 'Preset mappings declare planning. Target executors and positions still require actual admission.', selectedFile: 'Blueprint file read',
      unmappedFields: 'Incomplete mapping fields', mappingIssueCount: '{count} fields need an explicit target', missingTarget: 'Target not filled',
      missingSourceKey: 'Source mapping key is missing', extraSourceKey: 'Source did not declare this mapping key', invalidMappingJson: 'Mapping JSON cannot be parsed',
      targetPresetChoices: 'Actual registered presets of the target executor', targetPresetUnavailable: 'Target preset catalog is not verified. Select or enter an explicit target preset ID.',
      outcomeUnknown: 'Request outcome is unknown: the server may still be processing or may have committed. An authoritative receipt is required.',
      retrySameRequest: 'Retrying unchanged content keeps the original request ID.', requestIdentity: 'Request ID',
      verificationRecovery: 'Candidate reuse and independent verification', verificationOnce: 'Reuse the existing candidate for one independent verification',
      verificationReuse: 'Reuse the existing candidate for independent verification', verificationRecoveryNote: 'Formal completion requires the authoritative independent-verification receipt and acceptance evidence.',
      targetAttempt: 'Candidate attempt to reuse', priorVerification: 'Prior verification operation', repairKind: 'Verification repair kind', repairIdentity: 'Registered repair ID',
      expectedCases: 'Required cases', maxVerifications: 'Maximum verification runs', runtimeFiles: 'Runtime assets', runtimeBytes: 'Total runtime asset bytes',
      originalPlanHash: 'Original verification-plan SHA256', runtimeManifestHash: 'Runtime manifest SHA256', interpreterHash: 'Interpreter SHA256',
      retainedCandidateReview: 'Independent review of retained candidate', retainedCandidateNote: 'The original card requires new verification and integration before formal completion. This review adds no Native concurrent session.',
      sourceAttempt: 'Original producing attempt', sourceRole: 'Original Native position', sourceTaskRevision: 'Original production task revision', targetCard: 'Original target card',
      reviewTask: 'Independent review task', reviewAttempt: 'Actual review attempt', reviewState: 'Review state', reviewNotStarted: 'Not started',
      verificationPlan: 'New verification plan', modelCallsBudget: 'Model-call budget', readOnlyPolicy: 'Read-only policy', deadlineAt: 'Deadline',
      candidateHash: 'Candidate SHA256', provenanceHash: 'Production provenance SHA256', retainedHistory: 'Original producing attempt and model history retained',
      resourceActive: 'Active admission slots', resourceCoding: 'Coding admission slots', resourceCpu: 'CPU admission units', resourceMemory: 'Memory bytes',
      resourceBuild: 'Build permits', resourceGpu: 'GPU permits', resourceModels: 'In-flight model limit',
      startReview: 'Start independent review', resumeReview: 'Resume independent review', reviewActionRunning: 'Independent review action running',
      sourceTask: 'Original producing task', sourceGeneration: 'Original production generation', sourceBase: 'Original production Base SHA', modelRequestLimit: 'Review execution model-request limit',
    };
    const css = `
      .ff-native-panel{height:100%;min-width:0;overflow:auto;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font-size:13px;line-height:1.6;padding:28px;box-sizing:border-box;}
      .ff-native-panel *{box-sizing:border-box}.ff-native-panel h1,.ff-native-panel h2,.ff-native-panel h3,.ff-native-panel p{margin:0}.ff-native-panel h1{font-size:28px;line-height:1.25;letter-spacing:-.8px;font-weight:600}
      .ff-native-panel h2{font-size:16px;line-height:1.5;font-weight:600}.ff-native-panel h3{font-size:13px;line-height:1.5;font-weight:600}.ff-native-panel button:focus-visible,.ff-native-panel [role=button]:focus-visible{outline:2px solid var(--dsw-alias-label-primary);outline-offset:3px}
      .ffp-header,.ffp-toolbar,.ffp-heading,.ffp-pagination{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}.ffp-header{margin-bottom:20px}.ffp-header p,.ffp-note,.ffp-meta{color:var(--dsw-alias-label-tertiary);font-size:12px;line-height:1.8}.ffp-header p{margin-top:8px}.ffp-toolbar{justify-content:flex-start;margin:14px 0}.ffp-meta{display:flex;gap:14px;flex-wrap:wrap;margin:10px 0}.ffp-caption{color:var(--dsw-alias-label-caption);font-size:11px;line-height:1.6}
      .ffp-card,.ffp-stat,.ffp-role{background:var(--dsw-alias-bg-layer-1);border:.5px solid var(--dsw-alias-border-l1);border-radius:18px;padding:20px}.ffp-card{margin-top:18px;min-width:0}.ffp-heading{margin-bottom:16px}.ffp-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:20px 0}.ffp-stat{display:grid;gap:6px}.ffp-stat strong{font-size:28px;line-height:1.3;font-weight:600;font-variant-numeric:tabular-nums;letter-spacing:-.7px}.ffp-roles{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.ffp-role{padding:16px}.ffp-role p{margin-top:8px}.ffp-layout{display:grid;grid-template-columns:minmax(0,1fr) minmax(290px,340px);gap:18px;align-items:start}.ffp-details{position:sticky;top:0}
      .ffp-chain{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px}.ffp-chain>div{padding:18px;border-radius:14px;background:var(--dsw-alias-bg-base);border:.5px solid var(--dsw-alias-border-l1)}.ffp-chain strong{display:block;font-size:23px;line-height:1.4;font-variant-numeric:tabular-nums}.ffp-error{margin:14px 0;padding:14px;border:.5px solid var(--dsw-alias-border-l1);border-radius:14px;background:var(--dsw-alias-bg-layer-1);white-space:pre-wrap;overflow-wrap:anywhere}.ffp-empty{padding:32px;text-align:center;color:var(--dsw-alias-label-tertiary)}
      .ffp-table-wrap{overflow:auto;max-width:100%}.ff-native-panel table{width:100%;border-collapse:collapse;min-width:650px;font-size:12px;line-height:1.7}.ff-native-panel th{text-align:left;color:var(--dsw-alias-label-tertiary);font-weight:500;padding:10px}.ff-native-panel td{padding:12px 10px;border-top:.5px solid var(--dsw-alias-border-l1);vertical-align:top}.ff-native-panel td small{display:block;color:var(--dsw-alias-label-tertiary)}.ff-native-panel td code{display:block;font-size:10px;line-height:1.8;overflow-wrap:anywhere}.ffp-link{border:0;background:transparent;color:inherit;padding:0;max-width:420px;text-align:left;cursor:pointer;font:inherit}.ffp-link:hover{text-decoration:underline;text-underline-offset:3px}.ffp-pagination{margin-top:16px}.ffp-search{flex:1;min-width:200px;max-width:650px}.ffp-input-row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.ffp-input-row>span{flex:1;min-width:220px}
      .ff-native-panel dl{display:grid;grid-template-columns:100px minmax(0,1fr);gap:8px 12px;font-size:12px;line-height:1.7;margin:12px 0}.ff-native-panel dt{color:var(--dsw-alias-label-tertiary)}.ff-native-panel dd{margin:0;overflow-wrap:anywhere}.ff-native-panel code,.ff-native-panel pre{font-family:var(--dsw-font-mono,monospace)}.ff-native-panel pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:11px;line-height:1.8}.ff-native-panel ul{padding-left:20px;margin:8px 0}.ffp-paths{max-height:220px;overflow:auto;font-size:11px;line-height:1.8;overflow-wrap:anywhere}.ffp-paths li+li{margin-top:5px}.ffp-tags{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}.ffp-context{padding:14px 0;border-top:.5px solid var(--dsw-alias-border-l1)}.ffp-context:first-child{border:0}.ffp-indent{margin-left:calc(var(--ffp-depth,0)*18px)}
      .ffp-dag{overflow:auto;max-height:700px;padding:8px;border-radius:14px;background:var(--dsw-alias-bg-base)}.ffp-dag svg{display:block;min-width:800px;width:100%;color:var(--dsw-alias-label-tertiary)}.ffp-dag path{fill:none;stroke:var(--dsw-alias-border-l1);stroke-width:1.2}.ffp-dag rect{fill:var(--dsw-alias-bg-layer-1);stroke:var(--dsw-alias-border-l1);stroke-width:.5}.ffp-dag .ffp-dag-selected rect{stroke:var(--dsw-alias-label-primary);stroke-width:1.2}.ffp-dag text{fill:var(--dsw-alias-label-primary);font-size:12px}.ffp-dag .ffp-dag-id{fill:var(--dsw-alias-label-tertiary);font-size:9px}.ffp-dag [role=button]{cursor:pointer}.ffp-dag [role=button]:hover rect{fill:var(--dsw-alias-interactive-bg-hover)}
      .ffp-import-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;margin:16px 0}.ffp-import-field{display:flex;flex-direction:column;gap:6px;min-width:0}.ffp-json-editor{width:100%;resize:vertical;padding:14px;border:.5px solid var(--dsw-alias-border-l1);border-radius:12px;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font-family:var(--dsw-font-mono,monospace);font-size:12px;line-height:1.7}.ff-native-panel details{margin:12px 0}.ff-native-panel summary{cursor:pointer;color:var(--dsw-alias-label-secondary)}
      .ffp-card,.ffp-role,.ffp-stat{animation:ffp-enter .2s ease-out}.ffp-role{transition:background .16s ease-out}.ffp-role:hover{background:var(--dsw-alias-interactive-bg-hover)}@keyframes ffp-enter{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
      @media(max-width:1200px){.ffp-roles{grid-template-columns:repeat(2,minmax(0,1fr))}.ffp-layout{grid-template-columns:1fr}.ffp-details{position:static}}@media(max-width:850px){.ff-native-panel{padding:18px}.ffp-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.ffp-chain{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:520px){.ff-native-panel{padding:12px}.ff-native-panel h1{font-size:23px}.ffp-card,.ffp-stat{padding:14px}.ffp-roles{grid-template-columns:1fr}.ffp-chain{grid-template-columns:repeat(2,minmax(0,1fr))}.ffp-stat strong{font-size:24px}}@media(prefers-reduced-motion:reduce){.ff-native-panel *{animation:none!important;transition:none!important}}
    `;
    const record = value => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
    const list = value => Array.isArray(value) ? value.filter(row => row && typeof row === 'object' && !Array.isArray(row)) : [];
    const number = value => typeof value === 'number' && Number.isFinite(value) ? value : undefined;
    const display = (value, t) => value === null || value === undefined || value === '' ? t('unknown')
      : typeof value === 'string' ? value : JSON.stringify(value);
    const count = value => number(value) === undefined ? '—' : value.toLocaleString();
    const strings = value => Array.isArray(value) ? value.map(row => typeof row === 'string' ? row : JSON.stringify(row)) : [];
    const taskId = row => row.task_id ?? row.card_id ?? row.id;
    const unwrap = value => {
      const row = record(value);
      if (typeof row.content === 'string') return record(JSON.parse(row.content));
      return Object.keys(record(row.value)).length ? record(row.value) : row;
    };
    const observation = row => {
      const payload = record(row.payload);
      const source = Object.keys(record(payload.observation)).length ? record(payload.observation) : Object.keys(payload).length ? payload : row;
      return { ...row, event: source.event ?? row.event, value: record(source.value ?? row.value) };
    };
    const reasons = row => [...new Set([
      ...strings(row.admission_blockers), ...strings(row.blockers), ...strings(row.blocking_reasons),
      ...strings(record(row.metadata).admission_blockers),
    ])];
    function safeRequestError(error, t) {
      const row = record(error);
      const source = row.source ? `[${row.source}] ` : '';
      const status = row.status ? ` (HTTP ${row.status})` : '';
      return `${source}${error.code ?? t('requestFailed')}${status}: ${error.message ?? (typeof error === 'string' ? error : t('waiting'))}`;
    }
    async function request(url, body, signal) {
      const response = await fetch(url, {
        method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', signal,
        headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      const text = await response.text();
      let parsed;
      try { parsed = text ? JSON.parse(text) : null; }
      catch { throw Object.assign(new Error(`HTTP ${response.status}: ${response.statusText}`), { code: 'INVALID_RESPONSE' }); }
      if (!response.ok || record(parsed).ok === false) {
        const failure = record(record(parsed).error);
        throw Object.assign(new Error(failure.message ?? record(parsed).message ?? `HTTP ${response.status}`), {
          code: failure.code ?? record(parsed).code ?? `HTTP_${response.status}`,
          details: failure.details ?? record(parsed).details,
          outcome: failure.outcome ?? record(parsed).outcome,
          retry_same_request_id: failure.retry_same_request_id ?? record(parsed).retry_same_request_id,
          request_id: failure.request_id ?? record(parsed).request_id,
          status: response.status,
        });
      }
      return Object.hasOwn(record(parsed), 'data') ? parsed.data : Object.hasOwn(record(parsed), 'value') ? parsed.value : parsed;
    }
    function ErrorBox({ value, t }) {
      const details = record(value.details);
      return h('div', { className: 'ffp-error', role: 'alert' }, safeRequestError(value, t),
        value.outcome === 'UNKNOWN_COMMIT_OR_PENDING' && h('p', null, t('outcomeUnknown')),
        value.retry_same_request_id === true && h('p', null, t('retrySameRequest')),
        value.request_id && h('p', null, t('requestIdentity') + ' · ', h('code', null, value.request_id)),
        details.field && h('p', null, h('code', null, details.field), details.subject ? ' · ' + details.subject : '', details.reason ? ' · ' + details.reason : ''));
    }
    function Paths({ name, value, t }) {
      const paths = strings(value);
      return h('section', null, h('h3', null, t(name)), paths.length ? h('ul', { className: 'ffp-paths' },
        paths.map((item, index) => h('li', { key: `${index}:${item}` }, h('code', null, item)))) : h('p', { className: 'ffp-note' }, t('unknown')));
    }
    function Metric({ name, value, note, t }) {
      return h('div', { className: 'ffp-stat' }, h('span', { className: 'ffp-note' }, t(name)), h('strong', null, value), h('small', { className: 'ffp-caption' }, t(note)));
    }
    function VerificationRecovery({ value, t }) {
      const recovery = record(value);
      if (recovery.enabled !== true) return null;
      const runtime = record(recovery.runtime);
      return h('section', { className: 'ffp-card' }, h('h3', null, t('verificationRecovery')),
        h('p', null, t(recovery.max_once === 1 ? 'verificationOnce' : 'verificationReuse')),
        h('dl', null, h('dt', null, t('targetAttempt')), h('dd', null, h('code', null, display(recovery.attempt_id, t))),
          h('dt', null, t('priorVerification')), h('dd', null, h('code', null, display(recovery.prior_operation_id, t))),
          h('dt', null, t('repairKind')), h('dd', null, display(recovery.repair_kind, t)),
          h('dt', null, t('repairIdentity')), h('dd', null, h('code', null, display(recovery.repair_id, t))),
          h('dt', null, t('expectedCases')), h('dd', null, count(number(recovery.expected_case_count))),
          h('dt', null, t('maxVerifications')), h('dd', null, count(number(recovery.max_once))),
          h('dt', null, t('runtimeFiles')), h('dd', null, count(number(runtime.file_count))),
          h('dt', null, t('runtimeBytes')), h('dd', null, count(number(runtime.total_bytes)))),
        h('p', { className: 'ffp-note' }, t('verificationRecoveryNote')),
        h('details', null, h('summary', null, t('sourceDetails')), h('dl', null,
          h('dt', null, t('originalPlanHash')), h('dd', null, h('code', null, display(recovery.original_plan_sha256, t))),
          h('dt', null, t('runtimeManifestHash')), h('dd', null, h('code', null, display(runtime.manifest_sha256, t))),
          h('dt', null, t('interpreterHash')), h('dd', null, h('code', null, display(runtime.interpreter_sha256, t)))),
          h('pre', null, JSON.stringify({ generation: recovery.generation, task_revision: recovery.task_revision,
            repair_revision: recovery.repair_revision, repair_sha256: recovery.repair_sha256,
            execution_rights_granted: recovery.execution_rights_granted }, null, 2))));
    }
    function RetainedCandidateReview({ value, t }) {
      const review = record(value);
      if (review.enabled !== true || review.mode !== 'RETAINED_NATIVE_CANDIDATE_REVIEW') return null;
      const resources = record(review.resource_request);
      const resourceKeys = [['active_slot', 'resourceActive'], ['coding_slot', 'resourceCoding'], ['cpu_units', 'resourceCpu'],
        ['memory_bytes', 'resourceMemory'], ['build_permit', 'resourceBuild'], ['gpu_permit', 'resourceGpu'], ['provider_inflight', 'resourceModels']];
      const notStarted = review.review_attempt_state === 'NOT_STARTED'
        || Object.hasOwn(review, 'review_attempt_state') && review.review_attempt_state === null && review.review_attempt_id === null;
      return h('section', { className: 'ffp-card' }, h('h3', null, t('retainedCandidateReview')),
        h('p', null, t(review.max_once === 1 ? 'verificationOnce' : 'verificationReuse')),
        h('dl', null, h('dt', null, t('sourceAttempt')), h('dd', null, h('code', null, display(review.source_attempt_id, t))),
          h('dt', null, t('sourceTask')), h('dd', null, h('code', null, display(review.source_task_id, t))),
          h('dt', null, t('sourceRole')), h('dd', null, display(review.source_role_id, t)),
          h('dt', null, t('sourceGeneration')), h('dd', null, count(number(review.source_generation))),
          h('dt', null, t('sourceTaskRevision')), h('dd', null, count(number(review.source_task_revision))),
          h('dt', null, t('targetCard')), h('dd', null, h('code', null, display(review.target_task_id, t))),
          h('dt', null, t('reviewTask')), h('dd', null, h('code', null, display(review.review_task_id, t))),
          h('dt', null, t('reviewAttempt')), h('dd', null, h('code', null, display(review.review_attempt_id, t))),
          h('dt', null, t('reviewState')), h('dd', null, notStarted ? t('reviewNotStarted') : display(review.review_attempt_state, t)),
          h('dt', null, t('verificationPlan')), h('dd', null, h('code', null, display(review.verification_plan_id, t))),
          h('dt', null, t('expectedCases')), h('dd', null, count(number(review.expected_cases))),
          h('dt', null, t('maxVerifications')), h('dd', null, count(number(review.max_once))),
          h('dt', null, t('modelCallsBudget')), h('dd', null, count(number(review.model_calls))),
          h('dt', null, t('modelRequestLimit')), h('dd', null, count(number(record(review.model_budget).max_model_requests))),
          h('dt', null, t('readOnlyPolicy')), h('dd', null, display(review.read_only, t)),
          h('dt', null, t('deadlineAt')), h('dd', null, display(review.deadline_at, t))),
        review.old_attempt_preserved === true && h('p', { className: 'ffp-note' }, t('retainedHistory')),
        h('p', { className: 'ffp-note' }, t('retainedCandidateNote')),
        h('h3', null, t('resources')), Object.keys(resources).length ? h('dl', null,
          ...resourceKeys.flatMap(([key, label]) => [h('dt', { key: key + '-name' }, t(label)), h('dd', { key }, count(number(resources[key])))]))
          : h('p', { className: 'ffp-note' }, t('unknown')),
        h('details', null, h('summary', null, t('sourceDetails')), h('dl', null,
          h('dt', null, t('sourceBase')), h('dd', null, h('code', null, display(review.base_sha, t))),
          h('dt', null, t('candidateHash')), h('dd', null, h('code', null, display(review.candidate_sha, t))),
          h('dt', null, t('provenanceHash')), h('dd', null, h('code', null, display(review.source_provenance_sha256, t))),
          h('dt', null, t('verificationPlan')), h('dd', null, h('code', null, display(review.verification_plan_sha256, t))))));
    }
    function MappingChoice({ value, onChange, options, label }) {
      const [open, setOpen] = useState(false);
      return h(Menu, { open, portal: true, selectedId: value,
        anchor: h(Button, { size: 'sm', variant: 'outline', onClick: () => setOpen(item => !item), 'aria-expanded': open }, options.find(row => row.id === value)?.label ?? label),
        items: options, onClose: () => setOpen(false), onSelect: id => { onChange(id); setOpen(false); } });
    }
    function NativeConfigurationEditor({ projectId, t }) {
      const labels = t('panel') === '开发工作流' ? editorZh : editorEn;
      const e = key => labels[key] ?? t(key);
      const [context, setContext] = useState(null);
      const [spec, setSpec] = useState(null);
      const [saved, setSaved] = useState(null);
      const [versions, setVersions] = useState([]);
      const [selected, setSelected] = useState('');
      const [dirty, setDirty] = useState(false);
      const [busy, setBusy] = useState('');
      const [error, setError] = useState(null);
      const [newId, setNewId] = useState('');
      const [newName, setNewName] = useState('');
      const pending = useRef(null);
      const life = useRef(null);
      async function load(signal) {
        setBusy('LOAD'); setError(null);
        try {
          const [ctx, rows] = await Promise.all([
            request('/api/forgeflow-panel/configuration?project_id=' + encodeURIComponent(projectId), undefined, signal),
            request('/api/forgeflow-panel/configuration-drafts?project_id=' + encodeURIComponent(projectId), undefined, signal),
          ]);
          if (signal.aborted) return;
          setContext(ctx); setSpec(structuredClone(ctx.spec)); setSelected(ctx.spec.presets[0]?.id ?? '');
          setSaved(null); setVersions(list(rows)); setDirty(false); pending.current = null;
        } catch (failure) { if (!signal.aborted) setError(failure); }
        finally { if (!signal.aborted) setBusy(''); }
      }
      useEffect(() => {
        const controller = new AbortController(); life.current = controller;
        setContext(null); setSpec(null); setSaved(null); setVersions([]);
        if (projectId) load(controller.signal);
        return () => controller.abort();
      }, [projectId]);
      function update(fn) {
        setSpec(current => { const value = structuredClone(current); fn(value); return value; });
        setDirty(true); pending.current = null;
      }
      function selectVersion(id) {
        const version = versions.find(row => row.draft_id === id);
        if (!version || busy) return;
        setSpec(structuredClone(version.spec)); setSaved(version); setSelected(version.spec.presets[0]?.id ?? '');
        setDirty(false); setError(null); pending.current = null;
      }
      async function mutate(action) {
        if (!spec || !context || busy) return;
        setBusy(action); setError(null);
        const draftId = saved?.draft_id ?? pending.current?.draft_id ?? ('native-edit-' + crypto.randomUUID());
        const body = { project_id: projectId, action, draft_id: draftId,
          ...(action === 'SAVE' ? { expected_revision: saved?.revision ?? null, base_config_sha256: context.base_config_sha256, spec }
            : { expected_revision: saved.revision, ...(['PUBLISH', 'ACTIVATE'].includes(action) ? { review_sha256: saved.review_sha256 } : {}) }) };
        const fingerprint = JSON.stringify(body);
        if (pending.current?.fingerprint !== fingerprint) pending.current = { fingerprint, request_id: crypto.randomUUID(), draft_id: draftId };
        body.request_id = pending.current.request_id;
        try {
          const result = await request('/api/forgeflow-panel/configuration-drafts', body, life.current.signal);
          if (life.current.signal.aborted) return;
          setSaved(result); setVersions(rows => [...rows.filter(row => row.draft_id !== result.draft_id), result]);
          setDirty(false); pending.current = null;
        } catch (failure) { if (!life.current.signal.aborted) setError(mutationFailure(failure, body.request_id)); }
        finally { if (!life.current.signal.aborted) setBusy(''); }
      }
      const preset = spec?.presets.find(row => row.id === selected);
      const readonly = busy !== '' || saved?.status === 'PUBLISHED';
      const workerCapacity = spec?.max_active_attempts_per_worker;
      const invalidWorkerCapacity = workerCapacity !== undefined && (!Number.isInteger(workerCapacity) || workerCapacity < 1 || workerCapacity > 64);
      const field = (key, value, change, multiline) => h('label', { className: 'ffp-import-field' }, h('span', null, e(key)),
        multiline ? h('textarea', { className: 'ffp-textarea', style: { width: '100%', boxSizing: 'border-box', background: 'transparent', color: 'inherit', border: '1px solid var(--border-color, #888)', borderRadius: '8px', padding: '10px', font: 'inherit', resize: 'vertical' }, rows: key === 'personaPrefix' ? 8 : 3, value, disabled: readonly,
          'aria-label': e(key), onChange: event => change(event.target.value) })
          : h(Input, { value, disabled: readonly, 'aria-label': e(key), onChange: event => change(event.target.value) }));
      const pluginCards = (spec?.plugins ?? []).map(plugin => {
        const fields = Object.entries(plugin.config).map(([key, value]) => h('label', { className: 'ffp-import-field', key },
          h('span', null, key), h('input', {
            type: typeof value === 'boolean' ? 'checkbox' : typeof value === 'number' ? 'number' : 'text',
            ...(typeof value === 'boolean' ? { checked: value } : { value }), disabled: readonly || key === 'maxDepth',
            'aria-label': plugin.entry_id + ' · ' + key, min: 1, max: 1000000,
            onChange: event => update(next => { next.plugins.find(row => row.entry_id === plugin.entry_id).config[key] =
              typeof value === 'boolean' ? event.target.checked : typeof value === 'number' ? Number(event.target.value) : event.target.value; }),
          })));
        return h('article', { className: 'ffp-role', key: plugin.entry_id }, h('label', null,
          h('input', { type: 'checkbox', checked: plugin.enabled, disabled: readonly || context.required_plugins.includes(plugin.entry_id),
            onChange: event => update(next => { next.plugins.find(row => row.entry_id === plugin.entry_id).enabled = event.target.checked; }) }),
          h('code', null, ' ' + plugin.entry_id)), context.required_plugins.includes(plugin.entry_id) && h('small', null, e('requiredPlugin')), ...fields);
      });
      const roleRows = (spec?.role_bindings ?? []).map(binding => {
        const options = spec.presets.map(row => h('option', { key: row.id, value: row.id,
          disabled: spec.role_bindings.some(other => other.position_id !== binding.position_id && other.preset_id === row.id) }, row.name + ' · ' + row.id));
        const select = h('select', { value: binding.preset_id, disabled: readonly, 'aria-label': binding.position_id + ' · ' + e('bindPreset'),
          onChange: event => update(next => { next.role_bindings.find(row => row.position_id === binding.position_id).preset_id = event.target.value; }) }, options);
        return h('tr', { key: binding.position_id }, h('td', null, h('code', null, binding.position_id)), h('td', null, select));
      });
      return h('section', { className: 'ffp-card' }, h('div', { className: 'ffp-heading' }, h('h2', null, e('presetEditor')),
        h(Button, { size: 'sm', disabled: !!busy, onClick: () => load(life.current.signal) }, e('loadEditor'))),
        h('p', { className: 'ffp-note' }, e('editorNote')), error && h(ErrorBox, { value: error, t }),
        busy === 'LOAD' && h('p', { role: 'status' }, e('editorLoading')),
        spec && h(React.Fragment, null,
          h('div', { className: 'ffp-toolbar' }, h(MappingChoice, { value: saved?.draft_id ?? '',
            options: versions.map(row => ({ id: row.draft_id, label: `${row.draft_id} · ${row.status} · R${row.revision}` })),
            label: e('chooseDraft'), onChange: selectVersion }),
            h(Button, { size: 'sm', disabled: !!busy, onClick: () => load(life.current.signal) }, e('newDraft')),
            h(Tag, null, context.model), h(Tag, null, `${spec.presets.length} · ${t('preset')}`)),
          h('div', { className: 'ffp-toolbar', 'aria-label': e('editorActions') },
            h(Button, { size: 'sm', disabled: readonly || invalidWorkerCapacity || saved && !dirty, onClick: () => mutate('SAVE') }, e('saveDraft')),
            h(Button, { size: 'sm', disabled: readonly || dirty || !saved || saved.status !== 'DRAFT', onClick: () => mutate('PREVIEW') }, e('previewDraft')),
            h(Button, { size: 'sm', variant: 'primary', disabled: readonly || dirty || saved?.status !== 'PREVIEWED', onClick: () => mutate('PUBLISH') }, e('publishDraft')),
            h(Button, { size: 'sm', disabled: !!busy || dirty || saved?.status !== 'PUBLISHED' || !!saved?.activation, onClick: () => mutate('ACTIVATE') }, e('activateDraft'))),
          saved && h('div', { role: 'status' }, h(Tag, null, saved.status), h('code', null, ` ${saved.draft_id} · R${saved.revision}`),
            h('p', { className: 'ffp-note' }, dirty ? e('draftDirty') : saved.status === 'PUBLISHED' ? e('versionPublished') : e('draftSaved')),
            saved.review && h('p', { className: 'ffp-note' }, e('nativeResolved') + ' · ' + e('activePreserved')),
            saved.activation && h('p', { className: 'ffp-note' }, e('versionActivated') + ' · ' + saved.activation.config_sha256),
            saved.published_executor_profile_id && h('p', null, e('nativeProfile') + ' · ', h('code', null, saved.published_executor_profile_id))),
          h('label', { className: 'ffp-import-field' }, h('span', null, e('workerCapacity')),
            h('input', { type: 'number', min: 1, max: 64, step: 1, value: workerCapacity ?? '', disabled: readonly,
              'aria-label': e('workerCapacity'), 'aria-invalid': invalidWorkerCapacity,
              onChange: event => update(next => {
                if (event.target.value === '') delete next.max_active_attempts_per_worker;
                else next.max_active_attempts_per_worker = Number(event.target.value);
              }) })),
          h('p', { className: 'ffp-note', ...(invalidWorkerCapacity ? { role: 'alert' } : {}) },
            e(invalidWorkerCapacity ? 'workerCapacityInvalid' : 'workerCapacityNote')),
          h('h3', null, t('preset')), h(MappingChoice, { value: selected, onChange: setSelected,
            options: spec.presets.map(row => ({ id: row.id, label: `${row.name} · ${row.id}` })), label: t('preset') }),
          preset && h('div', { className: 'ffp-import-grid' }, h('code', null, preset.id),
            field('presetName', preset.name, value => update(next => { next.presets.find(row => row.id === selected).name = value; })),
            field('presetDescription', preset.description, value => update(next => { next.presets.find(row => row.id === selected).description = value; }), true),
            field('personaPrefix', preset.persona_prefix, value => update(next => { next.presets.find(row => row.id === selected).persona_prefix = value; }), true)),
          h('details', null, h('summary', null, e('newPreset')), h('p', { className: 'ffp-note' }, e('sourcePreset')),
            field('presetIdentity', newId, setNewId), field('presetName', newName, setNewName),
            h(Button, { size: 'sm', disabled: readonly || !preset || !newName.trim() || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(newId) || spec.presets.some(row => row.id === newId),
              onClick: () => { update(next => next.presets.push({ ...structuredClone(preset), id: newId, name: newName, clone_from: preset.clone_from })); setSelected(newId); setNewId(''); setNewName(''); } }, e('newPreset'))),
          h('h3', null, t('plugins')), h('div', { className: 'ffp-roles' }, pluginCards),
          h('h3', null, t('roster')), h('div', { className: 'ffp-table-wrap' }, h('table', null,
            h('thead', null, h('tr', null, h('th', null, t('role')), h('th', null, e('bindPreset')))),
            h('tbody', null, roleRows))),
          !saved?.review && h('p', { className: 'ffp-note' }, e('previewRequired'))));
    }
    function BlueprintImport({ t }) {
      const [projects, setProjects] = useState([]);
      const [targetId, setTargetId] = useState('');
      const [context, setContext] = useState(null);
      const [blueprint, setBlueprint] = useState(null);
      const [fileName, setFileName] = useState('');
      const [catalogId, setCatalogId] = useState('');
      const [taskPrefix, setTaskPrefix] = useState('');
      const [rolePrefix, setRolePrefix] = useState('');
      const [sourcePrefix, setSourcePrefix] = useState('');
      const [targetPrefix, setTargetPrefix] = useState('');
      const [executorId, setExecutorId] = useState('');
      const [resourceId, setResourceId] = useState('');
      const [routeId, setRouteId] = useState('');
      const [mappingText, setMappingText] = useState('');
      const [mappingOpen, setMappingOpen] = useState(false);
      const [preview, setPreview] = useState(null);
      const [imported, setImported] = useState(null);
      const [error, setError] = useState(null);
      const [busy, setBusy] = useState('');
      const pending = useRef(new Map());
      const lifetime = useRef(new AbortController());
      const previewFingerprint = useRef(null);
      const contextRequest = useRef(null);
      const selectedTarget = useRef(targetId);
      selectedTarget.current = targetId;
      const currentForm = useRef(null);
      currentForm.current = { targetId, blueprint, mappingText, context };
      useEffect(() => {
        const controller = new AbortController(); lifetime.current = controller;
        request('/api/forgeflow-panel/import-targets', undefined, controller.signal)
          .then(value => { if (!controller.signal.aborted) setProjects(list(record(value).projects)); }).catch(value => { if (!controller.signal.aborted) setError(value); });
        return () => { controller.abort(); contextRequest.current?.abort(); };
      }, []);
      const target = record(context);
      const targetExecutor = list(target.executor_profiles).find(row => row.id === executorId);
      const targetPresetIds = strings(targetExecutor?.preset_ids);
      const sourceIds = (name, key) => [...new Set(list(record(blueprint)[name]).map(row => row[key] ?? row.id).filter(value => typeof value === 'string'))];
      const targetOptions = (name, key) => list(target[name]).map(row => ({ id: row[key] ?? row.id, label: row.title ?? row.name ?? row.acceptance ?? row[key] ?? row.id }));
      const field = (key, value, onChange) => h('label', { className: 'ffp-import-field', key }, h('span', { className: 'ffp-note' }, t(key)),
        h(Input, { value, onChange: event => onChange(event.target.value), 'aria-label': t(key), disabled: !!busy }));
      const mapped = (group, key) => { try { return record(JSON.parse(mappingText))[group]?.[key] ?? ''; } catch { return ''; } };
      const updateMapping = (group, key, value) => {
        try {
          const body = JSON.parse(mappingText); body[group] = { ...record(body[group]), [key]: value };
          setMappingText(JSON.stringify(body, null, 2)); setPreview(null); setImported(null);
        } catch (value) { setError(value); }
      };
      async function upload(event) {
        const file = event.target.files?.[0]; if (!file) return;
        setError(null); setPreview(null); setImported(null);
        try {
          const value = JSON.parse(await file.text());
          if (value.schema_version !== 'forgeflow.native-project-blueprint.v2' || !['cards', 'roles', 'requirements', 'teams', 'owner_territories', 'parents'].every(key => Array.isArray(value[key]))) {
            throw new Error(t('blueprintVersion'));
          }
          setBlueprint(value); setFileName(file.name); setMappingText('');
        } catch (value) { setError(value); setBlueprint(null); setFileName(''); }
      }
      async function loadContext() {
        if (!targetId || busy) return;
        const controller = new AbortController(); contextRequest.current?.abort(); contextRequest.current = controller;
        setBusy('context'); setError(null); setContext(null); setPreview(null); setImported(null);
        try {
          const value = await request('/api/forgeflow-panel/import-context?project_id=' + encodeURIComponent(targetId), undefined, controller.signal);
          if (!controller.signal.aborted && selectedTarget.current === targetId) setContext(record(value));
        } catch (value) { if (!controller.signal.aborted) setError(value); }
        finally { if (contextRequest.current === controller && !controller.signal.aborted) setBusy(''); }
      }
      function draftMapping() {
        if (!blueprint || !context || !catalogId || !executorId || !resourceId || !routeId) { setError(new Error(t('mappingMissing'))); return; }
        const chooseMatching = (ids, choices) => Object.fromEntries(ids.map(id => [id, choices.some(row => row.id === id) ? id : '']));
        const sourceTasks = sourceIds('cards', 'task_id');
        const mapping = { target_catalog_id: catalogId,
          requirement_ids: chooseMatching(sourceIds('requirements', 'requirement_id'), targetOptions('requirements', 'requirement_id')),
          team_ids: chooseMatching(sourceIds('teams', 'team_id'), targetOptions('teams', 'team_id')),
          owner_ids: chooseMatching(sourceIds('owner_territories', 'owner_id'), targetOptions('owner_territories', 'owner_id')),
          task_ids: Object.fromEntries(sourceTasks.map(id => [id, taskPrefix + id])),
          role_ids: Object.fromEntries(sourceIds('roles', 'role_id').map(id => [id, rolePrefix + id])),
          preset_ids: Object.fromEntries([...new Set(list(blueprint.roles).map(row => row.preset_id).filter(Boolean))].map(id => [id, targetPresetIds.includes(id) ? id : ''])),
          path_rules: [{ source_prefix: sourcePrefix, target_prefix: targetPrefix }],
          executor_profile_ids: { default: executorId }, resource_profile_ids: { default: resourceId }, model_route_ids: { default: routeId } };
        setMappingText(JSON.stringify(mapping, null, 2)); setMappingOpen(true); setError(null); setPreview(null); setImported(null);
      }
      function mappingIssues() {
        if (!blueprint || !mappingText) return [];
        let mapping;
        try { mapping = JSON.parse(mappingText); }
        catch { return [{ field: 'mapping', subject: '', reason: 'invalidMappingJson' }]; }
        const groups = {
          requirement_ids: sourceIds('requirements', 'requirement_id'), team_ids: sourceIds('teams', 'team_id'),
          owner_ids: sourceIds('owner_territories', 'owner_id'), task_ids: sourceIds('cards', 'task_id'), role_ids: sourceIds('roles', 'role_id'),
          preset_ids: [...new Set(list(blueprint.roles).map(row => row.preset_id).filter(Boolean))],
          executor_profile_ids: [...new Set(list(blueprint.cards).map(row => row.execution_profile_ref).filter(Boolean))],
          resource_profile_ids: [...new Set(list(blueprint.cards).map(row => row.resource_profile_ref).filter(Boolean))],
          model_route_ids: [...new Set(list(blueprint.cards).map(row => row.model_route_ref).filter(Boolean))],
        };
        const issues = [];
        for (const [group, declared] of Object.entries(groups)) {
          const values = record(mapping[group]);
          for (const id of declared) {
            if (!Object.hasOwn(values, id)) issues.push({ field: 'mapping.' + group, subject: id, reason: 'missingSourceKey' });
            else if (typeof values[id] !== 'string' || !values[id] || /\s/.test(values[id])) issues.push({ field: 'mapping.' + group, subject: id, reason: 'missingTarget' });
          }
          for (const id of Object.keys(values)) if (!declared.includes(id)) issues.push({ field: 'mapping.' + group, subject: id, reason: 'extraSourceKey' });
        }
        return issues;
      }
      const incompleteMappings = mappingIssues();
      function expectedAuthority(mapping) {
        return { ...record(target.expected_authority), catalog_revision: list(target.catalogs).find(row => row.catalog_id === mapping.target_catalog_id)?.revision ?? null };
      }
      function identify(body, operation) {
        const fingerprint = JSON.stringify(body, (_key, value) => {
          if (value === null || typeof value !== 'object' || Array.isArray(value)) return value;
          return Object.fromEntries(Object.keys(value).sort().map(key => [key, value[key]]));
        });
        const prior = pending.current.get(operation);
        if (prior?.fingerprint !== fingerprint) pending.current.set(operation, { fingerprint, request_id: crypto.randomUUID() });
        return { ...body, request_id: pending.current.get(operation).request_id };
      }
      function mutationFailure(failure, requestId) {
        failure.request_id ??= requestId;
        if ((!failure.code || failure.code === 'INVALID_RESPONSE') && failure.name !== 'AbortError') {
          failure.outcome = 'UNKNOWN_COMMIT_OR_PENDING';
          failure.retry_same_request_id = true;
        }
        return failure;
      }
      function formFingerprint(form) {
        try { return JSON.stringify([form.targetId, form.blueprint, JSON.parse(form.mappingText), record(form.context).expected_authority]); }
        catch { return null; }
      }
      async function runPreview() {
        if (!blueprint || !context || busy) return;
        if (incompleteMappings.length) { setMappingOpen(true); setError(new Error(t('mappingIssueCount', { count: incompleteMappings.length }))); return; }
        setBusy('preview'); setError(null); setPreview(null); setImported(null);
        try {
          const mapping = JSON.parse(mappingText);
          const body = { target_project_id: targetId, blueprint, mapping, expected_authority: expectedAuthority(mapping) };
          const fingerprint = JSON.stringify([targetId, blueprint, mapping, target.expected_authority]);
          const identified = identify(body, 'preview');
          let value;
          try { value = await request('/api/forgeflow-panel/blueprint-preview', identified, lifetime.current.signal); }
          catch (failure) { throw mutationFailure(failure, identified.request_id); }
          if (formFingerprint(currentForm.current) !== fingerprint) throw new Error(t('previewChanged'));
          previewFingerprint.current = fingerprint;
          setPreview(record(value));
        } catch (value) { setError(value); }
        finally { setBusy(''); }
      }
      async function importReview() {
        if (!preview?.can_import || busy || !context || !blueprint) return;
        setBusy('import'); setError(null);
        try {
          const mapping = JSON.parse(mappingText);
          if (previewFingerprint.current !== JSON.stringify([targetId, blueprint, mapping, target.expected_authority])) throw new Error(t('previewChanged'));
          const body = { target_project_id: targetId, preview_id: preview.preview_id, expected_revision: preview.revision, review_sha256: preview.review_sha256 };
          const identified = identify(body, 'import');
          let value;
          try { value = await request('/api/forgeflow-panel/blueprint-import', identified, lifetime.current.signal); }
          catch (failure) { throw mutationFailure(failure, identified.request_id); }
          if (selectedTarget.current === targetId) setImported(record(value)); setPreview(null);
        } catch (value) { setError(value); }
        finally { setBusy(''); }
      }
      const sections = [];
      sections.push(h('section', { className: 'ffp-card', key: 'upload' }, h('h2', null, t('reuse')), h('p', { className: 'ffp-note' }, t('planningOnly')),
        h('div', { className: 'ffp-toolbar' }, h('label', null, h('span', { className: 'ffp-note' }, t('uploadBlueprint')),
          h('input', { type: 'file', accept: '.json,application/json', disabled: !!busy, onChange: upload, 'aria-label': t('uploadBlueprint') }))),
        fileName && h('p', { className: 'ffp-note' }, t('selectedFile') + ' · ' + fileName),
        h('div', { className: 'ffp-import-grid' }, field('targetProject', targetId, value => { setTargetId(value); setContext(null); setPreview(null); setImported(null); }),
          h(MappingChoice, { value: targetId, options: projects.map(row => ({ id: row.project_id, label: row.name ?? row.project_id, disabled: !!busy })), label: t('chooseProject'),
            onChange: value => { setTargetId(value); setContext(null); setPreview(null); setImported(null); } }),
          h(Button, { size: 'sm', disabled: !targetId || !!busy, onClick: loadContext }, busy === 'context' ? t('refreshing') : t('loadContext')))));
      if (error) sections.push(h(ErrorBox, { key: 'error', value: error, t }));
      if (context) sections.push(h('section', { className: 'ffp-card', key: 'mapping' }, h('h2', null, target.project?.name ?? targetId),
        target.project?.paused === true && h('p', { className: 'ffp-note' }, t('targetSafetyPaused')),
        h('div', { className: 'ffp-import-grid' }, field('targetCatalog', catalogId, value => { setCatalogId(value); setPreview(null); }),
          field('taskPrefix', taskPrefix, setTaskPrefix), field('rolePrefix', rolePrefix, setRolePrefix),
          field('sourcePath', sourcePrefix, setSourcePrefix), field('targetPath', targetPrefix, setTargetPrefix),
          h(MappingChoice, { value: executorId, onChange: value => { setExecutorId(value); if (mappingText) updateMapping('executor_profile_ids', 'default', value); }, options: targetOptions('executor_profiles', 'id').map(row => ({ ...row, disabled: !!busy })), label: t('executorMapping') }),
          h(MappingChoice, { value: resourceId, onChange: value => { setResourceId(value); if (mappingText) updateMapping('resource_profile_ids', 'default', value); }, options: targetOptions('resource_profiles', 'id').map(row => ({ ...row, disabled: !!busy })), label: t('resourceMapping') }),
          h(MappingChoice, { value: routeId, onChange: value => { setRouteId(value); if (mappingText) updateMapping('model_route_ids', 'default', value); }, options: targetOptions('model_routes', 'id').map(row => ({ ...row, disabled: !!busy })), label: t('modelMapping') })),
        h('div', { className: 'ffp-toolbar' }, h(Button, { size: 'sm', onClick: draftMapping, disabled: !blueprint || !!busy }, t('mappingDraft'))),
        incompleteMappings.length > 0 && h('section', { className: 'ffp-error', role: 'status' }, h('h3', null, t('unmappedFields')),
          h('p', null, t('mappingIssueCount', { count: incompleteMappings.length })), h('ul', { className: 'ffp-paths' }, incompleteMappings.map((issue, index) =>
            h('li', { key: index }, h('code', null, issue.field + (issue.subject ? '[' + issue.subject + ']' : '')), ' · ' + t(issue.reason))))),
        ...[['requirement_ids', 'requirements', 'requirement_id', 'requirementMapping'], ['team_ids', 'teams', 'team_id', 'teamMapping'],
          ['owner_ids', 'owner_territories', 'owner_id', 'ownerMapping']].map(([group, source, key, label]) => h('details', { key: group }, h('summary', null, t(label)),
            h('div', { className: 'ffp-import-grid' }, ...sourceIds(source, key).map(id => h('label', { className: 'ffp-import-field', key: id }, h('code', null, id),
              h(MappingChoice, { value: mapped(group, id), onChange: value => updateMapping(group, id, value), options: targetOptions(source, key), label: t(label) })))))),
        h('details', null, h('summary', null, t('presetMapping')), h('p', { className: 'ffp-note' }, t('presetMappingNote')),
          h('p', { className: 'ffp-note' }, targetPresetIds.length ? t('targetPresetChoices') + ' · ' + targetPresetIds.length : t('targetPresetUnavailable')),
          h('div', { className: 'ffp-import-grid' }, ...[...new Set(list(record(blueprint).roles).map(row => row.preset_id).filter(Boolean))].map(id =>
            h('label', { className: 'ffp-import-field', key: id }, h('code', null, id), h(Input, { value: mapped('preset_ids', id),
              onChange: event => updateMapping('preset_ids', id, event.target.value), disabled: !!busy, 'aria-label': t('presetMapping') + ' · ' + id }),
              h(MappingChoice, { value: mapped('preset_ids', id), onChange: value => updateMapping('preset_ids', id, value),
                options: targetPresetIds.map(value => ({ id: value, label: value, disabled: !!busy })), label: t('targetPresetChoices') }))))),
        h('details', { open: mappingOpen, onToggle: event => setMappingOpen(event.currentTarget.open) }, h('summary', null, t('advancedMapping')), h('textarea', { className: 'ffp-json-editor', rows: 18, value: mappingText,
          onChange: event => { setMappingText(event.target.value); setPreview(null); setImported(null); }, 'aria-label': t('advancedMapping'), disabled: !!busy })),
        h('div', { className: 'ffp-toolbar' }, h(Button, { variant: 'outline', disabled: !blueprint || !mappingText || incompleteMappings.length > 0 || !!busy, onClick: runPreview },
          busy === 'preview' ? t('actionPending') : t('previewImport')))));
      if (preview) sections.push(h('section', { className: 'ffp-card', key: 'preview' }, h('h2', null, t('importCounts')),
        h('div', { className: 'ffp-meta' }, ...Object.entries(record(preview.counts)).map(([key, value]) => h('span', { key }, key + ' · ' + count(number(value))))),
        h('h3', null, t('importFindings')), h('ul', null, list(preview.blocking_findings).map((row, index) => h('li', { key: index }, row.code + ' · ' + display(row.subject, t) + ' · ' + display(row.detail, t)))),
        h('h3', null, t('importWarnings')), h('ul', null, strings(preview.warnings).map((row, index) => h('li', { key: index }, row))),
        h('p', { className: 'ffp-note' }, t('planningOnly')), h('details', null, h('summary', null, t('sourceDetails')), h('pre', null, JSON.stringify({
          preview_id: preview.preview_id, review_sha256: preview.review_sha256, blueprint_sha256: preview.blueprint_sha256,
          target_authority_sha256: preview.target_authority_sha256, revision: preview.revision }, null, 2))),
        h(Button, { variant: 'primary', disabled: preview.can_import !== true || !!busy, onClick: importReview }, busy === 'import' ? t('actionPending') : t('importReviewed'))));
      if (imported) sections.push(h('section', { className: 'ffp-card', role: 'status', key: 'imported' }, h('h2', null, t('importResult')),
        h('dl', null, ...['catalog_id', 'catalog_revision', 'card_count', 'role_count', 'state'].flatMap(key => [h('dt', { key: key + '-name' }, key), h('dd', { key: key + '-value' }, display(imported[key], t))])),
        h('p', { className: 'ffp-note' }, t('planningOnly'))));
      return h(React.Fragment, null, ...sections);
    }
    function CardDetails({ card, t, onClose }) {
      if (!card) return null;
      const spec = record(card.spec);
      return h('aside', { className: 'ffp-card ffp-details' }, h('div', { className: 'ffp-heading' }, h('h2', null, card.title ?? taskId(card)),
        h(Button, { size: 'sm', onClick: onClose }, t('close'))), h('code', null, taskId(card)),
        h('dl', null, h('dt', null, t('owner')), h('dd', null, `${display(card.owner_id, t)} / ${display(card.team_id, t)}`),
          h('dt', null, t('state')), h('dd', null, display(card.state, t)), h('dt', null, t('preset')), h('dd', null, display(card.role_id, t)),
          h('dt', null, t('executor')), h('dd', null, display(spec.execution_profile, t))),
        h('h3', null, t('blockers')), h('ul', { className: 'ffp-paths' }, reasons(card).map(reason => h('li', { key: reason }, reason))),
        h(Paths, { name: 'requirements', value: card.requirement_ids, t }), h(Paths, { name: 'readSet', value: card.read_set, t }),
        h(Paths, { name: 'writeSet', value: card.write_set, t }), h(Paths, { name: 'dependencies', value: card.dependencies ?? card.predecessor_cards, t }),
        h('details', null, h('summary', null, t('inputs')), h('pre', null, JSON.stringify({ inputs: spec.inputs,
          produces: spec.produces, consumes: spec.consumes, verification_plan: spec.verification_plan,
          definition_of_done: record(record(card.metadata).source_card).definition_of_done,
          unbound_input_paths: card.unbound_input_paths }, null, 2))));
    }
    function Dag({ cards, selectedId, onSelect, t }) {
      const byId = useMemo(() => new Map(cards.map(card => [taskId(card), card])), [cards]);
      const selected = byId.get(selectedId) ?? cards[0];
      if (!selected) return h('p', { className: 'ffp-empty' }, t('emptyCatalog'));
      const before = strings(selected.dependencies ?? selected.predecessor_cards);
      const after = cards.filter(card => strings(card.dependencies ?? card.predecessor_cards).includes(taskId(selected))).map(taskId);
      const edges = cards.reduce((sum, card) => sum + strings(card.dependencies ?? card.predecessor_cards).length, 0);
      const left = before.slice(0, 16); const right = after.slice(0, 16);
      const height = Math.max(220, Math.max(left.length, right.length) * 68 + 24); const center = height / 2;
      const node = (key, x, y, selectedNode) => {
        const card = byId.get(key); const label = card?.title ?? key; const select = () => onSelect(key);
        return h('g', { key: `${key}:${x}`, className: selectedNode ? 'ffp-dag-selected' : undefined, role: 'button', tabIndex: 0,
          'aria-label': `${t('details')}: ${label}`, onClick: select, onKeyDown: event => {
            if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); select(); }
          } }, h('title', null, `${label}\n${key}`), h('rect', { x, y: y - 25, width: 242, height: 52, rx: 12 }),
          h('text', { x: x + 12, y: y - 5 }, String(label).slice(0, 23)), h('text', { x: x + 12, y: y + 13, className: 'ffp-dag-id' }, String(key).slice(0, 43)));
      };
      return h(React.Fragment, null, h('p', { className: 'ffp-note' }, t('dagNote', { cards: count(cards.length), edges: count(edges) })),
        h('div', { className: 'ffp-meta' }, h('span', null, `${t('predecessor')} · ${t('dagMore', { shown: left.length, total: before.length })}`),
          h('span', null, `${t('successor')} · ${t('dagMore', { shown: right.length, total: after.length })}`)),
        h('div', { className: 'ffp-dag' }, h('svg', { viewBox: `0 0 940 ${height}`, height, 'aria-label': t('dag') },
          ...left.map((key, index) => h('path', { key: `in:${key}`, d: `M254 ${index * 68 + 42} C312 ${index * 68 + 42}, 312 ${center}, 350 ${center}` })),
          ...right.map((key, index) => h('path', { key: `out:${key}`, d: `M592 ${center} C642 ${center}, 642 ${index * 68 + 42}, 686 ${index * 68 + 42}` })),
          ...left.map((key, index) => node(key, 12, index * 68 + 42, false)), node(taskId(selected), 350, center, true),
          ...right.map((key, index) => node(key, 686, index * 68 + 42, false)),
          !left.length && h('text', { x: 40, y: center }, t('noPredecessor')), !right.length && h('text', { x: 700, y: center }, t('noSuccessor')))));
    }
    function NativeWorkflow({ observations, t }) {
      const runs = useMemo(() => {
        const result = new Map();
        for (const row of observations) {
          const value = row.value; const event = row.event;
          if (!String(event).startsWith('tool-workflow/') || !value.runId) continue;
          const key = `${value.native_session_id}:${value.runId}`;
          const run = result.get(key) ?? { runId: value.runId, sessionId: value.native_session_id, members: new Map(), started: false };
          if (event === 'tool-workflow/run-start') { run.started = true; run.name = value.name; }
          if (event === 'tool-workflow/agent-start') run.members.set(value.memberSeq, { ...run.members.get(value.memberSeq), ...value });
          if (event === 'tool-workflow/agent-end') run.members.set(value.memberSeq, { ...run.members.get(value.memberSeq), ...value });
          if (event === 'tool-workflow/run-end') run.stopReason = value.stopReason;
          result.set(key, run);
        }
        return [...result.values()];
      }, [observations]);
      return h('section', { className: 'ffp-card' }, h('h2', null, t('workflow')), h('p', { className: 'ffp-note' }, t('workflowNote')),
        !runs.length ? h('p', { className: 'ffp-empty' }, t('noWorkflow')) : runs.map(run => h('article', { className: 'ffp-context', key: `${run.sessionId}:${run.runId}` },
          h('div', { className: 'ffp-heading' }, h('h3', null, run.name ?? run.runId), h(Tag, null, display(run.stopReason, t))),
          h('p', { className: 'ffp-caption' }, `${run.sessionId} · ${run.runId}`), !run.started && h('p', { className: 'ffp-note' }, t('workflowMissing')),
          h('div', { className: 'ffp-table-wrap' }, h('table', null, h('thead', null, h('tr', null,
            ...['member', 'phase', 'session', 'outcome'].map(key => h('th', { key }, t(key))))), h('tbody', null, [...run.members].map(([seq, member]) => h('tr', { key: seq },
              h('td', null, member.label ?? seq), h('td', null, display(member.phase, t)), h('td', null, h('code', null, display(member.childId, t))), h('td', null, display(member.outcome, t))))))))));
    }
    function HostContexts({ sessions, statuses, openSession, refreshNative, t }) {
      const [error, setError] = useState(null);
      const navigate = id => { try { openSession(id); setError(null); } catch (value) { setError(value); } };
      const refresh = () => { refreshNative().then(() => setError(null), setError); };
      const teams = Object.entries(record(sessions.projectionsBySession)).flatMap(([lead, projection]) => {
        const team = record(record(projection.values).agentTeam);
        return Array.isArray(team.members) ? [{ lead, team, state: projection.state, error: projection.error }] : [];
      });
      return h('section', { className: 'ffp-card' }, h('div', { className: 'ffp-heading' }, h('h2', null, t('hostContexts')),
        h(Button, { size: 'sm', icon: h(IconRefreshOutlineRegular, { size: 14 }), onClick: refresh }, t('refresh'))),
        error && h(ErrorBox, { value: error, t }),
        sessions.phase !== 'ready' ? h('p', { className: 'ffp-note' }, t('sessionLoading')) : !(sessions.ids ?? []).length
          ? h('p', { className: 'ffp-empty' }, t('noSession')) : h('div', { className: 'ffp-roles' }, sessions.ids.map(key => {
            const session = record(sessions.byId[key]); const status = statuses.get(key);
            const model = record(record(record(sessions.projectionsBySession[key]).values).modelSelection).lastUsed;
            return h('article', { className: 'ffp-role', key }, h('div', { className: 'ffp-heading' }, h('h3', null, session.displayTitle ?? key),
              h(Tag, null, status?.running === true ? 'running' : status?.running === false ? 'idle' : t('unknown'))),
              h('code', null, key), h('dl', null, h('dt', null, t('parent')), h('dd', null, session.parentId ?? t('root')),
                h('dt', null, t('model')), h('dd', null, model ? `${model.provider} / ${model.model}` : t('unknown'))),
              h(Button, { size: 'sm', onClick: () => navigate(key) }, t('openSession')));
          })), teams.map(({ lead, team, error }) => h('article', { className: 'ffp-context', key: lead }, h('h3', null, `${t('agents')} · ${lead}`),
            (error || team.failure) && h(ErrorBox, { value: error ?? { message: team.failure }, t }),
            h('div', { className: 'ffp-roles' }, list(team.members).map(member => {
              const running = statuses.get(member.id)?.running;
              return h('div', { className: 'ffp-role', key: member.id }, h('h3', null, member.name), h('code', null, member.id),
                h('p', { className: 'ffp-note' }, `${member.role} · ${member.phase} · ${running === true ? 'running' : running === false ? 'idle' : t('unknown')}`),
                h(Button, { size: 'sm', onClick: () => navigate(member.id) }, t('openSession')));
            })), h('h3', null, t('teamTasks')), h('ul', null, list(team.tasks).map(task => h('li', { key: task.id }, `${task.id} · ${task.subject} · ${task.status}`))),
            h('p', { className: 'ffp-note' }, t('teamNote')))));
    }
    function NativeContexts({ snapshot, observations, roles, t }) {
      const lifecycles = list(snapshot.native_child_lifecycles);
      const roleMap = new Map(roles.map(role => [role.agent_id ?? role.role_id ?? role.id, role]));
      const latest = new Map();
      const teams = new Map();
      for (const row of observations) {
        if (row.event === 'agent/status') latest.set(row.value.native_session_id, row.value.status);
        if ((row.event === 'team/member' || row.event === 'team/task') && row.value.teamId) {
          const team = teams.get(row.value.teamId) ?? { members: new Map(), tasks: new Map() };
          if (row.event === 'team/member' && row.value.member?.id) team.members.set(row.value.member.id, row.value.member);
          if (row.event === 'team/task' && row.value.task?.id) team.tasks.set(row.value.task.id, row.value.task);
          teams.set(row.value.teamId, team);
        }
      }
      return h(React.Fragment, null, h('section', { className: 'ffp-card' }, h('h2', null, t('workerContexts')),
        !Array.isArray(snapshot.native_child_lifecycles) ? h('p', { className: 'ffp-empty' }, t('waiting')) : !lifecycles.length
          ? h('p', { className: 'ffp-empty' }, t('noNative')) : h('div', { className: 'ffp-table-wrap' }, h('table', null,
            h('thead', null, h('tr', null, ...['session', 'position', 'state', 'parent', 'depth', 'model'].map(key => h('th', { key }, t(key))))),
            h('tbody', null, lifecycles.map(row => {
              const binding = record(record(row.admission).agent_options); const role = roleMap.get(binding.position_id);
              return h('tr', { key: row.allocation_id }, h('td', null, h('code', null, row.native_session_id), h('small', null, row.allocation_id)),
                h('td', null, role?.position ?? binding.position_id ?? t('unknown'), h('small', null, binding.preset_id ?? t('noPreset'))),
                h('td', null, display(row.state, t), h('small', null, display(latest.get(row.native_session_id), t))),
                h('td', null, h('code', null, row.parent_session_id ?? t('root'))), h('td', null, count(row.delegation_depth)),
                h('td', null, `${display(row.provider, t)} / ${display(row.model, t)}`));
            }))))), h('section', { className: 'ffp-card' }, h('h2', null, t('observedTeams')),
        !teams.size ? h('p', { className: 'ffp-empty' }, t('noTeam')) : [...teams].map(([teamId, team]) => h('article', { key: teamId, className: 'ffp-context' },
          h('h3', null, teamId), h('div', { className: 'ffp-roles' }, [...team.members].map(([key, member]) => h('div', { key, className: 'ffp-role' },
            h('h3', null, member.name ?? key), h('code', null, key), h('p', { className: 'ffp-note' }, `${display(member.phase, t)} · ${display(member.position_id, t)}`),
            h('small', null, display(member.preset_id, t))))), h('ul', null, [...team.tasks].map(([key, task]) => h('li', { key }, `${key} · ${task.status}`))))),
        h('p', { className: 'ffp-note' }, t('teamNote'))));
    }
    function Panel({ t, useSessions, useSessionStatus, openSession, refreshNative }) {
      const sessions = useSessions(state => state);
      const statuses = useSessionStatus(state => state);
      const [projectId, setProjectId] = useState('');
      const [view, setView] = useState('overview');
      const [data, setData] = useState(null);
      const [error, setError] = useState(null);
      const [loading, setLoading] = useState(false);
      const [revision, bump] = useState(0);
      const [auto, setAuto] = useState(true);
      const [projectMenu, setProjectMenu] = useState(false);
      const [ownerMenu, setOwnerMenu] = useState(false);
      const [search, setSearch] = useState('');
      const [owner, setOwner] = useState('');
      const [page, setPage] = useState(0);
      const [selectedId, setSelectedId] = useState('');
      const [attemptId, setAttemptId] = useState('');
      const [attemptMenu, setAttemptMenu] = useState(false);
      const [reason, setReason] = useState('');
      const [pendingAction, setPendingAction] = useState('');
      const [receipt, setReceipt] = useState(null);
      const [actionError, setActionError] = useState(null);
      const commandIdentity = useRef(null);
      const actionController = useRef(null);
      const readController = useRef(null);
      const lastSuccessfulState = useRef(null);
      const selectedProject = useRef(projectId);
      selectedProject.current = projectId;
      useEffect(() => {
        const controller = new AbortController(); readController.current = controller; setLoading(true); setError(null);
        const params = new URLSearchParams({ view });
        if (projectId) params.set('project_id', projectId);
        if (selectedId) params.set('task_id', selectedId);
        const previous = lastSuccessfulState.current;
        if (previous?.catalog_revision && previous.catalog_cards_loaded === true &&
            (!projectId || previous.selected_project_id === projectId)) params.set('catalog_revision', previous.catalog_revision);
        request(`/api/forgeflow-panel/state?${params}`, undefined, controller.signal).then(value => {
          if (controller.signal.aborted) return;
          const incoming = record(value);
          if (incoming.catalog_unchanged === true) {
            if (!previous || incoming.selected_project_id !== previous.selected_project_id
              || incoming.catalog_revision !== previous.catalog_revision || !Array.isArray(previous.planning_cards)) {
              throw Object.assign(new Error('An unchanged catalog has no matching project snapshot'), { code: 'CATALOG_CACHE_MISSING' });
            }
            incoming.planning_cards = previous.planning_cards;
          }
          lastSuccessfulState.current = incoming; setData(incoming);
        }).catch(value => { if (!controller.signal.aborted) setError(value); })
          .finally(() => { if (readController.current === controller) { readController.current = null; if (!controller.signal.aborted) setLoading(false); } });
        return () => controller.abort();
      }, [projectId, view, revision, selectedId]);
      useEffect(() => () => actionController.current?.abort(), []);
      const current = projectId && record(record(data).project).project_id !== projectId ? {} : record(data);
      const sectionErrors = new Set(list(current.errors).map(row => row.source));
      const cardsAvailable = current.catalog_cards_loaded === true && Array.isArray(current.planning_cards) && !sectionErrors.has('planning_cards');
      const rolesAvailable = !sectionErrors.has('role_catalog') && (current.roster || record(current.catalog).roster);
      const project = record(current.project); const currentProjectId = project.project_id;
      const snapshot = record(current.snapshot); const flow = record(current.flow);
      const delivery = unwrap(current.delivery); const catalog = unwrap(current.catalog); const audit = unwrap(current.capabilities);
      const registeredCardCount = number(catalog.card_count);
      const roles = list(record(current.roster).roles ?? current.roster);
      const cards = useMemo(() => list(current.planning_cards).map(row => ({
        ...record(record(row.metadata).source_card), ...record(row.metadata), ...record(row.task),
        task_id: row.task_id ?? record(row.task).task_id, metadata: row.metadata, spec: row.spec,
        admission_blockers: row.admission_blockers ?? record(row.metadata).admission_blockers,
        unbound_input_paths: row.unbound_input_paths,
      })), [current.planning_cards]);
      const cardMap = useMemo(() => new Map(cards.map(card => [taskId(card), card])), [cards]);
      const catalogIdsAvailable = Array.isArray(current.catalog_task_ids);
      const catalogIds = new Set(catalogIdsAvailable ? current.catalog_task_ids : cards.map(taskId));
      const observed = useMemo(() => list(current.observations).map(observation), [current.observations]);
      const attempts = list(snapshot.attempts); const running = attempts.filter(row => row.state === 'RUNNING');
      const attemptMap = new Map(attempts.map(row => [row.attempt_id, row]));
      const profiles = new Map(list(snapshot.attempt_native_profiles).map(row => [row.attempt_id, row]));
      const taskMap = new Map(list(snapshot.tasks).map(row => [row.task_id, row]));
      const lifecycles = list(snapshot.native_child_lifecycles);
      const nativeHeld = lifecycles.filter(row => row.state === 'HELD' && row.revoked !== true &&
        row.disposed_at == null && row.process_stopped_at == null &&
        attemptMap.get(row.attempt_id)?.state === 'RUNNING' &&
        attemptMap.get(row.attempt_id)?.generation === row.generation &&
        profiles.get(row.attempt_id)?.executor_kind === 'DSH_MANAGED');
      const modelRequests = list(snapshot.native_model_requests);
      const activeModels = modelRequests.filter(row => row.status === 'ADMITTED').length;
      const unknownModels = modelRequests.filter(row => row.status === 'QUARANTINED').length;
      const flowCards = flow.state === 'COMMITTED' ? list(flow.tasks).filter(row => catalogIds.has(taskId(row))) : [];
      const accepted = new Set(attempts.filter(row => row.state === 'SUCCEEDED' && catalogIds.has(row.task_id) &&
        taskMap.get(row.task_id)?.task_revision === row.task_revision &&
        ['FINALIZED', 'COMMITTED'].includes(record(row.result).state) &&
        record(record(row.result).receipt).ref_updated === true).map(row => row.task_id));
      for (const lineage of list(current.retained_native_candidate_acceptances)) {
        const source = record(lineage.source); const task = taskMap.get(source.task_id);
        if (lineage.accepted === true && catalogIds.has(source.task_id) && task &&
            task.task_revision === source.task_revision && task.input_digest === source.input_digest) accepted.add(source.task_id);
      }
      const activeAttempt = attempts.find(row => row.attempt_id === attemptId) ?? running[0] ?? attempts[attempts.length - 1];
      const retryAllowed = activeAttempt && ['FAILED', 'CANCELLED'].includes(activeAttempt.state);
      const cancelAllowed = activeAttempt && ['LEASED', 'STARTING', 'RUNNING', 'VERIFYING', 'REVIEW_READY', 'MERGE_QUEUED', 'MERGING', 'STOPPING', 'RECOVERY_REQUIRED'].includes(activeAttempt.state);
      const attemptLabel = row => `${row.task_id} · ${String(row.attempt_id).slice(0, 8)} · ${row.state}`;
      const selectedCard = cardMap.get(selectedId);
      const selectedDetail = record(current.selected_card);
      const displayedCard = selectedCard && selectedDetail.task_id === selectedId ? {
        ...selectedCard, ...record(record(selectedDetail.metadata).source_card), ...record(selectedDetail.metadata), ...record(selectedDetail.task),
        spec: selectedDetail.spec ?? selectedCard.spec, metadata: selectedDetail.metadata ?? selectedCard.metadata,
      } : selectedCard;
      const filtered = useMemo(() => cards.filter(card => (!owner || card.owner_id === owner)
        && (!search || [taskId(card), card.title, card.role_id, card.business_outcome, card.parent_task]
          .some(value => String(value ?? '').toLocaleLowerCase().includes(search.trim().toLocaleLowerCase())))), [cards, owner, search]);
      const pages = Math.max(1, Math.ceil(filtered.length / 40)); const currentPage = Math.min(page, pages - 1);
      const refreshInterval = number(current.refresh_interval_ms);
      const sourceReady = !!current.snapshot && !!current.delivery && !sectionErrors.has('snapshot') && !sectionErrors.has('delivery');
      const writable = currentProjectId && project.authority_mode === 'MANAGED' && project.archived !== true && sourceReady;
      const schedulingPaused = (record(current.scheduling).paused ?? record(delivery.scheduling).paused) === true;
      const canonicalBindings = new Map(list(current.canonical_task_bindings ?? snapshot.tasks).map(row => [row.task_id, row]));
      const actionReceipts = list(current.action_receipts);
      const currentReceipt = receipt ? actionReceipts.find(row => row.action_id === receipt.action_id) ?? receipt : null;
      const activeAction = key => actionReceipts.find(row => row.action === key && ['ACCEPTED', 'RUNNING'].includes(row.status));
      const nativePresetsAvailable = Array.isArray(current.agent_presets) && !sectionErrors.has('agent_presets');
      const nativePresets = list(current.agent_presets);
      const nativeInventory = record(current.native_plugin_inventory);
      const presetCompositions = new Map(list(nativeInventory.agentPresets).map(row => [row.id, row]));
      const planningBlockers = useMemo(() => {
        const counts = new Map(Object.entries(record(catalog.blocker_counts)).filter(([, value]) => number(value) !== undefined && value > 0));
        if (!counts.size) for (const card of cards) for (const reason of reasons(card)) counts.set(reason, (counts.get(reason) ?? 0) + 1);
        return [...counts].sort((a, b) => b[1] - a[1]);
      }, [catalog.blocker_counts, cards]);
      const blockedCardCount = cards.filter(card => reasons(card).length > 0).length;
      const executionBlockers = [...new Set([
        ...reasons(delivery), ...reasons(record(delivery.report)), ...reasons(record(delivery.dispatch_report)),
        ...Object.entries(record(delivery.blocker_counts)).filter(([, value]) => number(value) !== undefined && value > 0).map(([reason, value]) => `${reason} · ${value}`),
        ...Object.entries(record(record(delivery.report).blocker_counts)).filter(([, value]) => number(value) !== undefined && value > 0).map(([reason, value]) => `${reason} · ${value}`),
        ...Object.values(record(delivery.blocked)).flatMap(value => strings(value)),
        ...Object.values(record(record(delivery.dispatch_report).blocked)).flatMap(value => strings(value)),
      ])];
      useEffect(() => { setPage(0); }, [owner, search, projectId]);
      useEffect(() => {
        if (!auto || refreshInterval === undefined || refreshInterval <= 0) return;
        const timer = setInterval(() => { if (document.visibilityState === 'visible' && !readController.current) bump(value => value + 1); }, refreshInterval);
        return () => clearInterval(timer);
      }, [auto, refreshInterval]);
      async function command(action) {
        if (!writable || pendingAction) return;
        if (action === 'RETRY' && !retryAllowed || action === 'CANCEL' && !cancelAllowed) return;
        const body = { project_id: currentProjectId, action,
          ...((action === 'RETRY' || action === 'CANCEL') && activeAttempt ? { attempt_id: activeAttempt.attempt_id } : {}),
          ...(reason.trim() && action === 'REPLAN' ? { reason: reason.trim() } : {}) };
        const fingerprint = JSON.stringify(body);
        if (commandIdentity.current?.fingerprint !== fingerprint) commandIdentity.current = { fingerprint, request_id: crypto.randomUUID() };
        body.request_id = commandIdentity.current.request_id;
        const controller = new AbortController(); actionController.current = controller;
        setPendingAction(action); setActionError(null); setReceipt(null);
        try {
          const value = await request('/api/forgeflow-panel/command', body, controller.signal);
          if (!controller.signal.aborted) {
            if (!selectedProject.current || selectedProject.current === body.project_id) setReceipt(record(value));
            commandIdentity.current = null; bump(value => value + 1);
          }
        } catch (value) { if (!controller.signal.aborted) setActionError(value); }
        finally { if (!controller.signal.aborted) setPendingAction(''); }
      }
      const action = (key, label, icon, disabled) => {
        const active = activeAction(key);
        const resuming = key === 'START' && schedulingPaused;
        const reviewAction = key === 'START' && retainedReviewEnabled;
        return h(Button, {
          variant: key === 'START' ? 'primary' : 'outline', size: 'sm', icon,
          disabled: !writable || !!pendingAction || disabled === true || key === 'START' && project.paused === true || !!active && !resuming,
          title: key === 'START' && project.paused === true ? t('projectSafetyPaused') : !sourceReady ? t('sourceNotReady') : undefined,
          'aria-busy': pendingAction === key || !!active,
          onClick: () => command(key),
        }, pendingAction === key ? t('actionPending') : active && !resuming ? t(reviewAction ? 'reviewActionRunning' : key === 'START' ? 'developmentRunning' : 'actionExecuting')
          : resuming ? t(reviewAction ? 'resumeReview' : 'resumeDevelopment') : t(reviewAction ? 'startReview' : label));
      };
      const menu = (open, setOpen, items, selected, label, select) => h(Menu, {
        open, anchor: h(Button, { variant: 'outline', size: 'sm', onClick: () => setOpen(value => !value), 'aria-expanded': open }, label),
        items, selectedId: selected, onSelect: value => { select(value); setOpen(false); }, onClose: () => setOpen(false), portal: true,
      });
      const views = ['overview', 'catalog', 'dag', 'agents', 'workflow', 'presets', 'configuration', 'reuse'];
      const days = number(record(catalog.delivery_target).days ?? record(record(catalog.alignment).delivery_target).days
        ?? record(record(catalog.alignment).delivery_target).deadline_days ?? catalog.deadline_days
        ?? record(record(catalog.metadata).delivery_target).all_cards_days ?? record(record(catalog.metadata).delivery_target).days
        ?? record(catalog.metadata).delivery_days ?? record(catalog.metadata).deadline_days
        ?? record(delivery.acceptance).days ?? record(delivery.deadline).days ?? record(record(current.configuration).target).days);
      const rawRoles = roles.length ? roles : list(catalog.roster ?? catalog.roles);
      const configuration = record(current.configuration);
      const verificationRecovery = record(configuration.verification_recovery);
      const retainedCandidateReview = record(configuration.retained_candidate_review);
      const retainedReviewEnabled = retainedCandidateReview.enabled === true && retainedCandidateReview.mode === 'RETAINED_NATIVE_CANDIDATE_REVIEW';
      const modelConfiguration = record(configuration.model_configuration ?? current.model_configuration);
      const modelPolicy = record(configuration.model_policy);
      const executionPolicy = record(configuration.execution_policy ?? current.execution_policy);
      const desiredActive = number(executionPolicy.desired_active_agents ?? configuration.desired_active_agents ?? delivery.desired_active_agents
        ?? delivery.minimum_concurrency_target ?? record(configuration.target).minimum_real_concurrent_agents);
      const activeCeiling = executionPolicy.max_active_agents ?? configuration.max_active_agents ?? delivery.max_active_agents;
      const liveNative = lifecycles.filter(row => row.state === 'HELD' && row.revoked !== true && !row.disposed_at && !row.process_stopped_at).length;
      const roleAllocations = new Map();
      const teamNames = new Map(list(snapshot.teams).map(team => [team.team_id, team.name]));
      for (const role of rawRoles) {
        const key = `${role.owner_id ?? ''}:${role.team_id ?? ''}`;
        const group = roleAllocations.get(key) ?? { owner: role.owner_id, team: role.team_id, count: 0 };
        group.count++; roleAllocations.set(key, group);
      }
      const configurationPanel = h('section', { className: 'ffp-card' }, h('div', { className: 'ffp-heading' }, h('h2', null, t('reviewedConfiguration')), currentProjectId && Object.keys(configuration).length > 0 && h('a', { className: 'ffp-link', href: '/api/forgeflow-panel/blueprint?project_id=' + encodeURIComponent(currentProjectId), download: '' }, t('exportBlueprint'))), h('p', { className: 'ffp-note' }, t('configurationReadOnly')),
              h('dl', null, h('dt', null, t('project')), h('dd', null, project.name ?? currentProjectId ?? t('unknown')),
                h('dt', null, t('desiredConcurrency')), h('dd', null, count(desiredActive)),
                h('dt', null, t('softwareCap')), h('dd', null, activeCeiling === 0 ? t('noSoftwareCap') : display(activeCeiling, t)),
                h('dt', null, t('deliveryWindow')), h('dd', null, days === undefined ? t('noDeadline') : t('deadline', { days }))),
              h(VerificationRecovery, { value: verificationRecovery, t }), h(RetainedCandidateReview, { value: retainedCandidateReview, t }),
              h('h3', null, t('modelConfiguration')), h('dl', null,
                h('dt', null, t('model')), h('dd', null, display(modelConfiguration.user_model ?? modelPolicy.user_model ?? delivery.model, t)),
                h('dt', null, t('providerModel')), h('dd', null, display(modelConfiguration.expected_provider_model_id ?? modelConfiguration.id ?? modelPolicy.provider_model_id ?? delivery.expected_provider_model_id, t)),
                h('dt', null, t('modelRoute')), h('dd', null, display(modelConfiguration.model_route_id ?? modelPolicy.model_route_id ?? delivery.model_route, t)),
                h('dt', null, t('reasoningEffort')), h('dd', null, display(modelConfiguration.reasoning_effort, t)),
                h('dt', null, t('maxOutputTokens')), h('dd', null, count(number(modelConfiguration.max_output_tokens)))),
              h('p', { className: 'ffp-note' }, t('admissionNote')), h('h3', null, t('roleAllocation')),
              h('div', { className: 'ffp-table-wrap' }, h('table', null, h('thead', null, h('tr', null, h('th', null, t('owner')), h('th', null, t('roleAllocationCount')))),
                h('tbody', null, [...roleAllocations].map(([key, group]) => h('tr', { key }, h('td', null, `${display(group.owner, t)} / ${display(teamNames.get(group.team) ?? group.team, t)}`), h('td', null, count(group.count))))))), h('details', null, h('summary', null, t('sourceDetails')), h('pre', null, JSON.stringify({ configuration_source: configuration.source, model_policy_source: modelConfiguration.source, provider_policy_id: modelConfiguration.provider_policy_id, provider_policy_sha256: modelConfiguration.provider_policy_sha256 }, null, 2))));
      return h('div', { className: 'ff-native-panel' }, h('style', null, css),
        h('header', { className: 'ffp-header' }, h('div', null, h('h1', null, t('title')), h('p', null, t('subtitle'))),
          menu(projectMenu, setProjectMenu, list(current.projects).map(row => ({ id: row.project_id, label: row.name ?? row.project_id, disabled: !!pendingAction })),
            currentProjectId, project.name ?? t('chooseProject'), value => { setProjectId(value); setSelectedId(''); setAttemptId(''); setReceipt(null); setOwner(''); })),
        verificationRecovery.enabled === true && h('p', { className: 'ffp-note', role: 'status' },
          t(verificationRecovery.max_once === 1 ? 'verificationOnce' : 'verificationReuse') + ' · ' + t('targetAttempt') + ': ' + display(verificationRecovery.attempt_id, t)),
        retainedReviewEnabled && h('p', { className: 'ffp-note', role: 'status' }, t('retainedCandidateReview') + ' · ' + t('targetCard') + ': ' + display(retainedCandidateReview.target_task_id, t)
          + ' · ' + t('modelCallsBudget') + ': ' + count(number(retainedCandidateReview.model_calls))),
        h('div', { className: 'ffp-toolbar' }, action('PREPARE', 'prepare', h(IconBranchOutlineRegular, { size: 14 })),
          action('START', 'start', h(IconPlayOutlineRegular, { size: 14 })), action('PAUSE', 'pause', h(IconPauseOutlineRegular, { size: 14 })),
          h(Button, { size: 'sm', icon: h(IconRefreshOutlineRegular, { size: 14 }), disabled: loading, onClick: () => bump(value => value + 1) }, t('refresh')),
          h('label', { className: 'ffp-note' }, h('input', { type: 'checkbox', checked: auto, onChange: event => setAuto(event.target.checked) }), ` ${t('auto')}`)),
        h('div', { className: 'ffp-meta' }, h('span', null, `${t('project')} · ${project.name ?? t('noProject')}`),
          h('span', null, `${t('revision')} · ${display(snapshot.revision, t)}`), h('span', null, `${t('observed')} · ${display(snapshot.as_of, t)}`),
          h('span', null, `${t('model')} · ${display(delivery.model_id ?? delivery.native_model ?? record(delivery.model).model_id ?? delivery.model ?? delivery.model_route, t)}`),
          h('span', null, days === undefined ? t('noDeadline') : t('deadline', { days }))),
        loading && !data && h('p', { role: 'status', className: 'ffp-note' }, t('refreshing')),
        data && !sourceReady && h('p', { className: 'ffp-note', role: 'status' }, t('sourceNotReady')),
        project.paused === true && h('p', { className: 'ffp-error', role: 'status' }, t('projectSafetyPaused')),
        error && h(React.Fragment, null, h(ErrorBox, { value: error, t }), data && h('p', { className: 'ffp-note' }, t('stale'))),
        ...list(current.errors).map((value, index) => h(ErrorBox, { value, key: index, t })),
        actionError && h(ErrorBox, { value: actionError, t }), currentReceipt && h('section', { className: 'ffp-card', role: 'status' }, h('h2', null, t('actionReceipt')),
          h('dl', null, h('dt', null, t('actionId')), h('dd', null, display(currentReceipt.action_id, t)), h('dt', null, t('actionStatus')), h('dd', null, display(currentReceipt.status, t)),
            h('dt', null, t('source')), h('dd', null, display(currentReceipt.entry_source, t))), h('p', { className: 'ffp-note' }, t('actionNote'))),
        h('div', { className: 'ffp-grid' },
          h(Metric, { name: 'catalogCount', value: count(registeredCardCount ?? (cardsAvailable ? cards.length : undefined)), note: 'catalogNote', t }),
          h(Metric, { name: 'roleCount', value: rolesAvailable ? count(rawRoles.length) : '—', note: 'roleNote', t }),
          h(Metric, { name: 'runningCount', value: `${current.snapshot ? count(running.length) : '—'} / ${Array.isArray(snapshot.native_child_lifecycles) ? count(nativeHeld.length) : '—'}`, note: 'runningNote', t }),
          h(Metric, { name: 'acceptedCount', value: current.snapshot && catalogIdsAvailable ? count(accepted.size) : '—', note: 'acceptedNote', t })),
        h(SegmentedTabs, { items: views.map(value => ({ value, label: t(value), id: `ffp-tab-${value}`, panelId: `ffp-page-${value}` })),
          value: view, onChange: setView, label: t('panel') }),
        h('div', { id: `ffp-page-${view}`, role: 'tabpanel', 'aria-labelledby': `ffp-tab-${view}` },
          view === 'configuration' && h(React.Fragment, null, h(NativeConfigurationEditor, { key: currentProjectId, projectId: currentProjectId, t }), configurationPanel),
          view === 'reuse' && h(BlueprintImport, { t, nativePresets }),
          view === 'overview' && h(React.Fragment, null, h('section', { className: 'ffp-card' }, h('div', { className: 'ffp-heading' }, h('h2', null, t('overview')),
            h(Tag, null, flow.flow_revision ? `R${flow.flow_revision} · ${flow.state}` : t('waiting'))),
            h('div', { className: 'ffp-chain' }, ...[
              ['planned', registeredCardCount ?? (cardsAvailable ? cards.length : undefined)],
              ['committed', current.flow && catalogIdsAvailable ? flowCards.length : undefined],
              ['configured', current.flow ? flowCards.filter(row => Object.keys(record(row.envelope)).length).length : undefined],
              ['executing', current.snapshot && catalogIdsAvailable ? running.filter(row => catalogIds.has(row.task_id)).length : undefined],
              ['accepted', current.snapshot && catalogIdsAvailable ? accepted.size : undefined],
            ].map(([key, value]) => h('div', { key }, h('strong', null, count(value)), h('span', { className: 'ffp-note' }, t(key))))),
            h('div', { className: 'ffp-meta' }, h('span', null, `${t('modelPending')} · ${Array.isArray(snapshot.native_model_requests) ? activeModels : '—'}`),
              h('span', null, `${t('usageUnknown')} · ${Array.isArray(snapshot.native_model_requests) ? unknownModels : '—'}`)),
            h('div', { className: 'ffp-heading' }, h('h3', null, t('liveTarget')), h('strong', null,
              `${Array.isArray(snapshot.native_child_lifecycles) ? count(liveNative) : '—'} / ${count(desiredActive)}`)),
            h('p', { className: 'ffp-note' }, t('liveNote')),
            h('h3', null, t('blockers')), executionBlockers.length > 0 && h(React.Fragment, null,
              h('p', { className: 'ffp-note' }, t('executionBlockers')), h('ul', null, executionBlockers.map(value => h('li', { key: value }, value)))),
            planningBlockers.length > 0 && h(React.Fragment, null, h('p', { className: 'ffp-note' }, `${t('planningBlockers')} · ${t('blockedCards', { count: blockedCardCount })}`),
              h('ul', { className: 'ffp-paths' }, planningBlockers.map(([reason, value]) => h('li', { key: reason }, `${reason} · ${value}`)))),
            !executionBlockers.length && !planningBlockers.length && h('p', { className: 'ffp-note' }, t('noBlockers')),
            h('div', { className: 'ffp-toolbar ffp-input-row' }, h(Input, { value: reason, placeholder: t('replanReason'), 'aria-label': t('replanReason'), onChange: event => setReason(event.target.value) }),
              action('REPLAN', 'replan', h(IconBranchOutlineRegular, { size: 14 }))),
            h('div', { className: 'ffp-toolbar' }, menu(attemptMenu, setAttemptMenu, attempts.map(row => ({ id: row.attempt_id, label: attemptLabel(row) })),
              activeAttempt?.attempt_id, activeAttempt ? attemptLabel(activeAttempt) : t('noAttempt'), setAttemptId),
              action('RETRY', 'retry', null, !retryAllowed), action('CANCEL', 'cancel', null, !cancelAllowed)), h('p', { className: 'ffp-note' }, t('observationNote'))),
            h('section', { className: 'ffp-card' }, h('h2', null, t('resources')), h('div', { className: 'ffp-table-wrap' }, h('table', null,
              h('thead', null, h('tr', null, ...['scope', 'dimension', 'allocated', 'hardLimit'].map(key => h('th', { key }, t(key))))),
              h('tbody', null, list(snapshot.resource_limits).map((row, index) => h('tr', { key: `${row.scope_id}:${row.dimension}:${index}` },
                h('td', null, h('code', null, row.scope_id)), h('td', null, row.dimension), h('td', null, count(number(row.allocated))), h('td', null, count(number(row.hard_limit))))))))),
            h('section', { className: 'ffp-card' }, h('h2', null, t('receipts')), h('ul', null, list(current.action_receipts).slice(-20).reverse().map(row =>
              h('li', { key: row.action_id }, `${row.action} · ${row.status} · ${row.action_id}`))))),
          (view === 'catalog' || view === 'dag') && h('div', { className: displayedCard ? 'ffp-layout' : undefined },
            h('section', { className: 'ffp-card' }, h('div', { className: 'ffp-heading' }, h('h2', null, t(view)), h('span', { className: 'ffp-note' }, `${count(filtered.length)} / ${count(cards.length)}`)),
              h('div', { className: 'ffp-toolbar' }, h(Input, { className: 'ffp-search', type: 'search', value: search, placeholder: t('search'), 'aria-label': t('search'), onChange: event => setSearch(event.target.value) }),
                menu(ownerMenu, setOwnerMenu, [{ id: '', label: t('allOwners') }, ...[...new Set(cards.map(row => row.owner_id))].filter(Boolean).sort().map(value => ({ id: value, label: value }))], owner, owner || t('allOwners'), setOwner)),
              !cardsAvailable || !cards.length && registeredCardCount > 0 ? h('p', { className: 'ffp-empty', role: 'status' }, t(registeredCardCount > 0 ? 'registeredListUnavailable' : 'directoryUnavailable'))
                : view === 'dag' ? h(Dag, { cards, selectedId, onSelect: setSelectedId, t }) : !filtered.length ? h('p', { className: 'ffp-empty' }, t(cards.length ? 'emptyFilter' : 'emptyCatalog')) :
                h('div', { className: 'ffp-table-wrap' }, h('table', null, h('thead', null, h('tr', null, ...['task', 'owner', 'state', 'blockers'].map(key => h('th', { key }, t(key))))),
                  h('tbody', null, filtered.slice(currentPage * 40, currentPage * 40 + 40).map(card => {
                    const bound = canonicalBindings.get(taskId(card)) ?? flowCards.find(row => taskId(row) === taskId(card));
                    return h('tr', { key: taskId(card) }, h('td', null, h('button', { type: 'button', className: 'ffp-link', onClick: () => setSelectedId(taskId(card)) },
                      h('strong', null, card.title ?? taskId(card)), h('code', null, taskId(card)))), h('td', null, card.owner_id, h('small', null, card.team_id), h('small', null, card.role_id)),
                      h('td', null, display(bound?.state ?? card.state, t), h('small', null, bound ? t('currentFlow', { revision: bound.flow_revision ?? flow.flow_revision }) : t('noFlow')),
                        h('small', null, bound?.envelope || bound?.frozen_execution_envelope_present === true ? t('envelope') : t('noEnvelope'))), h('td', null, reasons(card).slice(0, 2).join(' · ') || t('noBlockers')));
                  })))), view === 'catalog' && h('div', { className: 'ffp-pagination' }, h('span', { className: 'ffp-note' }, t('pagination', { page: currentPage + 1, pages, count: filtered.length })),
                  h('div', null, h(Button, { size: 'sm', disabled: currentPage === 0, onClick: () => setPage(currentPage - 1) }, t('previous')),
                    h(Button, { size: 'sm', disabled: currentPage + 1 >= pages, onClick: () => setPage(currentPage + 1) }, t('next'))))),
            h(CardDetails, { card: displayedCard, t, onClose: () => setSelectedId('') })),
          view === 'agents' && h(React.Fragment, null, h(NativeContexts, { snapshot, observations: observed, roles: rawRoles, t }),
            h(HostContexts, { sessions, statuses, openSession, refreshNative, t }), h('section', { className: 'ffp-card' }, h('h2', null, t('roster')),
              h('div', { className: 'ffp-roles' }, rawRoles.map((role, index) => h('article', { className: 'ffp-role', key: role.agent_id ?? role.role_id ?? index },
                h('div', { className: 'ffp-heading' }, h('h3', null, role.position ?? role.name ?? role.title), h(Tag, null, role.state ?? 'PLANNED')),
                h('code', null, role.agent_id ?? role.role_id), h('dl', null, h('dt', null, t('owner')), h('dd', null, `${display(role.owner_id, t)} / ${display(role.team_id, t)}`),
                  h('dt', null, t('parent')), h('dd', null, role.parent_agent_id ?? role.parent_role_id ?? t('root')),
                  h('dt', null, t('preset')), h('dd', null, role.preset_id ?? role.agent_preset_id ?? t('noPreset')))))))),
          view === 'workflow' && h(NativeWorkflow, { observations: observed, t }),
          view === 'presets' && h('section', { className: 'ffp-card' }, h('div', { className: 'ffp-heading' }, h('h2', null, t('nativePresets')),
            h('span', { className: 'ffp-note' }, nativePresetsAvailable ? count(nativePresets.length) : '—')),
            h('p', { className: 'ffp-note' }, t('nativePresetsNote')),
            !nativePresetsAvailable ? h('p', { className: 'ffp-empty' }, t('presetUnavailable')) : h('div', { className: 'ffp-roles' }, nativePresets.map(preset =>
              h('article', { className: 'ffp-role', key: preset.id }, h('div', { className: 'ffp-heading' }, h('h3', null, preset.name ?? preset.id),
                h(Tag, null, preset.broken ? t('presetDiagnostic') : t('presetRegistered'))), h('code', null, preset.id),
                preset.description && h('p', { className: 'ffp-note' }, preset.description), preset.broken && h(ErrorBox, { value: { message: preset.broken }, t }),
                presetCompositions.has(preset.id) && h('details', null, h('summary', null, t('pluginComposition')),
                  h('ul', { className: 'ffp-paths' }, list(presetCompositions.get(preset.id).rows).map((row, index) => h('li', { key: `${row.entryId}:${index}` },
                    h('code', null, row.moduleName), ` · ${t('enabled')}: ${display(row.enabled, t)} · ${display(row.fiberPhase, t)}`))))))),
            h('div', { className: 'ffp-heading' }, h('h2', null, t('nativePlugins')), h('span', { className: 'ffp-note' },
              Array.isArray(nativeInventory.entries) && !sectionErrors.has('native_plugin_inventory') ? count(nativeInventory.entries.length) : '—')),
            h('div', { className: 'ffp-table-wrap' }, h('table', null, h('thead', null, h('tr', null, ...['plugins', 'module', 'enabled', 'fiberPhase'].map(key => h('th', { key }, t(key))))),
              h('tbody', null, list(nativeInventory.entries).map(row => h('tr', { key: row.entryId }, h('td', null, h('code', null, row.entryId)),
                h('td', null, h('code', null, row.moduleName)), h('td', null, display(row.enabled, t)), h('td', null, display(row.fiberPhase, t))))))),
            h('h2', null, t('presets')), h('div', { className: 'ffp-roles' }, list(current.executor_profiles).map(profile => {
            const mode = record(profile.native_mode); const audits = list(audit.profiles ?? audit.presets);
            const proof = audits.find(row => (row.executor_profile_id ?? row.profile_id ?? row.id) === profile.id);
            const actual = list(snapshot.attempt_native_profiles).filter(row => row.executor_profile_id === profile.id);
            const frozen = [...new Set(actual.flatMap(row => strings(row.capabilities)))];
            return h('article', { className: 'ffp-role', key: profile.id }, h('h3', null, profile.id), h('dl', null,
              h('dt', null, t('executor')), h('dd', null, profile.kind), h('dt', null, t('preset')), h('dd', null, display(mode.mode_id, t)),
              h('dt', null, t('model')), h('dd', null, display(profile.model_route_id, t)), h('dt', null, t('qualification')), h('dd', null, proof?.qualification ?? proof?.status ?? t('noAudit')),
              h('dt', null, t('presetHash')), h('dd', null, h('code', null, display(proof?.preset_sha256 ?? actual[0]?.preset_sha256, t))),
              h('dt', null, t('qualifiedScope')), h('dd', null, display(proof?.qualified_scope, t))),
              h('p', { className: 'ffp-note' }, t('capability')), h('div', { className: 'ffp-tags' }, frozen.map(value => h(Tag, { key: value }, value))));
          })), h('h3', null, t('plugins')), h('ul', null, list(audit.plugins).map((plugin, index) => h('li', { key: plugin.id ?? plugin.name ?? index },
            `${display(plugin.name ?? plugin.id, t)} · ${display(plugin.status ?? plugin.qualification, t)} · ${display(plugin.sha256 ?? plugin.version, t)}`))))),
        auto && refreshInterval === undefined && h('p', { className: 'ffp-note' }, t('pollUnavailable')));
    }
    function PanelIcon({ size }) { return h(IconBranchOutlineRegular, { size }); }
    return {
      name: 'forgeflow-native-ui-panel',
      inject: ['slots', 'locale', 'sessions', 'uiWorkspace'],
      apply(ctx) {
        ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'forgeflow-native-ui-panel: dictionaries');
        const t = ctx.locale.bind(NS);
        const actions = {
          openSession(id) {
            const address = ctx.sessions.subagentAddress(id);
            const known = ctx.sessions.list.getSnapshot().ids.includes(id);
            if (!address && !known) throw new Error(`SESSION_NOT_DISCOVERED: ${id}`);
            ctx.uiWorkspace.openSession(address ?? id);
          },
          async refreshNative() {
            await ctx.sessions.refresh();
            await Promise.all(ctx.sessions.list.getSnapshot().ids.map(id => ctx.sessions.refreshProjections(id)));
          },
        };
        ctx.slots.inject('main', () => ctx.slots.register({ name: 'main', key: PANEL_ID, locale: NS, inject: () => actions }, Panel));
        ctx.slots.inject('sidebar.panellist', () => ctx.slots.register({ name: 'sidebar.panellist', id: PANEL_ID,
          order: 15, locale: NS, label: () => t('panel') }, PanelIcon));
      },
    };
  },
});
