import { planningWorkbenchEnabled } from "./feature-flags";
import { NavLink } from "react-router-dom";
import { ArrowRight, ChevronDown, Route } from "lucide-react";

export function ProjectJourney({ projectId }: { projectId: string }) {
  const base = `/projects/${encodeURIComponent(projectId)}`;
  const query = `?project=${encodeURIComponent(projectId)}`;
  if (planningWorkbenchEnabled()) return <nav className="project-core-nav" aria-label="项目核心导航">{[
    ["总览", base], ["规划", `${base}/flows`], ["Agent 团队", `${base}/teams`], ["排程", `${base}/schedule`], ["执行与验收", `/runs${query}`],
  ].map(([label, to]) => <NavLink key={label} to={to} end={to === base}>{label}</NavLink>)}</nav>;
  const steps = [
    { title: "项目范围", description: "确认目标与交付范围", links: [["工作台", base], ["项目组合", "/portfolio"]] },
    { title: "需求与规划", description: "建立需求映射与依赖", links: [["需求", `${base}/requirements`], ["Flow", `${base}/flows`], ["合同", `${base}/contracts`]] },
    { title: "分工与容量", description: "分配责任并核对预算", links: [["任务", `${base}/tasks`], ["团队", `${base}/teams`], ["资源", "/resources"]] },
    { title: "排程与基线", description: "安排工期并保留计划依据", links: [["排程", `${base}/schedule`], ["日历", `/calendar${query}`]] },
    { title: "执行与尝试", description: "查看准入、执行与失败原因", links: [["执行", `/runs${query}`], ["执行器", "/executors"]] },
    { title: "审查与证据", description: "核对检查、回执与验收依据", links: [["检查", `/checks${query}`], ["证据", `${base}/evidence`]] },
    { title: "集成与交付", description: "回读集成结果和交付证据", links: [["集成", `${base}/integration`], ["交付证据", `${base}/evidence`]] },
  ];
  return <details className="project-journey">
    <summary><Route size={16} /><strong>项目交付路径</strong><ChevronDown size={12} className="journey-chevron" /><span>规划 <ArrowRight size={11} /> 分配 <ArrowRight size={11} /> 排程 <ArrowRight size={11} /> 执行 <ArrowRight size={11} /> 审查 <ArrowRight size={11} /> 交付</span></summary>
    <nav aria-label="项目交付路径"><ol>{steps.map((step, index) => <li key={step.title}>
      <div className="journey-step-title"><span className="journey-number">{index + 1}</span><strong>{step.title}</strong></div>
      <p>{step.description}</p>
      <div className="journey-links">{step.links.map(([label, to]) => <NavLink key={label} to={to} end>{label}<ArrowRight size={10} /></NavLink>)}</div>
    </li>)}</ol></nav>
  </details>;
}
