import {
  useEffect,
  useRef,
  useState,
  lazy,
  Suspense,
  type ReactNode,
  type PointerEvent as ReactPointerEvent,
} from "react";
import {
  Link,
  NavLink,
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigate,
  useParams,
} from "react-router-dom";
import {
  Layers3,
  LayoutGrid,
  FolderKanban,
  Workflow,
  Play,
  ShieldCheck,
  Gauge,
  Settings2,
  Search,
  Command,
  Menu,
  ArrowUpRight,
  Sun,
  Moon,
  CalendarDays,
  Network,
  FileCheck2,
  Terminal,
  GitMerge,
  RotateCcw,
  Inbox,
  Plus,
  ChevronDown,
  AlertCircle,
  Archive,
  PanelLeftClose,
  PanelLeftOpen,
  ChevronUp,
  X,
  BookOpen,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useApi, api, getToken, getWorkspace, isPersonalAccount, ApiError } from "./api";
import { useEventConnection, type ControlEvent } from "./events";
import { EcpJourney } from "./EcpJourney";
import type { ProjectRef } from "./types";
import { Drawer, EmptyState, ErrorNotice } from "../components";
import "./product-shell.css";
import "../features/flow/planning-workbench.css";
import { planningWorkbenchEnabled } from "./feature-flags";
import {WorkspaceSwitcher,type Account,type Workspace} from './WorkspaceSwitcher';
import {AppearanceButton} from './AppearanceControls';
import {useAppearance,toggleColorMode} from './appearance';
import '../styles/accounts-network.css';
const WorkspacesPage=lazy(()=>import('../features/workspaces').then(m=>({default:m.WorkspacesPage})));
const InvitePage=lazy(()=>import('../features/workspaces').then(m=>({default:m.InvitePage})));
const TutorialPage=lazy(()=>import('../features/tutorial').then(m=>({default:m.TutorialPage})));
const AgentNetworkPage=lazy(()=>import('../features/agent-network').then(m=>({default:m.AgentNetworkPage})));
const EcpConversationPage=lazy(()=>import('../features/collaboration').then(m=>({default:m.EcpConversation})));
const AgentRegistryPage=lazy(()=>import('../features/agents').then(m=>({default:m.AgentRegistryPage})));
const EcpHubPage=lazy(()=>import('../features/collaboration/EcpHub').then(m=>({default:m.EcpHub})));
const EcpBotRoomPage=lazy(()=>import('../features/agents/EcpBotRoom').then(m=>({default:m.EcpBotRoom})));
const EcpDagPage=lazy(()=>import('../features/flow/EcpDag').then(m=>({default:m.EcpDag})));
const EcpGanttPage=lazy(()=>import('../features/timeline/EcpGantt').then(m=>({default:m.EcpGantt})));
const EcpCalendarPage=lazy(()=>import('../features/timeline/EcpCalendar').then(m=>({default:m.EcpCalendar})));
const EcpAgentTheaterPage=lazy(()=>import('../features/agents/EcpAgentTheater').then(m=>({default:m.EcpAgentTheater})));
const EcpEvidencePage=lazy(()=>import('../features/evidence/EcpEvidence').then(m=>({default:m.EcpEvidence})));
const EcpReleasePage=lazy(()=>import('../features/releases/EcpRelease').then(m=>({default:m.EcpRelease})));
const EcpMaintenancePage=lazy(()=>import('../features/settings/EcpMaintenance').then(m=>({default:m.EcpMaintenance})));
import {
  SettingsPage,
  RecoveryPage,
  DecisionsPage,
  LoginPage,
} from "./UtilityPages";
const EcpPortfolioPage = lazy(() =>
  import("../features/portfolio/EcpPortfolio").then((module) => ({
    default: module.EcpPortfolio,
  })),
);
const ProjectPage = lazy(() =>
  import("../features/portfolio").then((module) => ({
    default: module.ProjectPage,
  })),
);
const ProjectNewPage = lazy(() =>
  import("../features/portfolio").then((module) => ({
    default: module.ProjectNewPage,
  })),
);
const RequirementsPage = lazy(() =>
  import("../features/planning").then((module) => ({
    default: module.RequirementsPage,
  })),
);
const FlowPage = lazy(() =>
  import("../features/flow").then((module) => ({ default: module.FlowPage })),
);
const TasksPage = lazy(() =>
  import("../features/flow").then((module) => ({ default: module.TasksPage })),
);
const ChecksPage = lazy(() =>
  import("../features/checks").then((module) => ({
    default: module.ChecksPage,
  })),
);
const ContractsPage = lazy(() =>
  import("../features/contracts").then((module) => ({
    default: module.ContractsPage,
  })),
);
const TeamsPage = lazy(() =>
  import("../features/teams").then((module) => ({ default: module.TeamsPage })),
);
const RunsPage = lazy(() =>
  import("../features/runs").then((module) => ({ default: module.RunsPage })),
);
const AttemptPage = lazy(() =>
  import("../features/runs").then((module) => ({
    default: module.AttemptPage,
  })),
);
const ExecutorsPage = lazy(() =>
  import("../features/runs").then((module) => ({
    default: module.ExecutorsPage,
  })),
);
const ResourcePage = lazy(() =>
  import("../features/runs").then((module) => ({
    default: module.ResourcePage,
  })),
);
const TimelinePage = lazy(() =>
  import("../features/timeline").then((module) => ({
    default: module.TimelinePage,
  })),
);
const ReleasesPage = lazy(() => import('./ReleasesPage').then(module => ({ default: module.ReleasesPage })));
const CalendarPage = lazy(() =>
  import("../features/timeline").then((module) => ({
    default: module.CalendarPage,
  })),
);
const EvidencePage = lazy(() =>
  import("../features/evidence").then((module) => ({
    default: module.EvidencePage,
  })),
);
const IntegrationPage = lazy(() =>
  import("../features/evidence").then((module) => ({
    default: module.IntegrationPage,
  })),
);
function ContextPage({
  children,
}: {
  children: (props: Readonly<Record<string, string | undefined>>) => ReactNode;
}) {
  return <>{children(useParams<Record<string, string>>())}</>;
}
type WorkspaceId = "mission" | "flow" | "agents" | "timeline" | "evidence" | "system";
type ProjectNamingFilter = "all" | "hide-tests" | "tests";
const projectKey = (project: ProjectRef) => project.id || project.project_id || "";
// A local navigation hint only. It is never used as an environment or authority flag.
const hasTestNaming = (project: ProjectRef) =>
  /(?:^|[\s_-])(?:qa|test|tests|smoke|acceptance|fixture|counterexample)(?:$|[\s_-])|测试|验收|交互验证/i.test(
    `${project.name} ${projectKey(project)}`,
  );
const groups: { id: WorkspaceId; label: string; caption: string; icon: LucideIcon; path: string; project?: boolean }[] = [
  { id: "mission", label: "总览", caption: "Mission Control", icon: LayoutGrid, path: "/portfolio" },
  { id: "flow", label: "规划", caption: "Planning", icon: Workflow, path: "/flows", project: true },
  { id: "agents", label: "Agent 团队", caption: "Agent Teams", icon: Network, path: "/teams", project: true },
  { id: "timeline", label: "排程", caption: "Schedule", icon: CalendarDays, path: "/schedule", project: true },
  { id: "evidence", label: "执行与验收", caption: "Execution & Review", icon: ShieldCheck, path: "/runs" },
  { id: "system", label: "系统", caption: "System", icon: Settings2, path: "/settings" },
];
function workspaceFor(path: string): WorkspaceId {
  if (/^\/(executors|resources|recovery|settings|decisions|workspaces)(\/|$)/.test(path)) return "system";
  if (/^\/runs(\/|$)/.test(path)) return "evidence";
  if (/\/(teams|agent-network)(\/|$)/.test(path)) return "agents";
  if (path === "/calendar" || /\/schedule(\/|$)/.test(path)) return "timeline";
  if (path === "/checks" || /\/(evidence|integration|releases)(\/|$)/.test(path)) return "evidence";
  if (/\/(requirements|flows|tasks|contracts)(\/|$)/.test(path)) return "flow";
  return "mission";
}
export function App() {
  const location = useLocation();
  const navigate = useNavigate();
  const pathProject = location.pathname.match(/^\/projects\/([^/]+)/)?.[1];
  const queryProject = new URLSearchParams(location.search).get("project") || undefined;
  const activeWorkspace = workspaceFor(location.pathname);
  const workspace = groups.find((group) => group.id === activeWorkspace)!;
  const [selected, setSelected] = useState(
    localStorage.getItem("forgeflow.project") || "",
  );
  const projectId =
    pathProject && pathProject !== "new"
      ? decodeURIComponent(pathProject)
      : queryProject || selected || undefined;
  const globalScope = [
    "/portfolio",
    "/resources",
    "/settings",
    "/executors",
    "/executors/registry",
    "/recovery",
    "/decisions",
    "/projects/new",
    "/workspaces", "/invite", "/tutorial",
  ].includes(location.pathname);
  const visibleProjectId = globalScope ? undefined : projectId;
  const [authVersion, setAuthVersion] = useState(0);
  const projects = useApi<ProjectRef[]>(isPersonalAccount()&&!getWorkspace()?null:"/projects");
  const [projectCatalog, setProjectCatalog] = useState<ProjectRef[]>([]);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [catalogError, setCatalogError] = useState<Error>();
  const identity = useApi<Record<string, unknown>>("/me");
  const personal=identity.data?.role==='account';
  const [collapsed, setCollapsed] = useState(
    localStorage.getItem("forgeflow.rail") === "collapsed",
  );
  const [mobile, setMobile] = useState(false);
  const [projectFilter, setProjectFilter] = useState("");
  const [projectNamingFilter, setProjectNamingFilter] = useState<ProjectNamingFilter>(() => {
    const stored = localStorage.getItem("forgeflow.project-naming-filter");
    return stored === "hide-tests" || stored === "tests" ? stored : "all";
  });
  const [narrow, setNarrow] = useState(
    () => matchMedia("(max-width: 768px)").matches,
  );
  const sidebarRef = useRef<HTMLElement>(null);
  const menuRef = useRef<HTMLButtonElement>(null);
  const theme=useAppearance().resolved;
  const [density, setDensity] = useState(
    localStorage.getItem("forgeflow.density") || "standard",
  );
  const [commands, setCommands] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [searchResults, setSearchResults] = useState<unknown>();
  const [searchError, setSearchError] = useState<Error>();
  const [searchLoading, setSearchLoading] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);
  const events = useEventConnection(visibleProjectId);
  useEffect(() => {
    setProjectCatalog(projects.data || []);
    setCatalogError(undefined);
    if (!projects.data || !projects.metadata.next_cursor) {
      setCatalogLoading(false);
      return;
    }
    const controller = new AbortController();
    setCatalogLoading(true);
    api
      .collect<ProjectRef>("/projects", controller.signal)
      .then((result) => setProjectCatalog(result.data))
      .catch((error) => {
        if (!controller.signal.aborted) setCatalogError(error as Error);
      })
      .finally(() => {
        if (!controller.signal.aborted) setCatalogLoading(false);
      });
    return () => controller.abort();
  }, [projects.data, projects.metadata.next_cursor]);
  useEffect(() => {
    const media = matchMedia("(max-width: 768px)");
    const change = () => setNarrow(media.matches);
    media.addEventListener("change", change);
    return () => media.removeEventListener("change", change);
  }, []);
  useEffect(() => {
    if (!mobile || !narrow) return;
    const focusable=()=>Array.from(sidebarRef.current?.querySelectorAll<HTMLElement>(
      'a[href],button,input,select,textarea,[tabindex]',
    )||[]).filter(node=>node.tabIndex>=0&&!node.matches(':disabled')&&!node.closest('[inert]')&&node.getClientRects().length>0);
    focusable()[0]?.focus();
    const trap = (event: KeyboardEvent) => {
      if (event.key !== "Tab") return;
      const nodes = focusable();
      if (event.shiftKey && document.activeElement === nodes[0]) {
        event.preventDefault();
        nodes.at(-1)?.focus();
      } else if (!event.shiftKey && document.activeElement === nodes.at(-1)) {
        event.preventDefault();
        nodes[0]?.focus();
      }
    };
    document.addEventListener("keydown", trap);
    return () => {
      document.removeEventListener("keydown", trap);
      menuRef.current?.focus();
    };
  }, [mobile, narrow]);
  useEffect(() => {
    const handler = () => {
      setAuthVersion((v) => v + 1);
      setSelected(localStorage.getItem('forgeflow.project')||'');
      setProjectCatalog([]);
      projects.reload();
      identity.reload();
    };
    window.addEventListener("forgeflow-auth", handler);
    return () => window.removeEventListener("forgeflow-auth", handler);
  }, [projects.reload, identity.reload]);
  useEffect(()=>{
    const refresh=()=>identity.reload();window.addEventListener('forgeflow-membership-stale',refresh);
    return()=>window.removeEventListener('forgeflow-membership-stale',refresh);
  },[identity.reload]);
  useEffect(() => {
    document.documentElement.dataset.density = density;
    localStorage.setItem("forgeflow.density", density);
  }, [density]);
  useEffect(() => {
    setMobile(false);
  }, [location.pathname]);
  useEffect(() => {
    if (projectId) {
      setSelected(projectId);
      localStorage.setItem("forgeflow.project", projectId);
    }
  }, [projectId]);
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if(document.querySelector('[data-appearance-dialog]'))return;
      const editing = (e.target as HTMLElement).closest(
        'input,textarea,select,[contenteditable="true"]',
      );
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCommands((v) => !v);
      } else if (e.key === "/" && !editing) {
        e.preventDefault();
        setSearchOpen(true);
      } else if (e.key === "Escape") {
        setMobile(false);
      }
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, []);
  useEffect(() => {
    if (searchOpen) searchRef.current?.focus();
  }, [searchOpen]);
  const project = projectCatalog.find(
    (p) => (p.id || p.project_id) === projectId,
  );
  const projectSearch = projectFilter.trim().toLocaleLowerCase();
  const filteredProjects = projectCatalog.filter((item) => {
    const matchesSearch = `${item.name} ${projectKey(item)}`.toLocaleLowerCase().includes(projectSearch);
    return matchesSearch && (projectNamingFilter === "all" ||
      (projectNamingFilter === "tests" ? hasTestNaming(item) : !hasTestNaming(item)));
  });
  const pinnedProject = visibleProjectId && project &&
    !filteredProjects.some((item) => projectKey(item) === visibleProjectId) ? project : undefined;
  const renderProjectLink = (item: ProjectRef) => {
    const key = projectKey(item);
    return key ? <Link key={key} className={`object-link project-catalog-entry ${key === visibleProjectId ? "selected" : ""}`}
      to={`/projects/${encodeURIComponent(key)}`} title={`${item.name}\n${key}`}
      aria-current={key === visibleProjectId ? "page" : undefined}>
      <FolderKanban size={14} /><span>{item.name}</span>
    </Link> : null;
  };
  const base = projectId
    ? `/projects/${encodeURIComponent(projectId)}`
    : "/portfolio";
  const toggleTheme = toggleColorMode;
  const scopeQuery = projectId ? `?project=${encodeURIComponent(projectId)}` : "";
  const groupPath = (g: (typeof groups)[number]) => {
    if (g.project) return projectId ? base + g.path : g.id === "timeline" ? "/calendar" : g.id === "evidence" ? "/checks" : "/flows";
    return g.path === "/runs" ? g.path + scopeQuery : g.path;
  };
  const projectViews = projectId ? [
    { workspace: "mission", label: "项目工作台", path: base, icon: FolderKanban },
    { workspace: "flow", label: "需求与设计", path: `${base}/requirements`, icon: FileCheck2 },
    { workspace: "flow", label: "规划工作台", path: `${base}/flows`, icon: Workflow },
    { workspace: "flow", label: "任务", path: `${base}/tasks`, icon: FileCheck2 },
    { workspace: "flow", label: "合同", path: `${base}/contracts`, icon: FileCheck2 },
    { workspace: "agents", label: "交付团队", path: `${base}/teams`, icon: Network },
    ...(personal?[{workspace:'agents',label:'Agent 通讯',path:`${base}/agent-network`,icon:Network}]:[]),
    { workspace: "timeline", label: "甘特排程", path: `${base}/schedule`, icon: CalendarDays },
    { workspace: "evidence", label: "证据溯源", path: `${base}/evidence`, icon: ShieldCheck },
    { workspace: "evidence", label: "Git 集成", path: `${base}/integration`, icon: GitMerge },
    { workspace: "evidence", label: "发布", path: `${base}/releases`, icon: Archive },
  ].filter((view) => view.workspace === activeWorkspace) : [];
  const globalViews = {
    mission: [{ label: "项目组合", path: "/portfolio", icon: LayoutGrid }, { label: "接入项目", path: "/projects/new", icon: Plus }],
    flow: [],
    agents: [{ label: "执行大厅", path: `/runs${scopeQuery}`, icon: Play }],
    timeline: [{ label: "日程与里程碑", path: `/calendar${scopeQuery}`, icon: CalendarDays }],
    evidence: [{ label: "统一检查", path: `/checks${scopeQuery}`, icon: ShieldCheck }],
    system: personal?[{label:'工作区与成员',path:'/workspaces',icon:Network},{label:'个人网站教程',path:'/tutorial',icon:BookOpen}]:[{ label: "执行器", path: "/executors", icon: Terminal }, { label: "Agent Registry", path: "/executors/registry", icon: Network }, { label: "资源监控", path: "/resources", icon: Gauge }, { label: "决策收件箱", path: "/decisions", icon: Inbox }, { label: "恢复台", path: "/recovery", icon: RotateCcw }, { label: "设置与部署", path: "/settings", icon: Settings2 },{label:'个人网站教程',path:'/tutorial',icon:BookOpen}],
  }[activeWorkspace];
  const routeObject = location.pathname.match(/\/(flows|tasks)\/([^/]+)/) || location.pathname.match(/^\/(runs)\/([^/]+)/);

  async function runSearch() {
    setSearchLoading(true);
    setSearchError(undefined);
    try {
      const needle=search.trim().toLocaleLowerCase();
      const matches=projectCatalog.filter(p=>`${p.name} ${projectKey(p)}`.toLocaleLowerCase().includes(needle));
      const cards=projectId&&project?await api.raw<{task_id:string;title:string}[]>(`/projects/${encodeURIComponent(projectId)}/tasks?q=${encodeURIComponent(search.trim())}&limit=20`):undefined;
      setSearchResults({items:[...matches.map(p=>({title:p.name,path:`/projects/${encodeURIComponent(projectKey(p))}`})),...(cards?.data??[]).map(t=>({title:t.title,path:`/projects/${encodeURIComponent(projectId!)}/tasks?task=${encodeURIComponent(t.task_id)}`}))],total_count:matches.length+(cards?.total_count??cards?.data?.length??0)});
    } catch (e) {
      setSearchError(e as Error);
    } finally {
      setSearchLoading(false);
    }
  }
  const needsLogin = (!getToken() && !identity.data) ||
    (identity.error instanceof ApiError && identity.error.status === 401);
  if (needsLogin && location.pathname !== "/settings") {
    return (
      <div className="welcome-shell">
        <header className="welcome-header">
          <a className="welcome-brand" href="/" aria-label="ForgeFlow 首页">
            <span className="brand-mark"><Layers3 size={23} strokeWidth={1.6} /></span>
            <span>ForgeFlow<span className="welcome-brand-caption">你的研发工作空间</span></span>
          </a>
          <div className="welcome-appearance-actions"><AppearanceButton welcome/><button className="welcome-theme" onClick={toggleTheme} aria-label={theme === "dark" ? "切换浅色主题" : "切换深色主题"}>
            {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
            <span>{theme === "dark" ? "浅色外观" : "深色外观"}</span>
          </button></div>
        </header>
        <main id="main-content" className={`welcome-main ${location.pathname==='/tutorial'?'public-tutorial':''}`}><Suspense fallback={<p role="status">正在打开…</p>}>{location.pathname==='/tutorial'?<TutorialPage/>:<>{location.pathname==='/invite'&&<p className="invite-login-hint">已收到工作区邀请。先注册或登录个人账号，再接受邀请。</p>}<LoginPage /></>}</Suspense></main>
        <footer className="welcome-footer"><span>ForgeFlow · 从想法到交付</span><span>独立部署，工作由你掌握。</span></footer>
      </div>
    );
  }
  return (
    <div className={`app-shell next-shell ${collapsed ? "rail-collapsed" : ""}`}>
      <a className="skip-link" href="#main-content">
        跳到工作区
      </a>
      {mobile && (
        <button
          className="mobile-scrim"
          onClick={() => setMobile(false)}
          aria-label="关闭导航"
        />
      )}
      <aside
        ref={sidebarRef}
        inert={narrow && !mobile}
        aria-hidden={(narrow && !mobile) || undefined}
        aria-label="工作空间导航"
        role={narrow && mobile ? "dialog" : undefined}
        aria-modal={(narrow && mobile) || undefined}
        className={`sidebar ${mobile ? "mobile-open" : ""}`}
      >
        <div className="workspace-rail">
          <Link className="brand" to="/portfolio" aria-label="ForgeFlow 首页" title="ForgeFlow">
            <span className="brand-mark"><Layers3 size={21} strokeWidth={1.6} /></span>
          </Link>
          <nav aria-label="六个工作空间">
            {groups.map((group) => (
              <Link key={group.id} to={groupPath(group)}
                className={`nav-item ${activeWorkspace === group.id ? "active" : ""}`}
                aria-label={`${group.label} · ${group.caption}`} aria-current={activeWorkspace === group.id ? "page" : undefined}
                title={`${group.label} · ${group.caption}`}>
                <group.icon size={19} strokeWidth={1.65} /><span>{group.label}</span>
              </Link>
            ))}
          </nav>
          <button className="icon-button explorer-toggle" aria-label={collapsed ? "展开对象浏览栏" : "收起对象浏览栏"}
            aria-expanded={!collapsed} aria-controls="workspace-explorer" onClick={() => setCollapsed((value) => {
              localStorage.setItem("forgeflow.rail", value ? "expanded" : "collapsed"); return !value;
            })}>{collapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}</button>
        </div>
        <div id="workspace-explorer" className="workspace-explorer" inert={collapsed && !narrow}>
          {personal&&<WorkspaceSwitcher account={identity.data?.account as Account} workspaces={identity.data?.workspaces as Workspace[]}/>}
          <div className="explorer-heading"><span><strong>{workspace.label}</strong><small>{workspace.caption}</small></span>
            {narrow && <button className="icon-button" aria-label="关闭导航" onClick={() => setMobile(false)}><X size={16} /></button>}
          </div>
          <nav className="object-navigation" aria-label={`${workspace.label}子视图`}>
            {[...globalViews, ...projectViews].map((view) => <NavLink key={view.path} to={view.path} end={view.path === base || view.path === "/portfolio"}
              className={({ isActive }) => `object-link ${isActive ? "active" : ""}`}><view.icon size={15} /><span>{view.label}</span></NavLink>)}
            {activeWorkspace === "flow" && !projectId && <p className="explorer-note">选择项目，查看需求、Flow、任务与合同。</p>}
          </nav>
          <div className="explorer-section-title">项目目录 <span>{filteredProjects.length} / {projectCatalog.length}{catalogLoading ? "+" : ""}</span></div>
          <input className="project-filter" type="search" aria-label="筛选项目目录" placeholder="筛选项目…" value={projectFilter} onChange={(event) => setProjectFilter(event.target.value)} />
          <select className="project-catalog-mode" aria-label="项目命名筛选" value={projectNamingFilter} onChange={(event) => {
            const value = event.target.value as ProjectNamingFilter;
            setProjectNamingFilter(value);
            localStorage.setItem("forgeflow.project-naming-filter", value);
          }}>
            <option value="all">全部项目</option>
            <option value="hide-tests">收起测试命名项目</option>
            <option value="tests">仅看测试命名项目</option>
          </select>
          <p className="project-catalog-hint">按名称和标识识别测试命名，仅筛选此目录，不改变项目环境或全局检查。</p>
          <nav className="explorer-projects" aria-label="项目目录">
            {projects.loading && !projectCatalog.length && <p className="explorer-note" role="status">正在读取项目…</p>}
            {(projects.error || catalogError) && <button className="explorer-retry" onClick={projects.reload}>目录读取失败 · 重试</button>}
            {!projects.loading && !projects.error && !projectCatalog.length && <p className="explorer-note">尚无项目</p>}
            {pinnedProject && <div className="project-catalog-pinned"><p className="project-catalog-group">当前项目 · 保留展示</p>{renderProjectLink(pinnedProject)}</div>}
            {projectCatalog.length > 0 && filteredProjects.length === 0 && <p className="explorer-note">没有匹配项目{pinnedProject ? "，当前项目仍保留展示。" : "。"}</p>}
            {([false, true] as const).map((testNaming) => {
              const group = filteredProjects.filter((item) => hasTestNaming(item) === testNaming);
              return group.length > 0 ? <div key={String(testNaming)} className="project-catalog-group-items">
                <p className="project-catalog-group">{testNaming ? "测试命名" : "其他命名"}<span>{group.length}</span></p>
                {group.map(renderProjectLink)}
              </div> : null;
            })}
          </nav>
          {routeObject && <div className="route-context"><span>当前路径对象 · 详情由页面提供</span><strong>{routeObject[1] === "tasks" ? "Task" : routeObject[1] === "runs" ? "Attempt" : "Flow"}</strong><code>{decodeURIComponent(routeObject[2])}</code></div>}
          <Link className="explorer-add" to="/projects/new"><Plus size={14} />接入项目</Link>
        </div>
      </aside>
      <div className="workspace-main" inert={narrow && mobile}>
        <header className="topbar">
          <button
            ref={menuRef}
            className="mobile-menu icon-button"
            onClick={() => setMobile(true)}
            aria-label="打开主导航"
          >
            <Menu size={20} />
          </button>
          <div className="scope-select">
            <Layers3 size={16} />
            <select
              title={
                catalogLoading
                  ? "正在读取剩余项目目录"
                  : `已读取 ${projectCatalog.length} 个项目`
              }
              aria-label="当前项目作用域"
              value={visibleProjectId || ""}
              onChange={(e) => {
                const id = e.target.value;
                setSelected(id);
                localStorage.setItem("forgeflow.project", id);
                navigate(
                  id ? `/projects/${encodeURIComponent(id)}` : "/portfolio",
                );
              }}
            >
              <option value="">全部项目</option>
              {projectCatalog.map((p) => (
                <option key={p.id || p.project_id} value={p.id || p.project_id}>
                  {p.name}
                </option>
              ))}
              {projectId && !project && (
                <option value={projectId}>{projectId}</option>
              )}
            </select>
            <ChevronDown size={12} />
            {catalogError && (
              <button
                className="icon-button"
                onClick={projects.reload}
                aria-label="重试完整项目目录"
                title={catalogError.message}
              >
                <AlertCircle size={14} />
              </button>
            )}
          </div>
          <span className="topbar-divider" />
          <span className="topbar-context">{workspace.caption}</span>
          <button
            className="search-trigger"
            onClick={() => setSearchOpen(true)}
          >
            <Search size={15} />
            <span>搜索项目与当前任务</span>
            <kbd>/</kbd>
          </button>
          <button
            className="icon-button"
            title="命令面板 Ctrl / Cmd + K"
            aria-label="打开命令面板"
            onClick={() => setCommands(true)}
          >
            <Command size={17} />
          </button>
          <button
            className="icon-button"
            aria-label="切换主题"
            onClick={toggleTheme}
          >
            {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
          </button>
          <AppearanceButton/>
          <Link className="icon-button" aria-label={personal?'工作区与成员':'决策收件箱'} to={personal?'/workspaces':'/decisions'}>
            {personal?<Network size={17}/>:<Inbox size={17} />}
          </Link>
          <Link
            className="account-avatar"
            to={personal?'/workspaces':'/settings'}
            aria-label="访问身份设置"
          >
            {personal?String((identity.data?.account as Account)?.display_name||'F').slice(0,1):'F'}
          </Link>
        </header>
        <div className="context-strip">
          <div className="breadcrumbs">
            <Link to="/portfolio">工作空间</Link>
            <span>/</span>
            <span>
              {visibleProjectId
                ? project?.name || visibleProjectId
                : "全部项目"}
            </span>
            {visibleProjectId && (
              <>
                <span>/</span>
                <span className="mono">{visibleProjectId.slice(0, 12)}</span>
              </>
            )}
          </div>
          <div
            className="connection-state"
            role="status"
            title={
              events.lastEvent ? `最近事件 ${events.lastEvent}` : undefined
            }
          >
            <span
              className={
                events.status === "事件已连接"
                  ? "connection-dot connected"
                  : "connection-dot"
              }
            />
            {events.status}
          </div>
        </div>
        <main
          id="main-content"
          tabIndex={-1}
          className="page-content"
          key={authVersion}
        >
          {visibleProjectId && identity.data && (activeWorkspace === "mission" || planningWorkbenchEnabled()) && <EcpJourney projectId={visibleProjectId} />}
          <Suspense
            fallback={
              <div className="loading-state" role="status">
                正在打开工作区…
              </div>
            }
          >
            {((!getToken() && !identity.data) ||
              (identity.error instanceof ApiError &&
                identity.error.status === 401)) &&
            location.pathname !== "/settings" ? (
              <LoginPage />
            ) : (
              <Routes>
                <Route path="/workspaces" element={<WorkspacesPage/>}/>
                <Route path="/invite" element={<InvitePage/>}/>
                <Route path="/tutorial" element={<TutorialPage/>}/>
                <Route path="/projects/:projectId/agent-network" element={<ContextPage>{p=><AgentNetworkPage key={p.projectId} projectId={p.projectId}/>}</ContextPage>}/>
                <Route path="/conversations/:conversationId" element={<ContextPage>{p=><EcpHubPage conversationId={p.conversationId || ""} threadId={new URLSearchParams(location.search).get("thread") || ""}/>}</ContextPage>}/>
                <Route
                  path="/"
                  element={<Navigate to="/portfolio" replace />}
                />
                <Route path="/portfolio" element={<EcpPortfolioPage />} />
                <Route path="/flows" element={<FlowPage projectId={projectId} />} />
                <Route path="/projects/new" element={<ProjectNewPage />} />
                <Route
                  path="/projects/:projectId"
                  element={
                    <ContextPage>
                      {(p) => <ProjectPage projectId={p.projectId} />}
                    </ContextPage>
                  }
                />
                <Route
                  path="/projects/:projectId/requirements"
                  element={
                    <ContextPage>
                      {(p) => <RequirementsPage projectId={p.projectId} />}
                    </ContextPage>
                  }
                />
                <Route
                  path="/projects/:projectId/flows"
                  element={
                    <ContextPage>
                      {(p) => <EcpDagPage projectId={p.projectId} />}
                    </ContextPage>
                  }
                />
                <Route
                  path="/projects/:projectId/flows/:flowId"
                  element={
                    <ContextPage>
                      {(p) => (
                        <FlowPage projectId={p.projectId} flowId={p.flowId} />
                      )}
                    </ContextPage>
                  }
                />
                <Route
                  path="/projects/:projectId/tasks"
                  element={
                    <ContextPage>
                      {(p) => <TasksPage projectId={p.projectId} />}
                    </ContextPage>
                  }
                />
                <Route
                  path="/projects/:projectId/tasks/:taskId"
                  element={
                    <ContextPage>
                      {(p) => (
                        <TasksPage projectId={p.projectId} taskId={p.taskId} />
                      )}
                    </ContextPage>
                  }
                />
                <Route
                  path="/projects/:projectId/teams"
                  element={
                    <ContextPage>
                      {(p) => <TeamsPage projectId={p.projectId} />}
                    </ContextPage>
                  }
                />
                <Route
                  path="/projects/:projectId/contracts"
                  element={
                    <ContextPage>
                      {(p) => <ContractsPage projectId={p.projectId} />}
                    </ContextPage>
                  }
                />
                <Route
                  path="/projects/:projectId/evidence"
                  element={
                    <ContextPage>
                      {(p) => <EcpEvidencePage projectId={p.projectId} />}
                    </ContextPage>
                  }
                />
                <Route
                  path="/projects/:projectId/integration"
                  element={
                    <ContextPage>
                      {(p) => <IntegrationPage projectId={p.projectId} />}
                    </ContextPage>
                  }
                />
                <Route
                  path="/projects/:projectId/schedule"
                  element={
                    <ContextPage>
                      {(p) => <EcpGanttPage projectId={p.projectId} />}
                    </ContextPage>
                  }
                />
                <Route path="/projects/:projectId/releases" element={<ContextPage>{p => <EcpReleasePage projectId={p.projectId} />}</ContextPage>} />
                <Route path="/projects/:projectId/releases/:releaseId" element={<ContextPage>{p => <EcpReleasePage projectId={p.projectId} releaseId={p.releaseId} />}</ContextPage>} />
                <Route
                  path="/runs"
                  element={<EcpAgentTheaterPage projectId={projectId} />}
                />
                <Route
                  path="/runs/:attemptId"
                  element={
                    <ContextPage>
                      {(p) => (
                        <AttemptPage
                          attemptId={p.attemptId}
                          projectId={projectId}
                        />
                      )}
                    </ContextPage>
                  }
                />
                <Route path="/executors" element={<ExecutorsPage />} />
                <Route path="/executors/registry" element={<AgentRegistryPage />} />
                <Route path="/executors/bot" element={<EcpBotRoomPage />} />
                <Route
                  path="/checks"
                  element={<ChecksPage projectId={projectId} />}
                />
                <Route path="/resources" element={<ResourcePage />} />
                <Route
                  path="/calendar"
                  element={<EcpCalendarPage projectId={projectId} />}
                />
                <Route path="/recovery" element={<EcpMaintenancePage />} />
                <Route path="/decisions" element={<DecisionsPage />} />
                <Route
                  path="/settings"
                  element={personal?<Navigate to="/workspaces" replace/>:<SettingsPage projectId={projectId} />}
                />
                <Route
                  path="*"
                  element={
                    <EmptyState
                      title="页面不存在"
                      description="该地址未对应工作区页面。"
                      action={<Link to="/portfolio">返回项目组合</Link>}
                    />
                  }
                />
              </Routes>
            )}
          </Suspense>
        </main>
        <EventDock key={visibleProjectId || "global"} projectId={visibleProjectId} connectionStatus={events.status} />
        <footer className="statusbar">
          <span>
            <span className="status-square" /> ForgeFlow Control{" "}
            <span className="statusbar-version">/ v0.1</span>
          </span>
          <div>
            <Link to={personal?'/workspaces':'/executors'}>
              {personal?<Network size={12}/>:<Terminal size={12} />}
              {personal?'工作区':'执行器'}
            </Link>
            <Link to={personal?'/tutorial':'/recovery'}>
              {personal?<BookOpen size={12}/>:<RotateCcw size={12} />}
              {personal?'使用教程':'恢复台'}
            </Link>
            <span>{Intl.DateTimeFormat().resolvedOptions().timeZone}</span>
            <button
              onClick={() =>
                setDensity((d) => (d === "standard" ? "compact" : "standard"))
              }
            >
              {density === "standard" ? "标准密度" : "紧凑密度"}
            </button>
          </div>
        </footer>
      </div>
      {commands && (
        <Drawer animateClose title="前往工作区" onClose={() => setCommands(false)}>
          <p className="muted">选择目的地 · Ctrl / Cmd + K</p>
          <div className="command-list">
            {[
              ...groups.map((g) => ({
                label: g.label,
                path: groupPath(g),
                icon: g.icon,
              })),
              { label: "接入项目", path: "/projects/new", icon: Plus },
              { label: "日程与里程碑", path: "/calendar", icon: CalendarDays },
              ...(personal?[{label:'工作区与成员',path:'/workspaces',icon:Network},{label:'个人网站教程',path:'/tutorial',icon:BookOpen}]:[{ label: "执行器与通道", path: "/executors", icon: Terminal },{ label: "恢复与异常", path: "/recovery", icon: RotateCcw }]),
            ].map((g) => (
              <button
                key={g.label}
                onClick={() => {
                  navigate(g.path);
                  setCommands(false);
                }}
              >
                <g.icon size={17} />
                <span>{g.label}</span>
                <ArrowUpRight size={14} />
              </button>
            ))}
          </div>
        </Drawer>
      )}
      {searchOpen && (
        <Drawer animateClose title="搜索项目与当前任务" onClose={() => setSearchOpen(false)}>
          <p className="muted">搜索当前工作区的项目目录，以及当前项目的全部任务；任务结果最多显示 20 条。</p>
          <form
            className="search-form"
            onSubmit={(e) => {
              e.preventDefault();
              void runSearch();
            }}
          >
            <input
              ref={searchRef}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="输入项目或任务关键字"
              aria-label="搜索关键字"
            />
            <button
              className="primary"
              disabled={!search.trim() || searchLoading}
            >
              <Search size={15} />
              {searchLoading ? "搜索中" : "搜索"}
            </button>
          </form>
          {searchError && <ErrorNotice error={searchError} />}{" "}
          {searchResults !== undefined && (
            <SearchResults
              value={searchResults}
              onNavigate={(path) => {
                navigate(path);
                setSearchOpen(false);
              }}
            />
          )}
          <p className="muted">
            查询完整服务端对象集合，包含当前画布之外的记录。
          </p>
        </Drawer>
      )}
    </div>
  );
}
interface DockEvent { cursor: string; kind: string; objectId: string; receivedAt: string }
function EventDock({ projectId, connectionStatus }: { projectId?: string; connectionStatus: string }) {
  const [open, setOpen] = useState(false);
  const [height, setHeight] = useState(200);
  const [rows, setRows] = useState<DockEvent[]>([]);
  const [filter, setFilter] = useState("");
  const drag = useRef<{ pointerId: number; y: number; height: number } | undefined>(undefined);
  // The App owns the single connection. A collapsed Dock has no event listener.
  useEffect(() => {
    if (!open || !projectId) return;
    const receive = (event: Event) => {
      const detail = (event as CustomEvent<ControlEvent>).detail;
      if (!detail || detail.projectId !== projectId || !detail.cursor || !detail.kind) return;
      setRows((current) => current.some((row) => row.cursor === detail.cursor) ? current : [...current, {
        cursor: detail.cursor, kind: detail.kind, objectId: detail.objectId, receivedAt: new Date().toISOString(),
      }].slice(-200));
    };
    window.addEventListener("forgeflow-event", receive);
    return () => window.removeEventListener("forgeflow-event", receive);
  }, [open, projectId]);
  const resize = (value: number) => setHeight(Math.max(160, Math.min(320, value)));
  const move = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (drag.current?.pointerId === event.pointerId) resize(drag.current.height + drag.current.y - event.clientY);
  };
  const visible = rows.filter((row) => `${row.kind} ${row.objectId} ${row.cursor}`.toLocaleLowerCase().includes(filter.toLocaleLowerCase()));
  return <section className={`event-dock ${open ? "is-open" : ""}`} aria-label="项目事件控制台">
    {open && <div className="dock-resizer" role="separator" aria-label="调整事件控制台高度" aria-orientation="horizontal"
      aria-valuemin={160} aria-valuemax={320} aria-valuenow={height} tabIndex={0}
      onKeyDown={(event) => {
        if (event.key === "ArrowUp" || event.key === "ArrowDown" || event.key === "Home" || event.key === "End") {
          event.preventDefault(); resize(event.key === "Home" ? 160 : event.key === "End" ? 320 : height + (event.key === "ArrowUp" ? 16 : -16));
        }
      }} onPointerDown={(event) => {
        event.preventDefault(); drag.current = { pointerId: event.pointerId, y: event.clientY, height };
        event.currentTarget.setPointerCapture(event.pointerId);
      }} onPointerMove={move} onPointerUp={(event) => {
        drag.current = undefined;
        if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
      }} onPointerCancel={() => { drag.current = undefined; }}><span /></div>}
    <div className="dock-header">
      <button aria-expanded={open} aria-controls="event-dock-body" onClick={() => setOpen((value) => !value)}><Terminal size={14} />事件控制台{open ? <ChevronDown size={13} /> : <ChevronUp size={13} />}</button>
      <span className="dock-connection" title={projectId || "未选择项目"}>{connectionStatus}</span>
      {open && <button className="dock-clear" disabled={!rows.length} onClick={() => setRows([])}>清空显示</button>}
    </div>
    {open && <div id="event-dock-body" className="dock-body" style={{ height }}>
      <div className="dock-toolbar"><input type="search" aria-label="过滤已接收事件" placeholder="过滤事件类型、对象或 cursor…" value={filter} onChange={(event) => setFilter(event.target.value)} /><span>{visible.length}/{rows.length} · 最多200条</span></div>
      <div className="dock-event-list" tabIndex={0} role="region" aria-label="已接收项目事件">
        {!projectId ? <p className="dock-empty">选择项目后订阅其真实事件。</p> : !rows.length ? <p className="dock-empty">展开期间尚未收到项目事件。历史日志请进入执行详情。</p> : !visible.length ? <p className="dock-empty">已接收事件中没有匹配项。</p> : visible.map((row) => <div className="dock-event" key={row.cursor}><time dateTime={row.receivedAt} title={row.receivedAt}>{new Date(row.receivedAt).toLocaleTimeString()}</time><span>{row.kind}</span><code title={row.objectId}>{row.objectId}</code><code title={row.cursor}>{row.cursor}</code></div>)}
      </div>
    </div>}
  </section>;
}
function SearchResults({
  value,
  onNavigate,
}: {
  value: unknown;
  onNavigate: (path: string) => void;
}) {
  const list = Array.isArray(value)
    ? value
    : typeof value === "object" && value && "items" in value
      ? (value as { items: unknown[] }).items
      : [];
  if (list.length === 0) return <EmptyState title="没有匹配对象" />;
  return (
    <div className="command-list">
      {typeof value==='object'&&value&&'total_count' in value&&<p className="muted">共匹配 {String(value.total_count)} 项 · 显示 {list.length} 项</p>}
      {list.map((raw, i) => {
        const row = raw as Record<string, unknown>;
        const path =
          typeof row.url === "string"
            ? row.url
            : typeof row.path === "string"
              ? row.path
              : undefined;
        return path ? (
          <button key={i} onClick={() => onNavigate(path)}>
            <span>{String(row.title || row.name || row.id)}</span>
            <ArrowUpRight size={14} />
          </button>
        ) : (
          <div className="search-result" key={i}>
            {String(row.title || row.name || row.id)}
            <small>{String(row.project_id || row.object_type || "")}</small>
          </div>
        );
      })}
    </div>
  );
}
