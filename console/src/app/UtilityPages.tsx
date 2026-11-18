import { useState } from "react";
import {
  KeyRound,
  RefreshCw,
  ArrowRight,
  Layers3,
  Eye,
  EyeOff,
  ChevronDown,
  LockKeyhole,
} from "lucide-react";
import { api, getToken, setToken, useApi, validateToken } from "./api";
import { ExecutorSettings } from "./ExecutorSettings";
import { BackupsPanel } from "./MaintenancePages";
import {AppearanceControls} from './AppearanceControls';
import {ThemeScene} from '../components/ThemeScene';
import {
  PageHeader,
  Panel,
  Field,
  QueryState,
  JsonView,
  ErrorNotice,
  SourceStamp,
} from "../components";
export function SettingsPage({
  projectId,
}: {
  projectId?: string;
}) {
  const info = useApi<Record<string, unknown>>("/system/info");
  const [token, changeToken] = useState(getToken());
  const [saved, setSaved] = useState(false);
  const [password, setPassword] = useState("");
  const [authError, setAuthError] = useState<Error>();
  const [authBusy, setAuthBusy] = useState(false);
  async function login() {
    setAuthBusy(true);
    setAuthError(undefined);
    try {
      const session = await api.post<{token:string}>("/session",{password});
      setToken(session.token);
      changeToken(session.token);
      setPassword("");
      setSaved(true);
    } catch (e) {
      setAuthError(e as Error);
    } finally {
      setAuthBusy(false);
    }
  }
  async function logout() {
    setAuthBusy(true);
    setAuthError(undefined);
    try {
      await api.post("/logout", {});
      setToken("");
      changeToken("");
      setSaved(false);
    } catch (e) {
      setAuthError(e as Error);
    } finally {
      setAuthBusy(false);
    }
  }
  async function applyToken() {
    setAuthBusy(true);
    setAuthError(undefined);
    try {
      await validateToken(token.trim());
      setToken(token.trim());
      setSaved(true);
    } catch (e) {
      setAuthError(e as Error);
    } finally {
      setAuthBusy(false);
    }
  }
  return (
    <>
      <PageHeader
        title="设置与交付"
        description="管理本地访问、显示偏好与可追溯的系统交付。"
      />
      <div className="settings-grid">
        <Panel title="访问身份">
          <div className="panel-body">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void login();
              }}
            >
              <Field label="负责人密码">
                <input
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="输入部署时设置的密码"
                />
              </Field>
              <div className="toolbar">
                <button className="primary" disabled={authBusy || !password}>
                  登录工作空间
                </button>
                <button
                  type="button"
                  disabled={authBusy || !getToken()}
                  onClick={() => void logout()}
                >
                  退出会话
                </button>
              </div>
            </form>
            {authError && <ErrorNotice error={authError} />}
          </div>
          <form
            className="panel-body"
            onSubmit={(e) => {
              e.preventDefault();
              void applyToken();
            }}
          >
            <p className="muted">
              使用部署时配置的负责人访问令牌。凭据只保留在当前浏览器会话。
            </p>
            <Field label="负责人访问令牌">
              <input
                type="password"
                value={token}
                onChange={(e) => {
                  changeToken(e.target.value);
                  setSaved(false);
                }}
                autoComplete="off"
                placeholder="输入访问令牌"
              />
            </Field>
            <button
              className="primary"
              type="submit"
              disabled={authBusy || !token.trim()}
            >
              <KeyRound size={15} />
              应用访问令牌
            </button>
            {saved && (
              <p role="status" className="muted">
                访问身份已通过控制服务验证。
              </p>
            )}
          </form>
        </Panel>
        <Panel title="工作区偏好">
          <div className="panel-body">
            <AppearanceControls/>
            <div className="preference-row">
              <div>
                <strong>默认时区</strong>
                <p className="muted">Asia/Shanghai · UTC+08:00</p>
              </div>
            </div>
            <p className="muted">
              快捷键：Ctrl / Cmd + K 打开导航；/ 全局搜索；Esc 关闭抽屉。
            </p>
          </div>
        </Panel>
      </div>
      <ExecutorSettings />
      <Panel
        title="系统信息"
        actions={
          <button onClick={info.reload}>
            <RefreshCw size={14} />
            刷新
          </button>
        }
      >
        <QueryState
          loading={info.loading}
          error={info.error}
          onRetry={info.reload}
        >
          <JsonView value={info.data} />
        </QueryState>
        <SourceStamp
          source={info.metadata.source}
          observedAt={info.metadata.observed_at}
        />
      </Panel>
      <BackupsPanel projectId={projectId} />
    </>
  );
}
export { RecoveryPage } from './MaintenancePages';
export { DecisionsPage } from './DecisionsPage';

export function LoginPage() {
  const [registering, setRegistering] = useState(false);
  const [legacy, setLegacy] = useState(false);
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [token, setAccessToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error>();
  async function login() {
    setBusy(true);
    setError(undefined);
    try {
      const session = await api.post<{token:string;account?:unknown}>(registering?"/registrations":"/session",registering?{email,display_name:displayName,password}:{password,...(!legacy?{email}:{})});
      setToken(session.token,!!session.account);
    } catch (e) {
      setError(e as Error);
    } finally {
      setBusy(false);
    }
  }
  async function tokenLogin() {
    setBusy(true);
    setError(undefined);
    try {
      const identity = await validateToken(token) as {role?:string};
      setToken(token, identity.role === "account");
    } catch (e) {
      setError(e as Error);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="login-workspace">
      <div className="login-intro">
        <span className="login-eyebrow"><span /> BUILT FOR YOUR NEXT IDEA</span>
        <h1>
          让想法，
          <br />
          有序发生。
        </h1>
        <p>
          连接需求、团队与每一次交付。
          <br />
          在一个安静、清晰的工作空间里，专注创造。
        </p>
        <div className="login-flow" aria-label="工作流程：需求、Flow、交付">
          <div><span>01</span><strong>需求</strong></div><ArrowRight size={20} strokeWidth={1.4} />
          <div><span>02</span><strong>Flow</strong></div><ArrowRight size={20} strokeWidth={1.4} />
          <div><span>03</span><strong>交付</strong></div>
        </div>
        <ThemeScene/>
        <div className="login-detail">
          <span>本地部署</span>
          <span>明确权限</span>
          <span>完整溯源</span>
        </div>
      </div>
      <Panel className="login-card">
        <div className="login-card-heading">
          <span className="login-card-icon"><Layers3 size={24} strokeWidth={1.5} /></span>
          <p className="login-card-eyebrow">WELCOME BACK</p>
          <h2>{registering ? "创建个人账号" : legacy ? "管理员登录" : "欢迎回到 ForgeFlow"}</h2>
          <p>{registering ? "建立自己的工作区，邀请人与 Agent 一起协作。" : "一个账号，连接你参与的工作区。"}</p>
          <div className="account-tabs" role="group" aria-label="账号入口">{[false,true].map(value => <button key={String(value)} type="button" aria-pressed={registering===value && !legacy} onClick={() => {setRegistering(value);setLegacy(false);setError(undefined);}}>{value ? "注册账号" : "登录"}</button>)}</div>
        </div>
        <form
          className="panel-body"
          onSubmit={(e) => {
            e.preventDefault();
            void login();
          }}
        >
          {registering && <Field label="你的名字"><input required maxLength={80} autoComplete="name" value={displayName} onChange={e => setDisplayName(e.target.value)} placeholder="协作者如何称呼你" /></Field>}
          {!legacy && <Field label="邮箱"><input required type="email" autoComplete="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="you@example.com" /></Field>}
          <Field label={legacy ? "管理员密码" : "密码"}>
            <div className="login-password">
            <input
              type={showPassword ? "text" : "password"}
              autoComplete={registering ? "new-password" : "current-password"}
              aria-label={legacy ? "管理员密码" : "密码"}
              minLength={registering ? 12 : undefined}
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={registering ? "设置至少 12 位密码" : "输入密码"}
              aria-describedby="login-password-description"
            />
            <button type="button" className="login-reveal" onClick={() => setShowPassword(!showPassword)} aria-label={showPassword ? "隐藏密码" : "显示密码"} aria-pressed={showPassword}>
              {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
            </button>
            </div>
            <small id="login-password-description">{registering ? "至少 12 个字符；注册后自动建立独立工作区。" : legacy ? "这是安装 ForgeFlow 时设置的管理员密码。" : "使用你的个人账号密码。"}</small>
          </Field>
          <button className="primary login-submit" disabled={busy || !password}>
            <span>{busy ? (registering ? "正在创建…" : "正在登录…") : registering ? "创建账号与工作区" : "进入工作区"}</span><ArrowRight size={18} />
          </button>
          {error && <ErrorNotice error={error} />}
          <a className="tutorial-entry" href="/tutorial">先看教程：和 Agent 团队制作个人网站 <ArrowRight size={14} /></a>
          <details className="login-help">
            <summary>账号与邀请说明<ChevronDown size={14} /></summary>
            <p>注册后可以自建工作区，也可打开协作者的邀请链接加入。邀请链接仅供可信协作者使用。此版本不通过邮件发送邀请或重置密码；管理员可使用原有部署凭据登录。</p>
          </details>
        </form>
        <details className="login-service">
          <summary>高级登录方式<ChevronDown size={14} /></summary>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void tokenLogin();
            }}
          >
            <button type="button" onClick={() => {setLegacy(true);setRegistering(false);setError(undefined);}}>使用部署管理员密码</button>
            <p className="login-token-description">已有 ForgeFlow 访问令牌时，也可以用它登录。令牌由部署者提供，权限由对应身份决定；通常使用上方密码即可。</p>
            <Field label="ForgeFlow 访问令牌">
              <input
                type="password"
                autoComplete="off"
                value={token}
                onChange={(e) => setAccessToken(e.target.value)}
                placeholder="输入 ForgeFlow 令牌"
              />
            </Field>
            <button className="login-token-submit" disabled={busy || !token}>{busy ? "正在验证…" : "使用令牌登录"}</button>
          </form>
        </details>
        <p className="login-privacy"><LockKeyhole size={13} />登录凭据仅保留在当前浏览器会话</p>
      </Panel>
    </div>
  );
}
