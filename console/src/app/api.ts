import { useCallback, useEffect, useLayoutEffect, useState, useSyncExternalStore } from "react";
import { useSearchParams } from "react-router-dom";
import { QueryCache, type QuerySnapshot } from "./query-cache";
import type { ApiEnvelope, QueryMetadata } from "./types";
import type { ControlEvent, ControlResync } from "./events";
const TOKEN_KEY = "forgeflow.owner-token";
export function getAuthScope() {
  let scope = sessionStorage.getItem("forgeflow.auth-scope");
  if (!scope) { scope = crypto.randomUUID(); sessionStorage.setItem("forgeflow.auth-scope", scope); }
  return scope;
}
/** Drafts belong to the signed-in identity and survive query/workspace changes. */
export function getDraftScope() {
  let scope=sessionStorage.getItem('forgeflow.draft-scope');
  if(!scope){scope=getAuthScope();sessionStorage.setItem('forgeflow.draft-scope',scope);}
  return scope;
}
export function getToken() {
  return sessionStorage.getItem(TOKEN_KEY) || "";
}
export function isPersonalAccount() { return sessionStorage.getItem("forgeflow.personal-account") === "1"; }
export function getWorkspace() { return sessionStorage.getItem("forgeflow.workspace") || ""; }
export function workspaceWritable() { return !isPersonalAccount() || (!!getWorkspace()&&['OWNER','EDITOR'].includes(sessionStorage.getItem("forgeflow.workspace-role")||'')); }
export function useWorkspaceWritable() {
  return useSyncExternalStore(notify=>{
    window.addEventListener('forgeflow-permissions',notify);window.addEventListener('forgeflow-auth',notify);
    return()=>{window.removeEventListener('forgeflow-permissions',notify);window.removeEventListener('forgeflow-auth',notify);};
  },workspaceWritable,workspaceWritable);
}
export function setWorkspace(id: string, role?: string) {
  const previous=getWorkspace();
  const oldRole=sessionStorage.getItem('forgeflow.workspace-role');
  const nextRole=id?(role??(previous===id?oldRole:null)):null;
  const verifiedRole=nextRole&&['OWNER','EDITOR','VIEWER'].includes(nextRole)?nextRole:null;
  if(previous===id&&oldRole===verifiedRole)return;
  // Seed the stable namespace before rotating the query namespace, including
  // an existing tab that upgrades with pre-existing local drafts.
  getDraftScope();
  if(id)sessionStorage.setItem("forgeflow.workspace", id);
  else sessionStorage.removeItem('forgeflow.workspace');
  if(verifiedRole)sessionStorage.setItem("forgeflow.workspace-role", verifiedRole);
  else sessionStorage.removeItem('forgeflow.workspace-role');
  if(previous===id){window.dispatchEvent(new Event('forgeflow-permissions'));return;}
  localStorage.removeItem("forgeflow.project");
  sessionStorage.setItem("forgeflow.auth-scope", crypto.randomUUID());
  window.dispatchEvent(new Event("forgeflow-auth"));
}
export function setToken(token: string, personal = false) {
  sessionStorage.removeItem('forgeflow.csrf');
  sessionStorage.removeItem("forgeflow.workspace");
  sessionStorage.removeItem("forgeflow.workspace-role");
  if (personal) sessionStorage.setItem("forgeflow.personal-account", "1");
  else sessionStorage.removeItem("forgeflow.personal-account");
  const scope=crypto.randomUUID();
  sessionStorage.setItem("forgeflow.auth-scope", scope);
  sessionStorage.setItem('forgeflow.draft-scope',scope);
  localStorage.removeItem('forgeflow.project');
  if (token) sessionStorage.setItem(TOKEN_KEY, token);
  else sessionStorage.removeItem(TOKEN_KEY);
  window.dispatchEvent(new Event("forgeflow-auth"));
}
/** Rotate this account's credential while retaining its workspace and drafts. */
export function renewAccountSession(token:string) {
  sessionStorage.setItem(TOKEN_KEY,token);sessionStorage.removeItem('forgeflow.csrf');
  authGeneration++;queryCache.clear();
  window.dispatchEvent(new Event('forgeflow-session-renewed'));
}
export async function validateToken(token: string) {
  const response = await fetch(apiUrl("/me"), {
    credentials: "omit",
    headers: { Accept: "application/json", Authorization: `Bearer ${token}` },
  });
  let body: Record<string, unknown>;
  try {
    body = await response.json();
  } catch {
    throw new ApiError(response.status, {
      code: "INVALID_RESPONSE",
      message: "控制服务未返回有效身份验证响应。",
    });
  }
  if (!response.ok) throw new ApiError(response.status, body);
  return body.data;
}
export class ApiError extends Error {
  code: string;
  status: number;
  requestId?: string;
  objectId?: string;
  remediation?: string;
  details?: unknown;
  constructor(status: number, body: Record<string, unknown>) {
    super(String(body.message || `请求失败 (${status})`));
    this.name = "ApiError";
    this.status = status;
    this.code = String(body.code || "HTTP_ERROR");
    this.requestId = body.request_id as string;
    this.objectId = body.object_id as string;
    this.remediation = body.remediation as string;
    this.details = body.details;
  }
}
export interface CommandOptions {
  expectedRevision?: number;
  idempotencyKey?: string;
  signal?: AbortSignal;
}
export function apiUrl(path: string) {
  return path.startsWith("/api/v1")
    ? path
    : `/api/v1${path.startsWith("/") ? path : `/${path}`}`;
}
async function request<T>(
  path: string,
  method: string,
  body?: unknown,
  options: CommandOptions = {},
): Promise<ApiEnvelope<T>> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const token = getToken();
  const generation=authGeneration;
  const identityScope=getDraftScope();
  if (token) headers.Authorization = `Bearer ${token}`;
  const workspace = getWorkspace();
  if (workspace) headers["X-ForgeFlow-Workspace"] = workspace;
  if (method !== "GET") {
    const csrf=sessionStorage.getItem('forgeflow.csrf');if(csrf)headers['X-CSRF-Token']=csrf;
    headers["Content-Type"] = "application/json";
    headers["Idempotency-Key"] = options.idempotencyKey || crypto.randomUUID();
  }
  if (options.expectedRevision !== undefined)
    headers["If-Match"] = String(options.expectedRevision);
  let payload = body;
  if (
    options.expectedRevision !== undefined &&
    body &&
    typeof body === "object" &&
    !Array.isArray(body)
  )
    payload = { ...body, expected_revision: options.expectedRevision };
  const response = await fetch(apiUrl(path), {
    method,
    headers,
    body: payload === undefined ? undefined : JSON.stringify(payload),
    signal: options.signal,
  });
  const text = await response.text();
  // A command may have committed in its original workspace. Its late response
  // must not continue a multi-step action or invalidate the new context.
  const accountCredential=method==='POST'&&apiUrl(path)==='/api/v1/account/password';
  if(token!==getToken() || identityScope!==getDraftScope() ||
    (!accountCredential&&(generation!==authGeneration || workspace!==getWorkspace())))
    throw new ApiError(0,{code:'REQUEST_CONTEXT_CHANGED',message:'账号或工作区已切换，请回到原工作区确认操作结果。'});
  let parsed: unknown;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    throw new ApiError(response.status, {
      code:
        response.status === 404
          ? "ENDPOINT_UNAVAILABLE"
          : response.status >= 500
            ? "CONTROL_SERVICE_UNAVAILABLE"
            : "INVALID_RESPONSE",
      message:
        response.status === 404
          ? "控制服务尚未提供此接口 (404)。"
          : response.status >= 500
            ? `控制服务暂时不可用 (${response.status})。请检查服务是否启动。`
            : "服务未返回有效 JSON。请检查 API 地址及反向代理配置。",
    });
  }
  if (
    response.status === 401 &&
    getToken() &&
    getToken() === token &&
    !(parsed && typeof parsed==='object' && 'code' in parsed && parsed.code==='INVALID_CREDENTIALS') &&
    !apiUrl(path).endsWith("/session")
  )
    setToken("");
  if(response.status===403 && isPersonalAccount() && getToken()===token && getWorkspace()===workspace && !['/me','/workspaces'].includes(path))
    window.dispatchEvent(new Event('forgeflow-membership-stale'));
  if (!response.ok)
    throw new ApiError(
      response.status,
      (parsed && typeof parsed === "object"
        ? parsed
        : {
            code:
              response.status >= 500
                ? "CONTROL_SERVICE_UNAVAILABLE"
                : "HTTP_ERROR",
            message:
              response.status >= 500
                ? `控制服务暂时不可用 (${response.status})。请检查服务是否启动。`
                : `请求失败 (${response.status})：${response.statusText}`,
          }) as Record<string, unknown>,
    );
  if (method !== "GET" && !/\/(session|registrations|account\/password|planning-scenarios|flow-checks|admission-checks)$/.test(apiUrl(path))) {
    const full=apiUrl(path);
    const network=full.match(/^(\/api\/v1\/projects\/[^/?]+\/agent-network)\/(agents|integrations|messages)(?:\/|$)/);
    if(network) {
      // Communication does not change tasks, schedules or execution authority.
      // Message and receipt polling refresh their own bounded log.
      if(network[2]!=='messages')queryCache.invalidate(key=>{
        const resource=keyPath(key).split('?')[0];
        return resource===`${network[1]}/${network[2]}` || (full.endsWith('/revoke')&&resource===`${network[1]}/agents`);
      });
    } else {
      const project = full.match(/^\/api\/v1\/projects\/([^/?]+)/)?.[1];
      invalidateProject(project ? decodeURIComponent(project) : undefined);
    }
  }
  if (apiUrl(path)==='/api/v1/me' && parsed && typeof parsed==='object' && 'data' in parsed && getToken()===token) {
    const identity=(parsed as ApiEnvelope<{csrf_token?:string;role?:string}>).data;
    if(identity?.csrf_token)sessionStorage.setItem('forgeflow.csrf',identity.csrf_token);
    if(identity?.role==='account')sessionStorage.setItem('forgeflow.personal-account','1');
  }
  if (parsed && typeof parsed === "object" && "data" in parsed)
    return parsed as ApiEnvelope<T>;
  return { data: parsed as T };
}
async function collect<T>(
  path: string,
  signal?: AbortSignal,
): Promise<ApiEnvelope<T[]>> {
  const records: T[] = [];
  const seen = new Set<string>();
  let cursor: string | null | undefined;
  let version: number | null | undefined;
  let last: QueryMetadata = {};
  for (let page = 0; page < 10000; page++) {
    const url = new URL(apiUrl(path), window.location.origin);
    if (!url.searchParams.has("limit")) url.searchParams.set("limit", "500");
    if (cursor) url.searchParams.set("cursor", cursor);
    else url.searchParams.delete("cursor");
    const { data, ...metadata } = await request<T[]>(
      url.pathname + url.search,
      "GET",
      undefined,
      { signal },
    );
    if (!Array.isArray(data))
      throw new ApiError(0, {
        code: "COLLECTION_REQUIRED",
        message: "分页集合接口未返回列表。",
      });
    if (!("next_cursor" in metadata))
      throw new ApiError(0, {
        code: "CURSOR_CONTRACT_MISSING",
        message: "控制服务未返回分页边界，无法确认完整集合。",
      });
    if (
      version !== undefined &&
      version !== null &&
      metadata.read_model_version !== undefined &&
      metadata.read_model_version !== null &&
      metadata.read_model_version !== version
    )
      throw new ApiError(409, {
        code: "SNAPSHOT_CHANGED",
        message: "读取分页期间项目版本发生变化，请重新读取完整集合。",
      });
    if (records.length + data.length > 100000)
      throw new ApiError(0, {
        code: "COLLECTION_TOO_LARGE",
        message:
          "集合超过客户端完整读取预算，未返回截断集合。请使用服务端范围快照。",
      });
    version ??= metadata.read_model_version;
    records.push(...data);
    last = metadata;
    cursor = metadata.next_cursor;
    if (!cursor) return { data: records, ...last, next_cursor: null };
    if (seen.has(cursor))
      throw new ApiError(0, {
        code: "INVALID_CURSOR",
        message: "控制服务返回重复分页游标，未把不完整集合标记为完整。",
      });
    seen.add(cursor);
  }
  throw new ApiError(0, {
    code: "COLLECTION_LIMIT",
    message:
      "分页数量超出客户端保护范围，未返回截断集合。请缩小查询或使用服务端快照。",
  });
}
export const api = {
  collect,
  raw: <T>(path: string, signal?: AbortSignal) =>
    request<T>(path, "GET", undefined, { signal }),
  get: async <T>(path: string, signal?: AbortSignal) =>
    (await request<T>(path, "GET", undefined, { signal })).data,
  post: async <T>(
    path: string,
    body: unknown = {},
    options: CommandOptions = {},
  ) => (await request<T>(path, "POST", body, options)).data,
  patch: async <T>(
    path: string,
    body: unknown = {},
    options: CommandOptions = {},
  ) => (await request<T>(path, "PATCH", body, options)).data,
};
let authGeneration = 0;
const queryCache = new QueryCache<ApiEnvelope<unknown>>((key, signal) => {
  const [, mode, ...parts] = key.split("\n");
  const path = parts.join("\n");
  return mode === "complete" ? collect(path, signal) : request(path, "GET", undefined, { signal });
});
const emptySnapshot: QuerySnapshot<ApiEnvelope<unknown>> = { loading: false };
const emptyMetadata: QueryMetadata = {};
function canonicalPath(path: string) {
  const url = new URL(apiUrl(path), window.location.origin);
  url.searchParams.sort();
  return url.pathname + url.search;
}
function keyPath(key: string) { return key.split("\n").slice(2).join("\n"); }
window.addEventListener("forgeflow-auth", () => { authGeneration++; queryCache.clear(); });
let eventTimer: ReturnType<typeof setTimeout> | undefined;
const pendingEvents = new Map<string, ControlEvent>();
window.addEventListener("forgeflow-event", event => {
  const detail = (event as CustomEvent<ControlEvent>).detail;
  if (!detail?.projectId) return;
  pendingEvents.set(`${detail.projectId}:${detail.kind}`, detail);
  if (eventTimer !== undefined) return;
  eventTimer = setTimeout(() => {
    const changes = [...pendingEvents.values()]; pendingEvents.clear(); eventTimer = undefined;
    queryCache.invalidate(key => changes.some(change => queryAffected(keyPath(key), change)));
  }, 180);
});
window.addEventListener("forgeflow-resync", event => {
  const detail = (event as CustomEvent<ControlResync>).detail;
  if (detail?.projectId) invalidateProject(detail.projectId);
});
function invalidateProject(projectId?: string) {
  const base = projectId ? `/api/v1/projects/${encodeURIComponent(projectId)}` : undefined;
  queryCache.invalidate(key => {
    const path = keyPath(key).split("?")[0];
    return !base || path === base || path.startsWith(`${base}/`) ||
      path.startsWith(`/api/v1/flows/${encodeURIComponent(projectId! + ":")}`) ||
      ["/api/v1/projects", "/api/v1/portfolio", "/api/v1/resources", "/api/v1/resource-usage"].includes(path);
  });
}
/** Shared, identity-scoped reads preserve old data while refresh is pending. */
export function useSharedApi<T>(path: string | null, complete = false) {
  const [identity, setIdentity] = useState(authGeneration);
  useEffect(() => {
    const change = () => setIdentity(authGeneration);
    window.addEventListener("forgeflow-auth", change);
    window.addEventListener('forgeflow-session-renewed',change);
    return () => {window.removeEventListener("forgeflow-auth", change);window.removeEventListener('forgeflow-session-renewed',change);};
  }, []);
  const key = path ? `${identity}\n${complete ? "complete" : "read"}\n${canonicalPath(path)}` : null;
  const subscribe = useCallback((notify: () => void) => key ? queryCache.subscribe(key, notify) : () => {}, [key]);
  const getSnapshot = useCallback(() => key ? queryCache.get(key) : emptySnapshot, [key]);
  const snapshot = useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
  // Start network I/O before first paint/layout; fresh cache entries still reuse TTL.
  useLayoutEffect(() => { if (key) queryCache.ensure(key); }, [key]);
  const reload = useCallback(() => { if (key) queryCache.invalidate(candidate => candidate === key); }, [key]);
  const envelope = ("data" in snapshot ? snapshot.data : undefined) as ApiEnvelope<T> | undefined;
  return { data: envelope?.data, error: "error" in snapshot ? snapshot.error : undefined,
    loading: snapshot.loading, refreshing: snapshot.loading && !!envelope,
    reload, updatedAt: envelope?.observed_at ?? ("updatedAt" in snapshot ? snapshot.updatedAt : undefined),
    metadata: envelope ?? emptyMetadata };
}
export function useApi<T>(path: string | null) { return useSharedApi<T>(path); }
function queryAffected(path: string, event: ControlEvent) {
  const full = apiUrl(path).split("?")[0];
  const base = `/api/v1/projects/${encodeURIComponent(event.projectId)}`;
  if (full === "/api/v1/projects") return !!event.kind?.startsWith("project.");
  if (["/api/v1/resources", "/api/v1/resource-usage", "/api/v1/portfolio"].includes(full)) return !/heartbeat|stdout|stderr|token_delta/.test(event.kind ?? "");
  if (full.startsWith(`/api/v1/flows/${encodeURIComponent(event.projectId + ":")}`)) return /^(flow|task|requirement|owner|team|contract|source|input|document)\./.test(event.kind ?? "");
  if (full !== base && !full.startsWith(`${base}/`)) return false;
  const kind = event.kind;
  if (!kind) return true;
  if (
    /heartbeat|(?:\.|_)(?:stdout|stderr|token_delta|log)(?:\.|_|$)|^tool\./.test(
      kind,
    )
  )
    return false;
  const family = full.slice(base.length + 1).split("/")[0];
  const collection =
    event.payload && typeof event.payload === "object"
      ? (event.payload as Record<string, unknown>).collection
      : undefined;
  if (!family) return kind.startsWith("project.");
  if (["snapshot", "planning-overview", "planning-inputs", "assignment-context"].includes(family)) return true;
  if (family === "requirements")
    return /^requirements?\.|^requirements\.imported|^source\./.test(kind);
  if (family === "sources")
    return (
      /^source\.|^requirements\.imported/.test(kind) ||
      (kind === "document.updated" && collection === "sources")
    );
  if (family === "flows")
    return (
      /^flow\.|^task\.|^requirements?\.|^owner\.|^team\.|^contract\.|^source\./.test(
        kind,
      ) ||
      (kind === "document.updated" &&
        ["sources", "contracts", "contract_versions", "flow_contexts"].includes(
          String(collection),
        ))
    );
  if (family === "tasks")
    return /^task\.|^flow\.|^attempt\.|^execution\.|^merge\.|^requirements?\.|^contract\./.test(
      kind,
    );
  if (family === "teams")
    return /^team\.|^owner\.|^resource_policy\./.test(kind);
  if (family === "resources")
    return /^resource_policy\.|^attempt\.|^lease\.|^team\.|^merge\./.test(kind);
  if (family === "attempts")
    return /^attempt\.|^execution\.|^process\.|^session\.|^merge\.|^worker\./.test(
      kind,
    );
  if (family === "evidence")
    return /^evidence\.|^verification\.|^merge\.|^contract\./.test(kind);
  if (family === "contracts")
    return (
      /^contract\./.test(kind) ||
      (kind === "document.updated" &&
        ["contracts", "contract_versions"].includes(String(collection)))
    );
  if (family === "schedule" || family === "milestones")
    return (
      /^schedule\.|^milestone\./.test(kind) ||
      (kind === "document.updated" &&
        ["schedules", "milestones"].includes(String(collection)))
    );
  if (family === "documents")
    return (
      kind === "document.updated" &&
      collection === full.slice(base.length + 1).split("/")[1]
    );
  return true;
}
export function items<T>(
  data: T[] | { items?: T[]; data?: T[] } | undefined,
): T[] {
  return Array.isArray(data) ? data : data?.items || data?.data || [];
}
export interface CursorApiControls {
  nextPage: () => void;
  previousPage: () => void;
  firstPage: () => void;
  hasNext: boolean;
  hasPrevious: boolean;
  page?: number;
  loading: boolean;
  error?: unknown;
}
export function useCursorApi<T>(path: string | null, cursorKey = "cursor") {
  const [params, setParams] = useSearchParams();
  const cursor = params.get(cursorKey);
  const [history, setHistory] = useState<{
    path: string | null;
    cursors: (string | null)[];
  }>({ path, cursors: [cursor] });
  useEffect(() => {
    if (history.path !== path) {
      setHistory({ path, cursors: [null] });
      setParams(
        (previous) => {
          const next = new URLSearchParams(previous);
          next.delete(cursorKey);
          return next;
        },
        { replace: true },
      );
    }
  }, [path, history.path, cursorKey, setParams]);
  const url = path ? new URL(apiUrl(path), window.location.origin) : undefined;
  if (url) {
    if (cursor && history.path === path) url.searchParams.set("cursor", cursor);
    else url.searchParams.delete("cursor");
  }
  const query = useApi<T>(url ? url.pathname + url.search : null);
  const index = history.path === path ? history.cursors.indexOf(cursor) : -1;
  function navigate(next: string | null) {
    setParams((previous) => {
      const updated = new URLSearchParams(previous);
      if (next) updated.set(cursorKey, next);
      else updated.delete(cursorKey);
      return updated;
    });
  }
  function nextPage() {
    const next = query.metadata.next_cursor;
    if (!next) return;
    setHistory((previous) => {
      const at = previous.path === path ? previous.cursors.indexOf(cursor) : -1;
      return {
        path,
        cursors:
          at >= 0
            ? [...previous.cursors.slice(0, at + 1), next]
            : [cursor, next],
      };
    });
    navigate(next);
  }
  function previousPage() {
    if (index > 0) navigate(history.cursors[index - 1]);
  }
  function firstPage() {
    setHistory({ path, cursors: [null] });
    navigate(null);
  }
  return {
    ...query,
    nextPage,
    previousPage,
    firstPage,
    hasNext: !!query.metadata.next_cursor,
    hasPrevious: index > 0,
    page: index >= 0 && history.cursors[0] === null ? index + 1 : undefined,
  };
}
