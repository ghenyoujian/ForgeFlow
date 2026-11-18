import { useEffect, useState } from "react";
import { api, apiUrl, getToken } from "../../app/api";
import type { ControlResync } from "../../app/events";
import { object, num, str, type Row } from "../portfolio/monitor";
type StreamState = {
  events: Row[];
  cursor: number;
  connected: boolean;
  error?: string;
  observedAt?: string;
  notice?: string;
  cacheNotice?: string;
};
const CACHE_BYTES = 256 * 1024;
const MAX_EVENTS = 1000;
const BATCH_SIZE = 50;
const CACHE_NOTICE = "仅显示最近事件，显示缓存预算为 256 KiB / 1,000 条；较早记录未完整显示，完整原文保留在服务端。";
export function useProjectEvents(projectId?: string) {
  const [state, setState] = useState<StreamState>({
    events: [],
    cursor: 0,
    connected: false,
  });
  useEffect(() => {
    if (!projectId) {
      setState({ events: [], cursor: 0, connected: false });
      return;
    }
    const storageKey = `forgeflow.events.${projectId}`;
    let cached: StreamState = { events: [], cursor: 0, connected: false };
    try {
      const value = JSON.parse(sessionStorage.getItem(storageKey) ?? "null");
      if (
        value &&
        Array.isArray(value.events) &&
        Number.isSafeInteger(value.cursor) &&
        value.cursor >= 0
      )
        cached = {
          events: value.events,
          cursor: value.cursor,
          connected: false,
          notice: typeof value.notice === "string" ? value.notice : undefined,
          cacheNotice: typeof value.cacheNotice === "string" ? value.cacheNotice : undefined,
          observedAt: typeof value.observedAt === "string" ? value.observedAt : undefined,
        };
    } catch {
      /* Server remains authority. */
    }
    let cursor = cached.cursor;
    let buffer = cached.events;
    let notice = cached.notice;
    let cacheNotice = cached.cacheNotice;
    let observedAt = cached.observedAt;
    const encoder = new TextEncoder();
    let sizes = buffer.map((event) => encoder.encode(JSON.stringify(event)).length + 1);
    let bufferedBytes = sizes.reduce((sum, size) => sum + size, 0);
    const trimBuffer = () => {
      // Reserve space for the JSON wrapper and visible notices. Rows retain
      // their original payload; an omitted row is explicitly a display limit.
      while (buffer.length && (buffer.length > MAX_EVENTS || bufferedBytes > CACHE_BYTES - 2048)) {
        buffer.shift();
        bufferedBytes -= sizes.shift() ?? 0;
        cacheNotice = CACHE_NOTICE;
      }
    };
    trimBuffer();
    setState({ ...cached, events: [...buffer], notice, cacheNotice });
    let dirty = false;
    let disposed = false;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    let publicationTimer: ReturnType<typeof setTimeout> | undefined;
    const controller = new AbortController();
    const persist = () => {
      try {
        const serialized = JSON.stringify({ events: buffer, cursor, notice, cacheNotice, observedAt });
        if (encoder.encode(serialized).length <= CACHE_BYTES)
          sessionStorage.setItem(storageKey, serialized);
      } catch {
        /* Buffer remains in memory when storage is full. */
      }
    };
    const flush = (connected = true) => {
      if (publicationTimer !== undefined) {
        clearTimeout(publicationTimer);
        publicationTimer = undefined;
      }
      if (!dirty || disposed || controller.signal.aborted) return;
      persist();
      setState((previous) => ({ ...previous, events: [...buffer], cursor,
        connected, observedAt, notice, cacheNotice }));
      dirty = false;
    };
    // Shrink a legacy session cache immediately, even if this project has no
    // new event. Future writes occur only at batch publication boundaries.
    persist();
    async function connect() {
      let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
      let retryDelay = 3000;
      const releaseReader = async () => {
        if (!reader) return;
        try {
          await reader.cancel();
        } catch {
          /* An aborted or closed stream still releases its reader lock. */
        }
        reader.releaseLock();
        reader = undefined;
      };
      const synchronize = async () => {
        const snapshot = await api.raw<{
          project: { project_id: string };
          revision: number;
        }>(`/projects/${encodeURIComponent(projectId ?? "")}/snapshot`, controller.signal);
        const version = snapshot.read_model_version;
        if (
          snapshot.source !== "postgres" ||
          snapshot.data?.project?.project_id !== projectId ||
          typeof version !== "number" ||
          !Number.isSafeInteger(version) ||
          version < 0 ||
          snapshot.data.revision !== version
        )
          throw new Error("权威快照身份或版本无效，游标未推进");
        if (disposed || controller.signal.aborted) return;
        // Snapshot recovery closes a missing history range; it never invents
        // domain events or describes the retained event buffer as complete.
        cursor = version;
        buffer = [];
        sizes = [];
        bufferedBytes = 0;
        observedAt = undefined;
        dirty = false;
        notice = "历史事件未完整显示，已同步权威快照";
        persist();
        setState({ events: [], cursor, connected: false, notice, cacheNotice });
        window.dispatchEvent(new CustomEvent("forgeflow-resync", {
          detail: {
            projectId: projectId!,
            cursor: `${projectId}:${version}`,
            readModelVersion: version,
          } satisfies ControlResync,
        }));
        retryDelay = 0;
      };
      try {
        const headers: Record<string, string> = { Accept: "text/event-stream" };
        const token = getToken();
        if (token) headers.Authorization = `Bearer ${token}`;
        if (cursor) headers["Last-Event-ID"] = `${projectId}:${cursor}`;
        const response = await fetch(
          apiUrl(
            `/projects/${encodeURIComponent(projectId ?? "")}/events?after=${cursor}`,
          ),
          { headers, signal: controller.signal },
        );
        if (!response.ok) {
          if (response.status === 409) {
            const error = await response.json();
            if (error.code === "SNAPSHOT_REQUIRED") {
              await synchronize();
              return;
            }
          }
          throw new Error(`事件请求失败 (${response.status})`);
        }
        if (
          !response.headers.get("content-type")?.includes("text/event-stream")
        )
          throw new Error("服务未返回持久化事件流");
        if (!response.body) throw new Error("浏览器无法读取事件流");
        setState((previous) => ({
          ...previous,
          connected: true,
          error: undefined,
        }));
        reader = response.body.getReader();
        const decoder = new TextDecoder();
        let pending = "";
        let processed = 0;
        while (!disposed && !controller.signal.aborted) {
          const chunk = await reader.read();
          if (chunk.done) break;
          pending = (
            pending + decoder.decode(chunk.value, { stream: true })
          ).replace(/\r\n/g, "\n");
          let end: number;
          while (!disposed && !controller.signal.aborted && (end = pending.indexOf("\n\n")) !== -1) {
            const frame = pending.slice(0, end);
            pending = pending.slice(end + 2);
            if (frame.length > 2_000_000)
              throw new Error("EVENT_FRAME_TOO_LARGE");
            const data = frame
              .split("\n")
              .filter((line) => line.startsWith("data:"))
              .map((line) => line.slice(5).trimStart())
              .join("\n");
            if (!data) continue;
            const event = object(JSON.parse(data));
            if (event.code) throw new Error(str(event.code));
            const sequence = num(event.project_seq);
            if (
              event.project_id !== projectId ||
              typeof event.event_id !== "string" ||
              !event.event_id ||
              typeof event.kind !== "string" ||
              !event.kind ||
              sequence === undefined ||
              !Number.isSafeInteger(sequence) ||
              sequence < 1
            )
              throw new Error("事件身份或序号无效，游标未推进");
            if (sequence > cursor) {
              if (sequence !== cursor + 1)
                throw new Error("EVENT_SEQUENCE_GAP");
              if (!buffer.some((e) => e.event_id === event.event_id)) {
                buffer.push(event);
                const size = encoder.encode(data).length + 1;
                sizes.push(size);
                bufferedBytes += size;
                trimBuffer();
              }
              cursor = sequence;
              observedAt = str(event.occurred_at, "");
              dirty = true;
            }
            processed += 1;
            if (processed >= BATCH_SIZE) {
              flush();
              processed = 0;
              // A fulfilled reader promise only yields a microtask. Release
              // the main thread between replay batches for paint and input.
              await new Promise<void>((resolve) => setTimeout(resolve, 0));
            }
          }
          // A chunk can contain many valid frames. Only one complete frame or
          // the remaining unfinished frame consumes the per-frame limit.
          if (pending.length > 2_000_000)
            throw new Error("EVENT_FRAME_TOO_LARGE");
          if (dirty && publicationTimer === undefined)
            publicationTimer = setTimeout(() => {
              publicationTimer = undefined;
              flush();
            }, 0);
        }
        if (!disposed) throw new Error("事件连接结束，正在恢复游标");
      } catch (e) {
        if (!disposed && !controller.signal.aborted) {
          if (e instanceof Error && ["EVENT_FRAME_TOO_LARGE", "EVENT_SEQUENCE_GAP", "SNAPSHOT_REQUIRED"].includes(e.message)) {
            await releaseReader();
            try {
              await synchronize();
            } catch (error) {
              if (!disposed && !controller.signal.aborted)
                setState((previous) => ({ ...previous, connected: false,
                  error: error instanceof Error ? error.message : "权威快照同步失败，正在重试" }));
            }
          } else {
            setState((previous) => ({
              ...previous,
              connected: false,
              error: e instanceof Error ? e.message : String(e),
            }));
          }
        }
      } finally {
        flush(false);
        await releaseReader();
        if (!disposed && !controller.signal.aborted)
          timeout = setTimeout(() => void connect(), retryDelay);
      }
    }
    void connect();
    return () => {
      disposed = true;
      controller.abort();
      if (timeout) clearTimeout(timeout);
      if (publicationTimer !== undefined) clearTimeout(publicationTimer);
    };
  }, [projectId]);
  return state;
}
