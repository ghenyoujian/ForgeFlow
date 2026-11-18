import { useEffect, useState } from "react";
import { api, apiUrl, getToken, getAuthScope, getWorkspace } from "./api";
export interface ControlEvent {
  projectId: string;
  cursor: string;
  kind: string;
  objectId: string;
  payload: unknown;
  event: Record<string, unknown>;
}
export interface ControlResync {
  projectId: string;
  cursor: string;
  readModelVersion: number;
}
export function useEventConnection(projectId?: string) {
  const [authRevision, setAuthRevision] = useState(0);
  useEffect(() => {
    const change = () => setAuthRevision((v) => v + 1);
    window.addEventListener("forgeflow-auth", change);
    window.addEventListener('forgeflow-session-renewed',change);
    return () => {window.removeEventListener("forgeflow-auth", change);window.removeEventListener('forgeflow-session-renewed',change);};
  }, []);
  const [status, setStatus] = useState("未选择项目");
  const [lastEvent, setLastEvent] = useState<string>();
  useEffect(() => {
    if (!projectId) {
      setStatus("项目级事件未订阅");
      return;
    }
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const key = `forgeflow.cursor.${getAuthScope()}.${projectId}`;
    let cursor = sessionStorage.getItem(key) || `${projectId}:0`;
    const connect = async () => {
      setStatus("正在连接");
      let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
      let retryDelay = 5000;
      const synchronize = async () => {
        setStatus("正在同步最新状态");
        const snapshot = await api.raw<{ project_id: string; cursor: number }>(
          `/projects/${encodeURIComponent(projectId)}/event-cursor`, controller.signal);
        const version = snapshot.data?.cursor;
        if (snapshot.source !== "postgres" || snapshot.data?.project_id !== projectId ||
            typeof version !== "number" || !Number.isSafeInteger(version) || version < 0)
          throw new Error("SNAPSHOT_SYNC_FAILED");
        if (controller.signal.aborted) return;
        cursor = `${projectId}:${version}`;
        sessionStorage.setItem(key, cursor);
        setLastEvent(undefined);
        // Cache invalidation is a client signal, separate from domain events.
        window.dispatchEvent(
          new CustomEvent("forgeflow-resync", {
            detail: { projectId, cursor, readModelVersion: version } satisfies ControlResync,
          }),
        );
        retryDelay = 0;
        setStatus("已同步最新状态，正在恢复事件");
      };
      try {
        const res = await fetch(
          apiUrl(
            `/projects/${encodeURIComponent(projectId)}/events?after=${encodeURIComponent(cursor.split(":").pop() || "0")}`,
          ),
          {
            headers: {
              Accept: "text/event-stream",
              Authorization: `Bearer ${getToken()}`,
              "Last-Event-ID": cursor,
              "X-ForgeFlow-Workspace": getWorkspace(),
            },
            signal: controller.signal,
          },
        );
        if (!res.ok) {
          if (res.status === 409) {
            const error = await res.json();
            if (error.code === "SNAPSHOT_REQUIRED") {
              await synchronize();
              return;
            }
          }
          setStatus(`事件服务 ${res.status}`);
          throw new Error("stream failed");
        }
        if (!res.body) throw new Error("empty stream");
        setStatus("事件已连接");
        reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        while (!controller.signal.aborted) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer = (buffer + decoder.decode(value, { stream: true })).replace(/\r\n/g, "\n");
          let at: number;
          while ((at = buffer.indexOf("\n\n")) >= 0) {
            const block = buffer.slice(0, at);
            buffer = buffer.slice(at + 2);
            if (block.length > 1024 * 1024)
              throw new Error("EVENT_FRAME_TOO_LARGE");
            if (
              block
                .split("\n")
                .some((line) => line.trim() === "event: stream_error")
            )
              throw new Error("EVENT_READ_FAILED");
            const id = block
              .split("\n")
              .find((l) => l.startsWith("id:"))
              ?.slice(3)
              .trim();
            if (id) {
              const data = block
                .split("\n")
                .filter((line) => line.startsWith("data:"))
                .map((line) => line.slice(5).trimStart())
                .join("\n");
              const event = JSON.parse(data) as Record<string, unknown>;
              if (
                event.project_id !== projectId ||
                typeof event.kind !== "string" ||
                typeof event.object_id !== "string" ||
                !Number.isSafeInteger(event.project_seq) ||
                id !== `${projectId}:${event.project_seq}`
              )
                throw new Error("event identity mismatch");
              if (
                Number(event.project_seq) <=
                Number(cursor.split(":").pop() || 0)
              )
                continue;
              if (event.project_seq !== Number(cursor.split(":").pop() || 0) + 1)
                throw new Error("EVENT_SEQUENCE_GAP");
              cursor = id;
              sessionStorage.setItem(key, id);
              setLastEvent(new Date().toISOString());
              window.dispatchEvent(
                new CustomEvent("forgeflow-event", {
                  detail: {
                    projectId,
                    cursor: id,
                    kind: event.kind,
                    objectId: event.object_id,
                    payload: event.payload,
                    event,
                  } satisfies ControlEvent,
                }),
              );
            }
          }
          if (buffer.length > 1024 * 1024)
            throw new Error("EVENT_FRAME_TOO_LARGE");
        }
        if (!controller.signal.aborted) setStatus("事件断连，正在重连");
      } catch (error) {
        if (!controller.signal.aborted) {
          if (error instanceof Error && ["EVENT_SEQUENCE_GAP", "EVENT_FRAME_TOO_LARGE"].includes(error.message)) {
            try {
              await synchronize();
            } catch {
              if (!controller.signal.aborted) setStatus("最新状态同步失败，正在重试");
            }
          } else {
            setStatus(
              error instanceof Error && error.message === "EVENT_READ_FAILED"
                ? "事件读取失败，正在重连"
                : error instanceof Error && error.message === "SNAPSHOT_SYNC_FAILED"
                  ? "最新状态同步失败，正在重试"
                  : "事件未连接，正在重试",
            );
          }
        }
      } finally {
        if (reader) {
          try {
            await reader.cancel();
          } catch {}
          reader.releaseLock();
        }
        if (!controller.signal.aborted) timer = setTimeout(connect, retryDelay);
      }
    };
    void connect();
    return () => {
      controller.abort();
      if (timer) clearTimeout(timer);
    };
  }, [projectId, authRevision]);
  return { status, lastEvent };
}
