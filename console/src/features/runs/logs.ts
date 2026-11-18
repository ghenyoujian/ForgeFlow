import { useEffect, useState, useCallback } from "react";
import { api } from "../../app/api";
import { object, num, str } from "../portfolio/monitor";
export function useAttemptLogs(attemptId?: string, enabled = false) {
  const [text, setText] = useState("");
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const reload = useCallback(() => setRefresh((n) => n + 1), []);
  useEffect(() => {
    setText("");
    setOffset(0);
    setError(undefined);
  }, [attemptId]);
  useEffect(() => {
    if (!enabled || !attemptId) return;
    const key = `forgeflow.logs.${attemptId}`;
    let cursor = 0;
    let buffer = "";
    try {
      const cached = JSON.parse(sessionStorage.getItem(key) ?? "null");
      if (
        cached &&
        Number.isSafeInteger(cached.offset) &&
        typeof cached.text === "string"
      ) {
        cursor = cached.offset;
        buffer = cached.text;
        setOffset(cursor);
        setText(buffer);
      }
    } catch {
      /* Read from zero when no valid local display cache exists. */
    }
    let disposed = false;
    let timeout: ReturnType<typeof setTimeout>;
    let controller: AbortController;
    async function read() {
      controller = new AbortController();
      setLoading(true);
      try {
        const value = object(
          await api.get(
            `/attempts/${encodeURIComponent(attemptId ?? "")}/logs?offset=${cursor}&limit_bytes=65536`,
            controller.signal,
          ),
        );
        if (disposed) return;
        const next = num(value.next_offset);
        if (
          value.attempt_id !== attemptId ||
          num(value.offset) !== cursor ||
          next === undefined ||
          next < cursor
        )
          throw new Error("日志身份或偏移不匹配，读取位置保持不变");
        buffer = (buffer + str(value.text, "")).slice(-262144);
        cursor = next;
        setText(buffer);
        setOffset(cursor);
        setError(undefined);
        try {
          sessionStorage.setItem(
            key,
            JSON.stringify({ offset: cursor, text: buffer }),
          );
        } catch {
          /* Memory buffer remains available. */
        }
      } catch (e) {
        if (!disposed) setError(e instanceof Error ? e.message : String(e));
      } finally {
        if (!disposed) {
          setLoading(false);
          timeout = setTimeout(() => void read(), 3000);
        }
      }
    }
    void read();
    return () => {
      disposed = true;
      controller?.abort();
      clearTimeout(timeout);
    };
  }, [attemptId, enabled, refresh]);
  return { text, offset, error, loading, reload };
}
