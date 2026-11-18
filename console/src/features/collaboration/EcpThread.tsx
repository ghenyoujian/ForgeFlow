import { useState } from "react";
import { api } from "../../app/api";

interface Props { conversationId: string; threadId: string; onSent?: () => void; }

export function EcpThread({ conversationId, threadId, onSent }: Props) {
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string>();
  async function send() {
    const bodyText = text.trim();
    if (!bodyText || busy) return;
    setBusy(true); setNotice(undefined);
    const key = crypto.randomUUID();
    try {
      await api.post(`/conversations/${encodeURIComponent(conversationId)}/messages`, {
        thread_id: threadId,
        message_kind: "chat.message",
        client_request_id: key,
        payload: { text: bodyText },
        correlation_id: null,
        causation_id: null,
        expires_at: null,
      }, { idempotencyKey: key });
      setText(""); setNotice("消息已提交；ACK 和 Task 状态保持独立。"); onSent?.();
    } catch (error) { setNotice(error instanceof Error ? error.message : "消息发送失败"); }
    finally { setBusy(false); }
  }
  return <div className="panel-body">
    <textarea aria-label="协作消息" rows={3} value={text} onChange={event => setText(event.target.value)} placeholder="写入正式协作消息…" disabled={busy}/>
    <div className="panel-actions"><button type="button" onClick={() => void send()} disabled={busy || !text.trim()}>{busy ? "提交中…" : "发送消息"}</button>{notice && <span role="status">{notice}</span>}</div>
  </div>;
}
