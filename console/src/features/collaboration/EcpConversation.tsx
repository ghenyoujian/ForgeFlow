import { useCallback, useEffect, useState } from "react";
import { api } from "../../app/api";
import { EcpAttachment } from "./EcpAttachment";
import { EcpThread } from "./EcpThread";

interface Message { message_id: string; sequence: number; message_kind: string; payload: { text?: string }; sender_principal_id: string; }
interface MessagePage { items: Message[]; checkpoint?: number; next_cursor?: number; has_more?: boolean; }
interface Props { conversationId: string; threadId: string; }

export function EcpConversation({ conversationId, threadId }: Props) {
  const [page, setPage] = useState<MessagePage>();
  const [after, setAfter] = useState(0);
  const [error, setError] = useState<string>();
  // Keep pagination explicit.  Depending on `after` here makes every cursor
  // change rerun the conversation effect below, which immediately reloads the
  // first page and makes "读取下一页" appear to do nothing.
  const load = useCallback(async (cursor: number) => {
    try { setError(undefined); setPage(await api.get<MessagePage>(`/conversations/${encodeURIComponent(conversationId)}/messages?after=${cursor}&limit=50`)); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "消息读取失败"); }
  }, [conversationId]);
  useEffect(() => { setAfter(0); void load(0); }, [conversationId, load]);
  const acknowledge = async () => {
    const sequence = page?.items.at(-1)?.sequence;
    if (sequence === undefined) return;
    const key = crypto.randomUUID();
    await api.post(`/conversations/${encodeURIComponent(conversationId)}/checkpoint`, { acknowledged_sequence: sequence, request_key: key }, { idempotencyKey: key });
    await load(after);
  };
  return <section className="panel" aria-label="ECP 协作会话">
    <header className="panel-header"><div><h2>正式协作会话</h2><p className="panel-caption"><code>{conversationId}</code> · cursor {page?.items.at(-1)?.sequence ?? after} · checkpoint {page?.checkpoint ?? 0}</p></div><button type="button" onClick={() => void acknowledge()} disabled={!page?.items.length}>确认已读</button></header>
    {error && <p className="error-notice" role="alert">{error}</p>}
    <div className="panel-body">
      {!page?.items.length && !error && <p className="muted">暂无消息。</p>}
      {page?.items.map(message => <article key={message.message_id} className="panel-row"><div><strong>{message.sender_principal_id}</strong><small>#{message.sequence} · {message.message_kind}</small></div><p>{message.payload?.text ?? "（结构化 payload）"}</p></article>)}
      <div className="panel-actions"><button type="button" onClick={() => { const next = page?.next_cursor; if (next !== undefined) { setAfter(next); void load(next); } }} disabled={!page?.has_more || page.next_cursor === undefined}>读取下一页</button></div>
      <EcpAttachment />
    </div>
    <EcpThread conversationId={conversationId} threadId={threadId} onSent={() => void load(after)} />
  </section>;
}
