import { open, constants } from 'node:fs/promises';

export function validateBase(value) {
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash || !['http:', 'https:'].includes(url.protocol)) throw new Error('Invalid ForgeFlow service URL');
  if (url.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) throw new Error('Remote ForgeFlow connections require HTTPS');
  return url.origin;
}
export async function privateToken(file) {
  // NONBLOCK lets us inspect and reject a FIFO without waiting for a writer.
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || (stat.mode & 0o777) !== 0o600 || (process.getuid && stat.uid !== process.getuid()) || stat.size > 8192) throw new Error('Connector credential file must be an owned 0600 regular file');
    // A file can grow after stat. Bound the actual read as well as its metadata.
    const buffer=Buffer.alloc(8193);
    let length=0;
    while(length<buffer.length) {
      const {bytesRead}=await handle.read(buffer,length,buffer.length-length,null);
      if(!bytesRead)break;
      length+=bytesRead;
    }
    if(length>8192)throw new Error('Connector credential file exceeds 8192 bytes');
    const token = buffer.toString('utf8',0,length).trim();
    if (!/^[a-f0-9]{64}$/.test(token)) throw new Error('Invalid connector credential format');
    return token;
  } finally { await handle.close(); }
}
export class ForgeFlowClient {
  constructor({url, projectId, workspaceId, tokenFile, token}) {
    this.url = validateBase(url);
    if (!projectId || !workspaceId) throw new Error('Project and workspace are required');
    this.projectId = projectId; this.workspaceId = workspaceId;
    this.tokenFile = tokenFile;
    // Captured in a closure and never returned by tools, doctor or configuration dumps.
    const configured = token || process.env.FORGEFLOW_CONNECTOR_TOKEN;
    this.credential = async () => tokenFile ? privateToken(tokenFile) : configured;
  }
  async request(path, {method = 'GET', body, signal, key} = {}) {
    const token = await this.credential();
    if (!/^[a-f0-9]{64}$/.test(token || '')) throw new Error('Set FORGEFLOW_CONNECTOR_TOKEN or an owned 0600 token file');
    const response = await fetch(`${this.url}/api/v1/projects/${encodeURIComponent(this.projectId)}/agent-network/${path}`, {
      method, redirect: 'error', signal: AbortSignal.any([AbortSignal.timeout(10000), ...(signal ? [signal] : [])]),
      headers: {Accept: 'application/json', Authorization: `Bearer ${token}`, 'X-ForgeFlow-Workspace': this.workspaceId,
        ...(method !== 'GET' ? {'Content-Type': 'application/json', 'Idempotency-Key': key || crypto.randomUUID()} : {})},
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const reader=response.body?.getReader();
    const chunks=[];let length=0;
    if(reader) {
      try {
        while(true) {
          const {done,value}=await reader.read();
          if(done)break;
          length+=value.byteLength;
          if(length>4*1024*1024)throw new Error('ForgeFlow response exceeds 4 MiB');
          chunks.push(value);
        }
      } finally {await reader.cancel().catch(()=>{});reader.releaseLock();}
    }
    const raw=Buffer.concat(chunks,length).toString('utf8');
    let parsed; try { parsed = JSON.parse(raw); } catch { throw new Error(`ForgeFlow returned invalid JSON (${response.status})`); }
    if (!response.ok) throw new Error(`ForgeFlow ${response.status}: ${parsed.code || 'REQUEST_FAILED'}`);
    if(!parsed || typeof parsed!=='object' || !Object.hasOwn(parsed,'data'))throw new Error('ForgeFlow returned an invalid response envelope');
    return parsed.data;
  }
  register(nativeId, name, signal) {return this.request('agents', {method: 'POST', body: {native_agent_id: nativeId, name}, signal});}
  agents(signal) {return this.request('agents', {signal});}
  send(sender, input, signal) {return this.request('messages', {method: 'POST', key: input.client_message_id, body: {...input, sender_agent_id: sender}, signal});}
  inbox(agent, after = 0, signal) {return this.request(`messages?agent_id=${encodeURIComponent(agent)}&after=${after}`, {signal});}
  ack(message, recipient, signal) {return this.request(`messages/${encodeURIComponent(message)}/receipts`, {method: 'POST', body: {recipient_agent_id:recipient}, signal});}
}
