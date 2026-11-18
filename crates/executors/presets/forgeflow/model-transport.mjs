/** Stock SDK fetch transport for one live canonical native model grant.
 * Load with Node --import before the unchanged DSH CLI. This is a UDS transport,
 * not a model broker: PostgreSQL admits once and the API consumes the grant
 * before any provider connection. Native SDK parsing and usage events stay intact.
 */
import { AsyncLocalStorage } from 'node:async_hooks';
import { createConnection } from 'node:net';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const grantKey = Symbol.for('forgeflow.nativeModelGrantContext.v1');
const configKey = Symbol.for('forgeflow.nativeModelTransportConfig.v1');
const installKey = Symbol.for('forgeflow.nativeModelTransportInstalled.v1');
const grants = globalThis[grantKey] ??= new AsyncLocalStorage();
const schema = 'forgeflow.model-uds.v1';
const endpoint = 'http://forgeflow-model.invalid/v1/messages';
const socketPath = '/tmp/forgeflow/model.sock';
const maximumFrame = 65536;
const headerNames = new Set(['anthropic-version', 'anthropic-beta', 'content-type',
  'accept', 'anthropic-dangerous-direct-browser-access']);

function denied(message) {
  return Object.assign(new Error(message), { code: 'FORGEFLOW_MODEL_TRANSPORT_DENIED' });
}
function aborted(signal) {
  return signal.reason instanceof Error ? signal.reason : new DOMException('Model transport aborted', 'AbortError');
}
function frame(bytes) {
  const prefix = Buffer.allocUnsafe(4);
  prefix.writeUInt32BE(bytes.length);
  return Buffer.concat([prefix, bytes]);
}

/** Deployment-owned, pinned provider policy; never selected by a model/tool. */
function applyProviderPolicy(parsed, grant, config) {
  if (config.provider_policy_id === undefined && config.provider_policy_path === undefined) return false;
  if (config.provider_policy_id !== 'glm-5.3-max.v1' || config.provider_policy_path !== '/tmp/forgeflow/provider-policy.json') {
    throw denied('Provider policy identity or frozen path is invalid');
  }
  let policy;
  try { policy = JSON.parse(readFileSync(config.provider_policy_path, 'utf8')); }
  catch { throw denied('Pinned provider policy cannot be read'); }
  if (policy.schema_version !== 'forgeflow.native-provider-policy.v1' || policy.id !== config.provider_policy_id ||
      policy.provider !== 'newapi' || policy.model !== 'glm-5.3' || policy.api !== 'anthropic-messages' ||
      policy.thinking_type !== 'enabled' || policy.effort !== 'max' || policy.max_output_tokens !== 131072 ||
      JSON.stringify(policy.input) !== '["text"]' || policy.model_fallback !== false ||
      grant.provider !== policy.provider || grant.model !== policy.model ||
      grant.max_output_tokens > policy.max_output_tokens) {
    throw denied('Model grant differs from the frozen GLM Max policy');
  }
  const imageBlock = blocks => Array.isArray(blocks) && blocks.some(block =>
    block && typeof block === 'object' && (['image', 'document'].includes(block.type) ||
      block.type === 'tool_result' && imageBlock(block.content)));
  if (imageBlock(parsed.system) || parsed.messages?.some(message => imageBlock(message.content))) {
    throw denied('Frozen GLM-5.3 policy accepts text input only');
  }
  // GLM-5.3 always reasons. Stock pi-ai's Anthropic budget-based branch clamps
  // max to high, while its adaptive branch uses Claude-only thinking knobs.
  // This reviewed route spells the requested effort explicitly for NewAPI's
  // ClaudeRequest.GetEfforts(), which reads output_config.effort. No budget or
  // answer guarantee is invented for GLM; the canonical total ceiling is kept.
  parsed.thinking = { type: policy.thinking_type };
  if (parsed.output_config !== undefined && (!parsed.output_config || typeof parsed.output_config !== 'object' || Array.isArray(parsed.output_config))) {
    throw denied('Model output configuration must be an object');
  }
  parsed.output_config = { ...parsed.output_config, effort: policy.effort };
  return true;
}
async function boundedBody(request, limit) {
  if (!request.body) throw denied('Model request body is missing');
  const reader = request.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    for (;;) {
      if (request.signal.aborted) throw aborted(request.signal);
      const result = await reader.read();
      if (result.done) break;
      length += result.value.byteLength;
      if (length > limit) throw denied('Model request exceeds frozen body limit');
      chunks.push(Buffer.from(result.value));
    }
  } catch (error) {
    await reader.cancel(error).catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, length);
}

export async function managedModelFetch(input, init) {
  const grant = grants.getStore();
  const config = globalThis[configKey];
  if (!grant?.live || grant.dispatch_started || config?.schema_version !== schema ||
      config.socket_path !== socketPath || config.sdk_origin !== 'http://forgeflow-model.invalid') {
    throw denied('Fetch requires one live canonical native model grant');
  }
  const request = new Request(input, init);
  // Stock Anthropic beta.messages (used by installed pi-ai) adds this one
  // SDK query. Both spellings map to the same fixed trusted messages route;
  // no caller-controlled origin/path/other query reaches the relay.
  if (![endpoint, endpoint + '?beta=true'].includes(request.url) || request.method !== 'POST' || request.redirect !== 'follow' && request.redirect !== 'error') {
    throw denied('Only the synthetic Anthropic messages endpoint is allowed');
  }
  if (request.signal.aborted) throw aborted(request.signal);
  const fields = ['project_id', 'task_id', 'attempt_id', 'native_session_id', 'allocation_id',
    'request_id', 'request_grant_id', 'provider', 'model'];
  if (fields.some(key => typeof grant[key] !== 'string' || !grant[key] || grant[key].length > 256) ||
      !Number.isSafeInteger(grant.generation) || grant.generation < 1 ||
      !Number.isSafeInteger(grant.max_output_tokens) || grant.max_output_tokens < 1 ||
      !Number.isSafeInteger(config.max_request_bytes) || config.max_request_bytes < 1 || config.max_request_bytes > 8388608 ||
      !Number.isSafeInteger(config.response_idle_timeout_ms) || config.response_idle_timeout_ms < 1 || config.response_idle_timeout_ms > 1800000) {
    throw denied('Model transport identity or frozen limits are invalid');
  }
  // Consume the in-process right before the first await. SDK retry, concurrent
  // fetch and alternate endpoint calls cannot spend the same admitted grant.
  grant.dispatch_started = true;
  let body = await boundedBody(request, config.max_request_bytes);
  if (!grant.live || request.signal.aborted) throw request.signal.aborted ? aborted(request.signal) : denied('Model grant closed before dispatch');
  let parsed;
  try { parsed = JSON.parse(body.toString('utf8')); }
  catch { throw denied('Model body must be JSON'); }
  if (parsed.stream !== true || parsed.model !== grant.model ||
      !Number.isSafeInteger(parsed.max_tokens) || parsed.max_tokens < grant.max_output_tokens) {
    throw denied('Streaming model body differs from its canonical grant');
  }
  // Installed stock pi-ai adds its thinking budget to the answer maxTokens
  // before constructing the SDK wire request. The canonical grant is a total
  // response ceiling. Only lower those two budget fields; never increase an SDK
  // ceiling or change prompts, tools, routes, provider keys or stream parsing.
  const sdkBodySha256 = createHash('sha256').update(body).digest('hex');
  const sdkMaxTokens = parsed.max_tokens;
  const sdkThinkingType = parsed.thinking?.type;
  let projected = parsed.max_tokens !== grant.max_output_tokens;
  parsed.max_tokens = grant.max_output_tokens;
  const providerPolicyApplied = applyProviderPolicy(parsed, grant, config);
  projected ||= providerPolicyApplied;
  if (!providerPolicyApplied && parsed.thinking?.type === 'enabled') {
    if (!Number.isSafeInteger(parsed.thinking.budget_tokens) || parsed.thinking.budget_tokens < 1) {
      throw denied('Explicit thinking budget is invalid');
    }
    if (grant.max_output_tokens <= 1024) {
      delete parsed.thinking;
      projected = true;
    } else {
      const budget = Math.min(parsed.thinking.budget_tokens, grant.max_output_tokens - 1024);
      projected ||= budget !== parsed.thinking.budget_tokens;
      parsed.thinking.budget_tokens = budget;
    }
  } else if (!providerPolicyApplied && parsed.thinking && !['adaptive', 'disabled'].includes(parsed.thinking.type)) {
    throw denied('Unsupported thinking configuration');
  } else if (!providerPolicyApplied && parsed.thinking?.type === 'adaptive' && parsed.thinking.budget_tokens !== undefined) {
    throw denied('Adaptive thinking cannot carry an explicit budget');
  }
  // Adaptive thinking keeps its supported provider semantics. No explicit
  // thinking budget or hidden second token ceiling is invented for that mode.
  if (projected) body = Buffer.from(JSON.stringify(parsed));
  if (body.length > config.max_request_bytes) throw denied('Projected model request exceeds frozen body limit');
  if (providerPolicyApplied) {
    // Private Worker stderr contains only identities, counts, hashes and known
    // request controls, never prompts, thinking content, tools or credentials.
    process.stderr.write(JSON.stringify({ schema_version: 'forgeflow.model-wire-projection.v1',
      request_id: grant.request_id, provider_policy_id: config.provider_policy_id,
      sdk_body_sha256: sdkBodySha256, forwarded_body_sha256: createHash('sha256').update(body).digest('hex'),
      sdk_max_tokens: sdkMaxTokens, canonical_max_tokens: parsed.max_tokens,
      sdk_thinking_type: sdkThinkingType ?? null, thinking_type: parsed.thinking.type,
      output_effort: parsed.output_config.effort }) + '\n');
  }
  const headers = [...request.headers].filter(([name]) => headerNames.has(name));
  const metadata = Buffer.from(JSON.stringify({ schema_version: schema,
    ...Object.fromEntries(fields.map(key => [key, grant[key]])), generation: grant.generation,
    max_output_tokens: grant.max_output_tokens, method: 'POST', url: endpoint,
    // Exact authority hashes bind the actual forwarded bytes after the
    // downward-only canonical budget projection, not the pre-projection body.
    body_bytes: body.length, body_sha256: createHash('sha256').update(body).digest('hex'), headers }));
  if (metadata.length === 0 || metadata.length > maximumFrame) throw denied('Model metadata exceeds frame limit');
  const completion = Promise.withResolvers();
  grant.transportComplete = completion.promise;
  // A transport error can precede the SDK iterator finishing. The bridge owns
  // the authoritative await; prevent a detached early rejection in the interim.
  completion.promise.catch(() => {});
  return responseFromSocket(metadata, body, request.signal, config.response_idle_timeout_ms, completion, grant);
}

function responseFromSocket(metadata, body, signal, idleTimeout, completion, grant) {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ path: socketPath });
    let buffer = Buffer.alloc(0);
    let header;
    let bodyController;
    let resolved = false;
    let ended = false;
    let failed = false;
    let frameLength;
    const cleanup = () => signal.removeEventListener('abort', onAbort);
    function fail(error) {
      if (ended || failed) return;
      failed = true;
      completion.reject(error);
      cleanup();
      socket.destroy();
      if (resolved) bodyController?.error(error);
      else reject(error);
    }
    function onAbort() { fail(aborted(signal)); }
    grant.cancelTransport = fail;
    function pump() {
      try {
        while (!ended && !failed) {
          if (header && bodyController && bodyController.desiredSize <= 0) {
            socket.pause();
            socket.setTimeout(0); // Downstream backpressure is not upstream idle.
            return;
          }
          if (frameLength === undefined) {
            if (buffer.length < 4) break;
            frameLength = buffer.readUInt32BE(0);
            buffer = buffer.subarray(4);
            if (frameLength > maximumFrame || !header && frameLength === 0) throw denied('Invalid model response frame length');
          }
          if (buffer.length < frameLength) break;
          const bytes = buffer.subarray(0, frameLength);
          buffer = buffer.subarray(frameLength);
          frameLength = undefined;
          if (!header) {
            header = JSON.parse(bytes.toString('utf8'));
            if (header.schema_version !== schema || !Number.isSafeInteger(header.status) || header.status < 200 || header.status > 599 ||
                !Array.isArray(header.headers) || header.headers.some(pair => !Array.isArray(pair) || pair.length !== 2 || pair.some(value => typeof value !== 'string'))) {
              throw denied('Invalid model response header');
            }
            const noBody = [204, 205, 304].includes(header.status);
            const stream = noBody ? null : new ReadableStream({
              start(controller) { bodyController = controller; },
              pull() {
                socket.setTimeout(idleTimeout);
                socket.resume();
                pump();
              },
              cancel() {
                // The Worker observes socket loss and drops the live upstream.
                // Native bridge settlement retains unknown/incomplete usage.
                ended = true;
                completion.reject(new DOMException('Model response body cancelled before terminal frame', 'AbortError'));
                cleanup();
                socket.destroy();
              },
            });
            const response = new Response(stream, { status: header.status, headers: header.headers });
            resolved = true;
            resolve(response);
          } else if (bytes.length === 0) {
            if (buffer.length) throw denied('Bytes after terminal model frame');
            ended = true;
            // Worker writes zero only after trusted API EOF, which follows the
            // durable transport observer. A message_stop event alone is not EOF.
            completion.resolve();
            cleanup();
            bodyController?.close();
            socket.destroy();
          } else {
            if (!bodyController) throw denied('Unexpected body on bodyless HTTP status');
            bodyController.enqueue(new Uint8Array(bytes));
          }
        }
      } catch (error) { fail(error); }
    }
    socket.setTimeout(idleTimeout, () => fail(denied('Model relay idle timeout')));
    socket.on('error', fail);
    socket.on('data', chunk => {
      if (ended || failed) return;
      buffer = buffer.length ? Buffer.concat([buffer, chunk]) : chunk;
      pump();
    });
    socket.on('end', () => { if (!ended && !failed) fail(denied('Model relay closed without terminal frame')); });
    socket.on('close', () => { if (!ended && !failed) fail(denied('Model relay closed before completion')); });
    socket.on('connect', () => {
      if (signal.aborted) { onAbort(); return; }
      // Full duplex is intentional. Never socket.end(): request-side EOF is
      // cancellation to the Worker while the upstream response remains active.
      socket.write(frame(metadata));
      socket.write(body);
    });
    signal.addEventListener('abort', onAbort, { once: true });
    if (signal.aborted) onAbort();
  });
}

if (!globalThis[installKey]) {
  Object.defineProperty(globalThis, installKey, { value: true });
  // No fallback to ambient network fetch: tools/telemetry without a live model
  // context fail closed. The outer Worker also disables direct IP networking.
  globalThis.fetch = managedModelFetch;
}
