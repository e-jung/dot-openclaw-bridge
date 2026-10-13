import http from 'node:http';
import { pathToFileURL } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod/v4';
import { SESSION_INPUTS, SESSION_NAMES } from './session-policy.mjs';
import { SessionError } from './session-store.mjs';

export const VERSION = '0.3.0';
const LOOPBACK = '127.0.0.1';
const MAX_BODY_BYTES = 16 * 1024;
const MAX_CONCURRENT = 8;

function portNumber(value, name, allowEphemeral = false) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < (allowEphemeral ? 0 : 1) || port > 65535) {
    throw new Error(`Invalid ${name}`);
  }
  return port;
}

export async function probeGateway(port) {
  // This is unauthenticated HTTP liveness, not proof of RPC authorization.
  // No Gateway token, config, device identity, headers, or content are read.
  try {
    const response = await fetch(`http://${LOOPBACK}:${port}/healthz`, {
      signal: AbortSignal.timeout(1200),
      redirect: 'error',
    });
    const reachable = response.ok;
    await response.body?.cancel();
    return reachable ? 'reachable' : 'not_ready';
  } catch {
    return 'unreachable';
  }
}

export function createMcpServer(gatewayPort, { stdio = false, jobs, approval = () => null, sessions, sessionApproval = () => null } = {}) {
  // HTTP remains health-only. Job tools are private-stdio only.
  if ((jobs || sessions) && !stdio) throw new Error('Job tools require private stdio');
  const toolNames = jobs ? ['health', 'submit_job', 'get_job', 'cancel_job'] : ['health'];
  if (sessions) toolNames.push(...SESSION_NAMES);
  const transportName = stdio ? 'stdio' : 'streamable-http';
  const exposureName = stdio ? 'private-stdio' : 'loopback-only-no-forwarding';
  const server = new McpServer({ name: 'dot-openclaw-bridge', version: VERSION });
  server.registerTool('health', {
    title: 'Bridge health',
    description: 'Read sanitized adapter capabilities and local Gateway HTTP liveness. Does not authorize, list sessions, read history, or dispatch work.',
    inputSchema: z.strictObject({}),
    outputSchema: z.strictObject({
      adapterVersion: z.literal(VERSION),
      capabilities: z.strictObject({
        tools: z.array(z.enum(toolNames)),
        transport: z.literal(transportName),
        agentDispatch: z.boolean(),
        sessionAccess: z.boolean(),
        jobControl: z.boolean(),
      }),
      gateway: z.strictObject({
        reachability: z.enum(['reachable', 'not_ready', 'unreachable']),
        probe: z.literal('unauthenticated-http-liveness'),
        rpcAuthorization: z.enum(['not-tested', 'authenticated-worker']),
      }),
      exposure: z.literal(exposureName),
    }),
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  }, async () => {
    const result = {
      adapterVersion: VERSION,
      capabilities: {
        tools: toolNames, transport: transportName,
        agentDispatch: jobs ? jobs.ready(approval()) : false,
        sessionAccess: !!sessions?.ready(sessionApproval()), jobControl: !!jobs,
      },
      gateway: {
        reachability: await probeGateway(gatewayPort),
        probe: 'unauthenticated-http-liveness',
        rpcAuthorization: (jobs?.ready(approval()) || sessions?.ready(sessionApproval())) ? 'authenticated-worker' : 'not-tested',
      },
      exposure: exposureName,
    };
    return { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result };
  });
  if (jobs) registerJobTools(server, jobs, approval);
  if (sessions) registerSessionTools(server, sessions, sessionApproval);
  return server;
}

import { SUBMIT_SCHEMA, JOB_SCHEMA } from './policy.mjs';
import { JobError } from './jobs.mjs';
function registerJobTools(server, jobs, approval) {
  const viewSchema = z.strictObject({ job_id: z.string().uuid(),
    status: z.enum(['queued', 'dispatching', 'running', 'cancelling', 'unknown', 'completed', 'failed', 'cancelled', 'timed_out']),
    created_at: z.string(), updated_at: z.string(), cancellation_requested: z.boolean(),
    result: z.string().nullable(), result_truncated: z.boolean(), error: z.string().nullable() });
  const call = fn => async args => {
    try {
      const result = fn(args);
      return { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result };
    } catch (error) {
      return { isError: true, content: [{ type: 'text', text: JSON.stringify({
        error: error instanceof JobError ? error.code : 'JOB_REQUEST_FAILED',
      }) }] };
    }
  };
  server.registerTool('submit_job', {
    title: 'Submit approved bridge job',
    description: 'Durably accept one approved bounded task. Use a stable idempotency_key for retries. Dispatch is disabled without local owner approval and a live independent worker. No caller-supplied agent, session, model or timeout.',
    inputSchema: SUBMIT_SCHEMA, outputSchema: viewSchema.extend({ duplicate: z.boolean() }),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  }, call(args => jobs.submit(args, approval())));
  server.registerTool('get_job', {
    title: 'Get bridge job', description: 'Read the durable status and bounded final result of this bridge-created job only. Does not query session history. Unknown status is not completion.',
    inputSchema: JOB_SCHEMA, outputSchema: viewSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, call(args => jobs.get(args)));
  server.registerTool('cancel_job', {
    title: 'Cancel bridge job', description: 'Request cancellation of this bridge-created job only. Running cancellation is pending until exact-run confirmation. Cannot undo earlier effects.',
    inputSchema: JOB_SCHEMA, outputSchema: viewSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
  }, call(args => jobs.cancel(args)));
}
function registerSessionTools(server, sessions, approval) {
  const summary = z.strictObject({ session_key: z.string().max(256), session_id: z.string().max(128), title: z.string().max(160), status: z.string().max(32), owner_id: z.string().max(128) });
  const resultSchema = z.strictObject({
    sessions: z.array(summary).max(20).optional(), session: summary.optional(),
    messages: z.array(z.strictObject({ role: z.enum(['user','assistant']), text: z.string().max(1024) })).max(20).optional(),
    response: z.string().max(8192).optional(), truncated: z.boolean().optional(), owner_id: z.string().max(128).optional(),
  });
  const output = z.strictObject({ operation_id: z.string().uuid(),
    status: z.enum(['queued','dispatching','running','unknown','completed','failed','timed_out','awaiting_verification']),
    session_key: z.string().max(256).nullable(), run_id: z.string().max(128).nullable(), result: resultSchema.nullable(), error: z.string().nullable(), duplicate: z.boolean() });
  const descriptions = {
    list_sessions: 'List the authenticated connected owner’s visible sessions, in bounded pages. Queues a native Gateway read.',
    get_session: 'Read selected visible session status and bounded user/assistant text history. No tools, attachments or reasoning are returned.',
    create_session: 'Create one persistent draft session with an exactly approved initial task. Stable idempotency_key required; never retries an uncertain dispatch.',
    assign_session_to_me: 'Assign responsibility to the server-verified connected owner. Does not grant sharing access. Requires exact local approval for this target.',
    send_session_message: 'Send one exactly approved follow-up to a visible approved session. Stable idempotency_key required; never retries an uncertain dispatch.',
    get_session_operation: 'Poll only a returned operation_id for native response/status. Results require an active owner-verified worker and fresh visibility validation. awaiting_verification means poll briefly; unknown means stop.',
  };
  for (const name of SESSION_NAMES) server.registerTool(name, {
    title: name.replaceAll('_', ' '), description: descriptions[name] + ' Disabled without separate local session approval and worker. Poll get_session_operation for the result.',
    inputSchema: SESSION_INPUTS[name], outputSchema: output,
    annotations: { readOnlyHint: ['list_sessions','get_session','get_session_operation'].includes(name), destructiveHint: false,
      idempotentHint: true, openWorldHint: ['create_session','send_session_message'].includes(name) },
  }, async args => {
    try {
      const result = name === 'get_session_operation' ? await sessions.poll(args, approval) : sessions.enqueue(name, args, approval());
      return { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result };
    } catch (error) {
      return { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: error instanceof SessionError ? error.code : 'SESSION_REQUEST_FAILED' }) }] };
    }
  });
}

function reject(res, status, message) {
  // Fixed diagnostic text only; never log request headers, bodies, or credentials.
  if (status === 403) process.stderr.write(`MCP request rejected: ${message}\n`);
  if (status === 413) res.setHeader('Connection', 'close');
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify({ error: message }));
}

async function parseBody(req) {
  let bytes = 0;
  const parts = [];
  for await (const part of req.iterator({ destroyOnReturn: false })) {
    bytes += part.length;
    if (bytes > MAX_BODY_BYTES) {
      // Do not destroy the stream before a bounded 413 can be returned.
      return { tooLarge: true };
    }
    parts.push(part);
  }
  try { return { value: JSON.parse(Buffer.concat(parts).toString('utf8')) }; }
  catch { return { invalid: true }; }
}

export async function startBridge({ port = 8787, gatewayPort = 18789 } = {}) {
  port = portNumber(port, 'adapter port', true);
  gatewayPort = portNumber(gatewayPort, 'Gateway port');
  let active = 0;
  const transports = new Set();
  const listener = http.createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const boundPort = listener.address().port;
    const hosts = new Set([`${LOOPBACK}:${boundPort}`, `localhost:${boundPort}`]);
    if (req.socket.remoteAddress !== LOOPBACK || !hosts.has(req.headers.host)) {
      return reject(res, 403, 'Local host required');
    }
    const origin = req.headers.origin;
    if (origin !== undefined && !new Set([...hosts].map(host => `http://${host}`)).has(origin)) {
      return reject(res, 403, 'Origin rejected');
    }
    // This Phase 1 server must not silently become a proxy-facing endpoint.
    if (Object.keys(req.headers).some(key => key === 'forwarded' || key.startsWith('x-forwarded-'))) {
      return reject(res, 403, 'Forwarding disabled');
    }
    if (req.url !== '/mcp') return reject(res, 404, 'Not found');
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      return reject(res, 405, 'Stateless MCP accepts POST only');
    }
    if (!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] ?? '')) {
      return reject(res, 415, 'JSON required');
    }
    if (active >= MAX_CONCURRENT) return reject(res, 429, 'Retry later');
    const declaredBytes = req.headers['content-length'];
    if (declaredBytes && Number(declaredBytes) > MAX_BODY_BYTES) return reject(res, 413, 'Request too large');
    active++;
    let server;
    let transport;
    let finished = false;
    const finish = async () => {
      if (finished) return;
      finished = true;
      active--;
      if (transport) transports.delete(transport);
      await server?.close().catch(() => {});
    };
    res.once('close', finish);
    try {
      const parsed = await parseBody(req);
      if (res.destroyed) return;
      if (parsed.tooLarge) return reject(res, 413, 'Request too large');
      if (parsed.invalid) return reject(res, 400, 'Invalid JSON');
      server = createMcpServer(gatewayPort);
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      transports.add(transport);
      await server.connect(transport);
      await transport.handleRequest(req, res, parsed.value);
    } catch {
      // Never log request bodies, upstream responses, headers, or exception text.
      if (!res.headersSent) reject(res, 500, 'Request failed');
      else res.end();
    } finally {
      if (res.writableEnded || res.destroyed) await finish();
    }
  });
  listener.requestTimeout = 5000;
  listener.headersTimeout = 5000;
  listener.keepAliveTimeout = 1000;
  listener.maxHeadersCount = 32;
  await new Promise((resolve, reject) => {
    listener.once('error', reject);
    listener.listen(port, LOOPBACK, resolve);
  });
  return {
    url: `http://${LOOPBACK}:${listener.address().port}/mcp`,
    address: listener.address(),
    async close() {
      await Promise.all([...transports].map(transport => transport.close()));
      await new Promise((resolve, reject) => listener.close(error => error ? reject(error) : resolve()));
    },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const bridge = await startBridge({
    port: process.env.DOT_BRIDGE_PORT ?? 8787,
    gatewayPort: process.env.DOT_BRIDGE_GATEWAY_PORT ?? 18789,
  });
  process.stdout.write(`dot-openclaw-bridge ${VERSION} listening at ${bridge.url}; health only\n`);
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, async () => {
    await bridge.close();
    process.exit(0);
  });
}
