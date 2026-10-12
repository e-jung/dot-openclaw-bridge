import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { SESSION_API_PINS } from './session-api-pins.mjs';
import { createSessionGateway, SESSION_ADVERTISED_METHODS } from './session-gateway.mjs';

export const INSTALLED_ROOT = `${homedir()}/.local/lib/node_modules/openclaw`;
// Fail closed on upgrades: these are the actual inspected installed artifacts.
export const PINNED_MODULES = {
  client: ['dist/client-nkyTFQ4I.mjs', '40dfca5c16697712e7327d7d5364018e5f75807ce2f6da3c6a967bdb5d2f095f'],
  secrets: ['dist/resolve-DZ2qHlDY.mjs', '9366492fcff17fd3afb54e3dc2d2957330337327c8bbc524c5006ac0d0073f8d'],
};
export class GatewayError extends Error {
  constructor(code) { super(code); this.code = code; }
}
async function installedImport(kind) {
  const [file, hash] = PINNED_MODULES[kind];
  const path = `${INSTALLED_ROOT}/${file}`;
  if (createHash('sha256').update(await readFile(path)).digest('hex') !== hash) throw new GatewayError('GATEWAY_VERSION_CHANGED');
  return import(pathToFileURL(path).href);
}

// Only an independently started, approved local worker constructs this backend.
// The stdio frontend does not resolve or possess Gateway credentials.
export async function connectLocalGateway(approval) {
  let token;
  try {
    const pkg = JSON.parse(await readFile(`${INSTALLED_ROOT}/package.json`, 'utf8'));
    if (pkg.version !== '2026.9.7') throw new GatewayError('GATEWAY_VERSION_CHANGED');
    if (approval.kind === 'sessions') {
      for (const [name, hash] of Object.entries(SESSION_API_PINS)) {
        if (createHash('sha256').update(await readFile(`${INSTALLED_ROOT}/dist/${name}`)).digest('hex') !== hash) throw new GatewayError('GATEWAY_VERSION_CHANGED');
      }
    }
    const config = JSON.parse(await readFile(`${homedir()}/.openclaw/openclaw.json`, 'utf8'));
    const gateway = config.gateway;
    if (gateway?.mode !== 'local' || gateway?.bind !== 'loopback' || gateway?.port !== 18789 || gateway?.auth?.mode !== 'token') throw new GatewayError('GATEWAY_CONFIG_CHANGED');
    const agents = config.agents?.entries ?? {};
    const listed = config.agents?.list ?? [];
    if (!Object.hasOwn(agents, approval.agent) && !listed.some(a => a.id === approval.agent)) throw new GatewayError('AGENT_NOT_CONFIGURED');
    const ref = gateway.auth.token;
    // This host uses a store SecretRef. No exec provider, device grant or token copy.
    if (ref?.source !== 'store') throw new GatewayError('GATEWAY_AUTH_CHANGED');
    token = await (await installedImport('secrets')).n(ref, { config, env: process.env });
    if (typeof token !== 'string' || !token.trim()) throw new GatewayError('GATEWAY_AUTH_UNAVAILABLE');
    const { t: GatewayClient } = await installedImport('client');
    return await createGatewayBackend(approval, { GatewayClient, token });
  } catch {
    token = undefined;
    throw new GatewayError('GATEWAY_CONNECT_FAILED');
  }
}

// Test seam: the production caller always supplies the verified installed client
// and fixed loopback URL above. Never reachable through MCP arguments.
export async function createGatewayBackend(approval, { GatewayClient, token,
  url = 'ws://127.0.0.1:18789', now = Date.now }) {
  let client;
  let connected = false;
  let epoch = 0;
  const sessions = approval.kind === 'sessions';
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new GatewayError('GATEWAY_CONNECT_FAILED')), 5000);
      client = new GatewayClient({ url, token,
        deviceIdentity: null, sharedStateMode: 'read-only', scopes: sessions ? ['operator.read', 'operator.write'] : ['operator.write'],
        clientName: 'gateway-client', mode: 'backend', clientDisplayName: 'Dot bridge worker',
        minProtocol: 4, maxProtocol: 4, requestTimeoutMs: 5000,
        hostDeps: { logDebug() {}, logError() {}, storeDeviceAuthToken() {}, clearDeviceAuthToken() {} },
        onHelloOk(hello) {
          clearTimeout(timer);
          epoch++;
          connected = (sessions ? SESSION_ADVERTISED_METHODS : ['agent', 'agent.wait', 'sessions.abort']).every(m => hello.features?.methods?.includes(m));
          if (!connected) reject(new GatewayError('GATEWAY_METHOD_UNAVAILABLE'));
          else resolve();
        },
        onClose() { connected = false; epoch++; },
        onConnectError() { connected = false; epoch++; clearTimeout(timer); reject(new GatewayError('GATEWAY_CONNECT_FAILED')); },
      });
      client.start();
    });
    const request = async (method, params, timeoutMs = 5000) => {
      try {
        if (!connected) throw new Error();
        const generation = epoch;
        const value = await client.request(method, params, { timeoutMs, expectFinal: false });
        if (!connected || epoch !== generation) throw new Error();
        return value;
      }
      catch { throw new GatewayError('GATEWAY_REQUEST_UNCERTAIN'); }
    };
    if (sessions) {
      const backend = createSessionGateway(request, approval, text => text.split(token).join('[REDACTED]'));
      await backend.verifyOwner();
      return { ...backend, close() { connected = false; client.stop(); token = undefined; } };
    }
    return {
      // No general RPC interface is returned or exposed as an MCP tool.
      dispatch: row => request('agent', { agentId: approval.agent, sessionKey: row.session_key,
        message: row.task, idempotencyKey: row.run_id, deliver: false,
        timeout: Math.max(1, Math.ceil((row.deadline - now()) / 1000)),
        label: `Dot bridge job ${row.id}` }),
      observe: row => request('agent.wait', { runId: row.run_id, timeoutMs: 0 }),
      abort: row => request('sessions.abort', { key: row.session_key, agentId: row.agent, runId: row.run_id }),
      sanitize: text => text.split(token).join('[REDACTED]'),
      close() { client.stop(); token = undefined; },
    };
  } catch {
    client?.stop(); token = undefined;
    throw new GatewayError('GATEWAY_CONNECT_FAILED');
  }
}
