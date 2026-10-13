import test from 'node:test';
import assert from 'node:assert/strict';
import { createGatewayBackend } from '../src/gateway.mjs';
import { SESSION_METHODS, SESSION_ADVERTISED_METHODS } from '../src/session-gateway.mjs';
import { OWNER_ID } from '../src/session-policy.mjs';
import { GatewayClient } from '@openclaw/gateway-client';
import { WebSocketServer } from 'ws';
const TOKEN = 'MOCK-SESSION-CREDENTIAL';
async function fixture(t, owner = OWNER_ID) {
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise(resolve => server.once('listening', resolve));
  const wire = []; const rows = new Map();
  server.on('connection', socket => {
    socket.send(JSON.stringify({ type: 'event', event: 'connect.challenge', payload: { nonce: 'mock', ts: Date.now() } }));
    socket.on('message', raw => {
      const r = JSON.parse(String(raw)); wire.push(r);
      let payload;
      if (r.method === 'connect') payload = { type: 'hello-ok', protocol: 4, server: { version: '2026.9.7', connId: 'mock' }, features: { methods: SESSION_ADVERTISED_METHODS, events: [] }, snapshot: {}, policy: { maxPayload: 1048576, maxBufferedBytes: 1048576, tickIntervalMs: 30000 } };
      else if (r.method === 'users.self') payload = { profile: { id: owner, mergedInto: null } };
      else if (r.method === 'sessions.create') {
        rows.set(r.params.key, { key: r.params.key, sessionId: 'mock-session', status: 'done' });
        payload = { ok: true, key: r.params.key, runId: 'mock-run', runStarted: true };
      } else if (r.method === 'sessions.describe') payload = { session: rows.get(r.params.key) ?? null };
      else if (r.method === 'sessions.assignOwner') payload = { ok: true, key: r.params.key, owner: { actor: r.params.owner } };
      else if (r.method === 'sessions.send') payload = { status: 'started', runId: r.params.idempotencyKey };
      else if (r.method === 'sessions.get') payload = { messages: [{ role: 'assistant', content: 'OK ' + TOKEN }] };
      else if (r.method === 'sessions.list') payload = { sessions: [...rows.values()] };
      else if (r.method === 'agent.wait') payload = { runId: r.params.runId, status: 'ok', endedAt: Date.now(), terminalReply: { disposition: 'visible', text: 'OK ' + TOKEN } };
      else if (r.method === 'sessions.abort') payload = { status: 'aborted', abortedRunId: r.params.runId };
      else throw new Error('Unexpected RPC');
      socket.send(JSON.stringify({ type: 'res', id: r.id, ok: true, payload }));
    });
  });
  t.after(async () => { for (const socket of server.clients) socket.terminate(); await new Promise(resolve => server.close(resolve)); });
  return { wire, url: `ws://127.0.0.1:${server.address().port}` };
}

test('official protocol-4 client sends only inspected native session RPCs with no owner/device grant from caller', async t => {
  const f = await fixture(t);
  const policy = { kind: 'sessions', agent: 'main', timeoutSeconds: 120 };
  const g = await createGatewayBackend(policy, { GatewayClient, token: TOKEN, url: f.url });
  try {
    assert.deepEqual(f.wire[0].params.scopes, ['operator.read','operator.write']);
    assert.equal(f.wire[0].params.device, undefined);
    const row = { id: 'operation-uuid', kind: 'create_session', session_key: 'agent:main:dot-session:mock', deadline: Date.now() + 120000 };
    assert.equal((await g.mutate(row, { task: 'Reply OK' }, () => {})).run_id, 'mock-run');
    assert.equal((await g.mutate({ ...row, kind: 'assign_session_to_me' }, {}, () => {})).result.owner_id, OWNER_ID);
    const follow = await g.mutate({ ...row, kind: 'send_session_message' }, { message: 'Follow' }, () => {});
    assert.equal(follow.run_id, row.id);
    const read = await g.read('get_session', { session_key: row.session_key, limit: 2 });
    assert.equal(read.messages[0].text, 'OK [REDACTED]');
    assert.equal((await g.read('list_sessions', { limit: 2, offset: 0 })).sessions.length, 1);
    assert.equal((await g.observe({ ...row, run_id: follow.run_id })).result.response, 'OK [REDACTED]');
    assert.equal((await g.abort({ ...row, run_id: follow.run_id })).abortedRunId, follow.run_id);
    const params = f.wire.find(x => x.method === 'sessions.assignOwner').params;
    assert.deepEqual(params, { key: row.session_key, agentId: 'main', owner: { type: 'human', id: OWNER_ID } });
    assert.ok(f.wire.slice(1).every(x => SESSION_METHODS.includes(x.method)));
    assert.equal(g.request, undefined); assert.equal(g.dispatch, undefined);
  } finally { g.close(); }
});

test('system/shared credential that does not identify the connected owner fails before session access', async t => {
  const f = await fixture(t, 'gateway-owner');
  await assert.rejects(createGatewayBackend({ kind: 'sessions', agent: 'main' }, { GatewayClient, token: TOKEN, url: f.url }), /GATEWAY_CONNECT_FAILED/);
  assert.deepEqual(f.wire.map(x => x.method), ['connect','users.self']);
});

test('reconnect discards in-flight result and rechecks owner instead of trusting earlier hello', async () => {
  let opts; let owner = OWNER_ID; let interrupted = false;
  class MockClient {
    constructor(options) { opts = options; }
    start() { opts.onHelloOk({ features: { methods: SESSION_METHODS } }); }
    stop() {}
    async request(method) {
      if (interrupted) { interrupted = false; opts.onClose(); opts.onHelloOk({ features: { methods: SESSION_METHODS } }); }
      if (method === 'users.self') return { profile: { id: owner } };
      return { sessions: [] };
    }
  }
  const backend = await createGatewayBackend({ kind: 'sessions', agent: 'main' }, { GatewayClient: MockClient, token: TOKEN });
  try {
    interrupted = true; await assert.rejects(backend.read('list_sessions', { limit: 1, offset: 0 }), /GATEWAY_REQUEST_UNCERTAIN/);
    owner = 'other'; await assert.rejects(backend.read('list_sessions', { limit: 1, offset: 0 }), /CONNECTED_OWNER_MISMATCH/);
    opts.onClose(); await assert.rejects(backend.verifyOwner(), /GATEWAY_REQUEST_UNCERTAIN/);
  } finally { backend.close(); }
});
