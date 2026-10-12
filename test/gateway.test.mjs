import test from 'node:test';
import assert from 'node:assert/strict';
import { createGatewayBackend } from '../src/gateway.mjs';

// Official packaged OpenClaw client and its ws dependency. No
// real Gateway/authentication: all frames use a loopback mock and a dummy secret.
import { GatewayClient } from '@openclaw/gateway-client';
import { WebSocketServer } from 'ws';
const SECRET = 'MOCK-ONLY-NOT-A-REAL-CREDENTIAL';

async function mock(t, { missing = false, rejectAuth = false } = {}) {
  const wire = [];
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise(resolve => server.once('listening', resolve));
  server.on('connection', socket => {
    socket.send(JSON.stringify({ type: 'event', event: 'connect.challenge', payload: { nonce: 'mock-nonce', ts: Date.now() } }));
    socket.on('message', raw => {
      const request = JSON.parse(String(raw));
      wire.push(request);
      let payload;
      if (request.method === 'connect') {
        if (rejectAuth) {
          socket.send(JSON.stringify({ type: 'res', id: request.id, ok: false,
            error: { code: 'INVALID_REQUEST', message: 'PRIVATE-AUTH-ERROR ' + SECRET } }));
          return;
        }
        payload = { type: 'hello-ok', protocol: 4,
          server: { version: '2026.9.7', connId: 'mock' },
          features: { methods: missing ? ['health'] : ['agent', 'agent.wait', 'sessions.abort'], events: [] },
          snapshot: {}, policy: { maxPayload: 1048576, maxBufferedBytes: 1048576, tickIntervalMs: 30000 } };
      } else if (request.method === 'agent') payload = { status: 'accepted', runId: request.params.idempotencyKey };
      else if (request.method === 'agent.wait') payload = { runId: request.params.runId, status: 'ok', stopReason: 'stop', endedAt: Date.now(), terminalReply: { disposition: 'visible', text: 'OK' } };
      else if (request.method === 'sessions.abort') payload = { status: 'aborted', abortedRunId: request.params.runId };
      else throw new Error('Unexpected mock RPC');
      socket.send(JSON.stringify({ type: 'res', id: request.id, ok: true, payload }));
    });
  });
  t.after(async () => {
    for (const socket of server.clients) socket.terminate();
    await new Promise(resolve => server.close(resolve));
  });
  return { url: `ws://127.0.0.1:${server.address().port}`, wire };
}

test('official client authenticates to mock with protocol 4 and no device or new grant', async t => {
  const f = await mock(t);
  const backend = await createGatewayBackend({ agent: 'main' }, { GatewayClient, token: SECRET, url: f.url });
  try {
    const connect = f.wire[0];
    assert.equal(connect.method, 'connect');
    assert.equal(connect.params.auth.token, SECRET);
    assert.deepEqual(connect.params.scopes, ['operator.write']);
    assert.equal(connect.params.minProtocol, 4);
    assert.equal(connect.params.maxProtocol, 4);
    assert.equal(connect.params.device, undefined);
    assert.equal(connect.params.client.mode, 'backend');
    assert.equal(backend.sanitize(`result ${SECRET}`), 'result [REDACTED]');
  } finally { backend.close(); }
});

test('only inspected job RPCs and generated selectors are used on the wire', async t => {
  const f = await mock(t);
  const backend = await createGatewayBackend({ agent: 'main' }, { GatewayClient, token: SECRET, url: f.url, now: () => 1000 });
  const row = { id: 'mock-job', agent: 'main', run_id: 'mock-run', session_key: 'agent:main:dot-bridge:mock-job', task: 'Reply OK', deadline: 121000 };
  try {
    assert.equal((await backend.dispatch(row)).status, 'accepted');
    const observed = await backend.observe(row);
    assert.equal(observed.terminalReply.text, 'OK');
    assert.equal(observed.status, 'ok');
    assert.equal(observed.stopReason, 'stop');
    assert.equal((await backend.abort(row)).abortedRunId, 'mock-run');
    const requests = f.wire.slice(1);
    assert.deepEqual(requests.map(x => x.method), ['agent', 'agent.wait', 'sessions.abort']);
    assert.deepEqual(requests[0].params, { agentId: 'main', sessionKey: row.session_key,
      message: row.task, idempotencyKey: row.run_id, deliver: false, timeout: 120, label: 'Dot bridge job mock-job' });
    assert.deepEqual(requests[1].params, { runId: row.run_id, timeoutMs: 0 });
    assert.deepEqual(requests[2].params, { key: row.session_key, agentId: row.agent, runId: row.run_id });
    assert.doesNotMatch(JSON.stringify(requests), /MOCK-ONLY|clearQueued|chat.history|shell/);
  } finally { backend.close(); }
});

test('unsupported methods and auth denial fail closed without leaking upstream errors', async t => {
  for (const options of [{ missing: true }, { rejectAuth: true }]) {
    const f = await mock(t, options);
    await assert.rejects(createGatewayBackend({ agent: 'main' }, { GatewayClient, token: SECRET, url: f.url }), error => {
      assert.equal(error.message, 'GATEWAY_CONNECT_FAILED');
      assert.doesNotMatch(error.message, /PRIVATE|MOCK-ONLY/);
      return true;
    });
    assert.ok(f.wire.every(x => x.method === 'connect'));
  }
});
