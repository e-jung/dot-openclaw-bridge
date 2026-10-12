import test from 'node:test';
import assert from 'node:assert/strict';
import { verify, createPublicKey, createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GatewayClient, buildDeviceAuthPayloadV3 } from '@openclaw/gateway-client';
import { WebSocketServer } from 'ws';
import { generateBridgeIdentity } from '../src/official-client.mjs';
import { storedIdentity } from '../src/standing-identity.mjs';
import { createOwnerAuthRuntime, OWNER_SCOPES } from '../src/owner-auth.mjs';
import { OWNER_ID } from '../src/session-policy.mjs';
import { SESSION_ADVERTISED_METHODS } from '../src/session-gateway.mjs';

async function fixture(t, { owner = OWNER_ID, helloPatch = {} } = {}) {
  const wire = [];
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise(resolve => server.once('listening', resolve));
  const identity = generateBridgeIdentity();
  server.on('connection', (socket, upgrade) => {
    const nonce = 'test-challenge'; const ts = Date.now();
    assert.equal(upgrade.headers['authorization'], undefined);
    socket.send(JSON.stringify({ type: 'event', event: 'connect.challenge', payload: { nonce, ts } }));
    socket.on('message', raw => {
      const r = JSON.parse(String(raw)); wire.push(r);
      let payload;
      if (r.method === 'connect') {
        assert.deepEqual(r.params.scopes, OWNER_SCOPES);
        assert.equal(r.params.client.platform, 'linux');
        assert.equal(r.params.client.deviceFamily, 'Linux');
        assert.equal(r.params.client.displayName, 'Dot bridge temporary owner-auth backend');
        assert.equal(r.params.auth, undefined);
        assert.equal(r.params.device.id, identity.deviceId);
        assert.equal(r.params.device.signedAt, ts);
        assert.equal(r.params.device.nonce, nonce);
        const signed = buildDeviceAuthPayloadV3({ deviceId: identity.deviceId, clientId: r.params.client.id,
          clientMode: r.params.client.mode, role: r.params.role, scopes: r.params.scopes,
          signedAtMs: ts, token: null, nonce, platform: r.params.client.platform, deviceFamily: r.params.client.deviceFamily });
        assert.equal(verify(null, Buffer.from(signed), identity.publicKeyPem, Buffer.from(r.params.device.signature, 'base64url')), true);
        const rawKey = createPublicKey(identity.publicKeyPem).export({ type: 'spki', format: 'der' }).subarray(-32);
        assert.equal(r.params.device.publicKey, rawKey.toString('base64url'));
        assert.equal(createHash('sha256').update(rawKey).digest('hex'), identity.deviceId);
        payload = { type: 'hello-ok', protocol: 4, server: { version: '2026.9.9', connId: 'mock' },
          auth: { method: 'tailscale', role: 'operator', scopes: OWNER_SCOPES, deviceToken: 'MOCK-ISSUED-TOKEN' },
          features: { methods: SESSION_ADVERTISED_METHODS, events: [] }, snapshot: {},
          policy: { maxPayload: 1048576, maxBufferedBytes: 1048576, tickIntervalMs: 30000 }, ...helloPatch };
      } else {
        assert.equal(r.method, 'users.self');
        payload = { profile: { id: owner, mergedInto: null } };
      }
      socket.send(JSON.stringify({ type: 'res', id: r.id, ok: true, payload }));
    });
  });
  // Inject only the test transport. Production endpoint is not caller-selectable.
  class LocalClient extends GatewayClient {
    constructor(options) {
      assert.equal(options.edgeAuthHeaders['X-OpenClaw-Scopes'], 'operator.read,operator.write');
      // Edge identity headers require real WSS; this loopback-only mock tests
      // device signatures and RPC gates, not a production proxy.
      super({ ...options, edgeAuthHeaders: undefined, url: `ws://127.0.0.1:${server.address().port}` });
    }
  }
  const runtime = createOwnerAuthRuntime({ GatewayClient: LocalClient, identity, policy: { agent: 'main' } });
  t.after(async () => { runtime.dispose(); for (const socket of server.clients) socket.terminate(); await new Promise(resolve => server.close(resolve)); });
  return { runtime, wire, server };
}

test('official client signs the existing identity, verifies owner and reconnects without token reuse or session operations', async t => {
  const f = await fixture(t);
  await f.runtime.open(); await f.runtime.reconnect();
  assert.equal(f.runtime.proof().owner_verified, true);
  assert.deepEqual(f.wire.map(r => r.method), ['connect', 'users.self', 'connect', 'users.self']);
  for (const socket of f.server.clients) socket.terminate();
  await new Promise(resolve => setTimeout(resolve, 30));
  assert.equal(f.runtime.proof().owner_verified, false);
});

test('official wire client rejects changed owner and broader scopes before exposing a backend', async t => {
  const owner = await fixture(t, { owner: 'other-owner' });
  await assert.rejects(owner.runtime.open(), /OWNER_IDENTITY_REJECTED/);
  assert.equal(owner.runtime.proof().owner_verified, false);
  const scopes = await fixture(t, { helloPatch: { auth: { method: 'tailscale', role: 'operator', scopes: [...OWNER_SCOPES, 'operator.admin'] } } });
  await assert.rejects(scopes.runtime.open(), /OWNER_HELLO_REJECTED/);
  assert.deepEqual(scopes.wire.map(r => r.method), ['connect']);
});

test('public-client identity format reloads unchanged through the existing private identity store', () => {
  const root = mkdtempSync(join(tmpdir(), 'bridge-official-identity-'));
  const dir = join(root, 'credentials'); mkdirSync(dir, { mode: 0o700 });
  const path = join(dir, 'device.json');
  const identity = generateBridgeIdentity();
  writeFileSync(path, JSON.stringify(identity), { mode: 0o600 });
  const before = readFileSync(path);
  assert.deepEqual(storedIdentity(() => { throw new Error('must not re-enroll'); }, { path }), identity);
  assert.deepEqual(readFileSync(path), before);
});
