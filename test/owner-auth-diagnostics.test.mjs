import test from 'node:test';
import assert from 'node:assert/strict';
import { GatewayClientRequestError as NativeRequestError, GatewayClientRequestTimeoutError as NativeTimeoutError } from '@openclaw/gateway-client';
import { buildPairingConnectErrorDetails as pairingDetails, ConnectErrorDetailCodes as NativeDetailCodes } from '@openclaw/gateway-protocol/connect-error-details';
import { createOwnerAuthRuntime, OWNER_SCOPES } from '../src/owner-auth.mjs';
import { ownerAuthFailureReport } from '../src/owner-auth-supervisor.mjs';
import { OWNER_ID } from '../src/session-policy.mjs';
import { SESSION_ADVERTISED_METHODS } from '../src/session-gateway.mjs';
// Internal transport classes are not public exports. Exercise their fixed
// categories without importing private package or CLI build artifacts.
class GatewayWebSocketTransportConfigurationError extends Error {}
class GatewayWebSocketTlsPinError extends Error {}
const NativeTransportError = GatewayWebSocketTransportConfigurationError;
const NativeTlsError = GatewayWebSocketTlsPinError;
const DEVICE = 'a'.repeat(64);
const REQUEST = '47fb9a4c-65c7-4541-9ef6-bd999a21ff0b';
const SECRET = 'NEVER-EMIT-MOCK-SECRET';
const goodHello = { protocol: 4, auth: { method: 'tailscale', role: 'operator', scopes: OWNER_SCOPES, deviceToken: SECRET },
  features: { methods: SESSION_ADVERTISED_METHODS } };
const details = patch => pairingDetails({ reason: 'not-paired', requestId: REQUEST, deviceId: DEVICE,
  requestedRole: 'operator', requestedScopes: OWNER_SCOPES, ...patch });
const nativeError = d => new NativeRequestError({ code: 'NOT_PAIRED', message: SECRET, details: d });

function fixture(start, request = async () => ({ profile: { id: OWNER_ID, mergedInto: null } })) {
  const clients = []; const wire = [];
  class MockClient {
    constructor(options) { this.options = options; this.stops = 0; clients.push(this); }
    start() { start?.(this.options); }
    stop() {
      this.stops++;
      if (this.stops === 1) {
        // Pinned beginStop notifies while connectSent && !helloReceived.
        this.options.onConnectError(new Error(`gateway client stopped ${SECRET}`));
        this.options.onClose(1008, SECRET, {});
      }
    }
    async request(method, params) { wire.push({ method, params }); return request(); }
  }
  const runtime = createOwnerAuthRuntime({ GatewayClient: MockClient,
    identity: { deviceId: DEVICE, privateKeyPem: SECRET, publicKeyPem: 'DUMMY-NOT-A-KEY' }, policy: { agent: 'main' }, timeoutMs: 20 });
  return { runtime, clients, wire };
}

async function rejected(error, expectedCode, category, extra = {}) {
  const f = fixture(options => options.onConnectError(error));
  try {
    let report;
    await assert.rejects(f.runtime.open(), e => {
      report = ownerAuthFailureReport(e);
      assert.equal(report.error, expectedCode);
      assert.equal(report.diagnostic.category, category);
      for (const [field, value] of Object.entries(extra)) assert.deepEqual(report.diagnostic[field], value);
      assert.doesNotMatch(JSON.stringify(report), new RegExp(SECRET));
      return true;
    });
    assert.equal(f.runtime.proof().owner_verified, false);
    assert.equal(f.wire.length, 0);
    assert.equal(f.clients[0].stops, 1);
    return report;
  } finally { f.runtime.dispose(); }
}

test('native pairing error survives reentrant stop, with only exact bound public selectors', async () => {
  const d = { ...details(), token: SECRET, headers: { Authorization: SECRET }, privateKey: SECRET, extra: { secret: SECRET } };
  const report = await rejected(nativeError(d), 'OWNER_DEVICE_APPROVAL_REQUIRED', 'pairing-required', { detail_code: 'PAIRING_REQUIRED', gateway_code: 'NOT_PAIRED' });
  assert.deepEqual(report.pending, { request_id: REQUEST, device_id: DEVICE, role: 'operator', scopes: OWNER_SCOPES, client: 'gateway-client', mode: 'backend' });
  assert.deepEqual(report.diagnostic.pairing_fields, { request_id: 'valid', device_id: 'valid', role: 'valid', scopes: 'valid' });
});

test('native optional or malformed pairing fields never yield an approval selector', async () => {
  for (const [patch, field, state] of [
    [{ requestId: undefined }, 'request_id', 'missing'], [{ requestId: `bad / ${SECRET}` }, 'request_id', 'invalid'],
    [{ deviceId: undefined }, 'device_id', 'missing'], [{ deviceId: 'b'.repeat(64) }, 'device_id', 'invalid'],
    [{ requestedRole: undefined }, 'role', 'missing'], [{ requestedRole: 'node' }, 'role', 'invalid'],
    [{ requestedScopes: undefined }, 'scopes', 'missing'], [{ requestedScopes: SECRET }, 'scopes', 'invalid'],
  ]) {
    // Builder normalizes malformed fields away; injected wire mutations also
    // exercise actual client preservation of malformed details unchanged.
    const wireDetails = { ...details(), ...patch };
    const report = await rejected(nativeError(wireDetails), 'OWNER_PAIRING_DETAILS_INVALID', 'pairing-details-invalid');
    assert.equal(report.diagnostic.pairing_fields[field], state); assert.equal(report.pending, undefined);
  }
  const report = await rejected(nativeError(details({ requestId: undefined })), 'OWNER_PAIRING_DETAILS_INVALID', 'pairing-details-invalid');
  assert.equal(report.diagnostic.pairing_fields.request_id, 'missing');
});

test('pairing scope mismatches and native auth scope mismatch stay distinct and fail closed', async () => {
  for (const scopes of [['operator.read'], [...OWNER_SCOPES, 'operator.admin'], ['operator.read', 'operator.read']]) {
    const report = await rejected(nativeError(details({ requestedScopes: scopes })), 'OWNER_SCOPE_MISMATCH', 'scope-mismatch');
    assert.equal(report.pending, undefined); assert.equal(report.diagnostic.pairing_fields.scopes, 'invalid');
  }
  await rejected(new NativeRequestError({ code: 'FORBIDDEN', message: SECRET, details: { code: 'AUTH_SCOPE_MISMATCH' } }),
    'OWNER_SCOPE_MISMATCH', 'scope-mismatch', { detail_code: 'AUTH_SCOPE_MISMATCH' });
});

test('native authentication codes are allowlisted, never relabeled as pairing or transport', async () => {
  for (const code of Object.values(NativeDetailCodes).filter(code => code.startsWith('AUTH_') && code !== 'AUTH_SCOPE_MISMATCH' || code.startsWith('DEVICE_AUTH_'))) {
    const report = await rejected(new NativeRequestError({ code: 'INVALID_REQUEST', message: SECRET, details: { code, token: SECRET } }),
      'OWNER_AUTH_REJECTED', 'authentication-failed', { detail_code: code });
    assert.equal(report.pending, undefined);
  }
  await rejected(new NativeRequestError({ code: 'INVALID_REQUEST', message: SECRET, details: { code: 'PROTOCOL_MISMATCH' } }),
    'OWNER_GATEWAY_REJECTED', 'gateway-contract-rejected');
});

test('native upgrade, transport-policy, timeout and Node TLS/network error shapes are safely classified', async () => {
  await rejected(new NativeRequestError({ code: 'UNAVAILABLE', message: SECRET, details: {
    reason: 'websocket-upgrade-rejected', httpStatus: 403, location: `https://example.invalid/${SECRET}`, gatewayErrorMessage: SECRET,
  } }), 'OWNER_TRANSPORT_FAILED', 'websocket-upgrade-rejected', { http_status: 403 });
  await rejected(new NativeTransportError(SECRET), 'OWNER_TRANSPORT_FAILED', 'transport-policy-rejected');
  await rejected(new NativeTlsError(SECRET), 'OWNER_TLS_FAILED', 'tls-failed');
  await rejected(new NativeTimeoutError({ method: 'connect', timeoutMs: 5000, requestSent: true }), 'OWNER_AUTH_TIMEOUT', 'timeout');
  for (const code of ['ECONNREFUSED', 'ENOTFOUND', 'ETIMEDOUT']) await rejected(Object.assign(new Error(SECRET), { code }),
    'OWNER_TRANSPORT_FAILED', 'transport-failed', { transport_code: code });
  for (const code of ['ERR_TLS_CERT_ALTNAME_INVALID', 'CERT_HAS_EXPIRED', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE']) await rejected(Object.assign(new Error(SECRET), { code }),
    'OWNER_TLS_FAILED', 'tls-failed', { transport_code: code });
});

test('missing structured details, legacy text and unknown codes cannot manufacture pending selectors', async () => {
  const report = await rejected(new NativeRequestError({ code: 'NOT_PAIRED', message: `device pairing required (requestId: ${REQUEST}) ${SECRET}` }),
    'OWNER_PAIRING_DETAILS_INVALID', 'pairing-details-missing');
  assert.equal(report.pending, undefined);
  await rejected(Object.assign(new Error(SECRET), { code: SECRET, details: { code: `AUTH_${SECRET}` } }), 'OWNER_CONNECT_UNKNOWN', 'connect-failure-unknown');
  assert.deepEqual(ownerAuthFailureReport(Object.assign(new Error(SECRET), { headers: { Authorization: SECRET } })), { error: 'OWNER_SUPERVISOR_FAILED' });
});

test('native closeInfo connectError preserves pairing; an unstructured pre-hello close is transport-only', async () => {
  for (const info of [{ connectError: nativeError(details()) }, {}]) {
    const f = fixture(o => o.onClose(1008, `${SECRET} pairing required`, info));
    try {
      await assert.rejects(f.runtime.open(), e => {
        const report = ownerAuthFailureReport(e);
        assert.equal(report.error, info.connectError ? 'OWNER_DEVICE_APPROVAL_REQUIRED' : 'OWNER_TRANSPORT_FAILED');
        assert.doesNotMatch(JSON.stringify(report), new RegExp(SECRET)); return true;
      });
      assert.equal(f.wire.length, 0);
    } finally { f.runtime.dispose(); }
  }
});

test('deadline and thrown start errors keep primary safe diagnostics despite stop callbacks', async () => {
  const timed = fixture();
  try { await assert.rejects(timed.runtime.open(), e => e.code === 'OWNER_AUTH_TIMEOUT' && e.diagnostic.category === 'timeout'); }
  finally { timed.runtime.dispose(); }
  const thrown = fixture(() => { throw Object.assign(new Error(SECRET), { code: 'ECONNRESET' }); });
  try { await assert.rejects(thrown.runtime.open(), e => e.code === 'OWNER_TRANSPORT_FAILED' && e.diagnostic.transport_code === 'ECONNRESET'); }
  finally { thrown.runtime.dispose(); }
});

test('same-key retry ignores stale stopped-client error/close/hello callbacks and rechecks owner', async () => {
  let pairing = true;
  const f = fixture(o => pairing ? o.onConnectError(nativeError(details())) : o.onHelloOk(goodHello));
  try {
    await assert.rejects(f.runtime.open(), /OWNER_DEVICE_APPROVAL_REQUIRED/);
    pairing = false; await f.runtime.open(); await f.runtime.reconnect();
    const old = f.clients[0].options;
    old.onConnectError(nativeError(details())); old.onClose(1008, SECRET, {}); old.onHelloOk({ auth: { deviceToken: SECRET } });
    assert.equal(f.runtime.proof().owner_verified, true);
    assert.deepEqual(f.wire.map(call => call.method), ['users.self', 'users.self']);
    assert.ok(f.clients.every(client => client.options.deviceIdentity === f.clients[0].options.deviceIdentity));
    assert.ok(f.clients.every(client => client.options.token === undefined && client.options.deviceToken === undefined && client.options.hostDeps.loadDeviceAuthToken() === null));
  } finally { f.runtime.dispose(); }
});

test('every fresh hello clears owner readiness and exact method/scope/owner gates remain enforced', async () => {
  let complete;
  const f = fixture(o => o.onHelloOk(goodHello));
  try {
    await f.runtime.open();
    f.clients[0].request = () => new Promise(resolve => { complete = resolve; });
    f.clients[0].options.onHelloOk(goodHello);
    assert.equal(f.runtime.proof().owner_verified, false);
    complete({ profile: { id: OWNER_ID, mergedInto: null } });
    await new Promise(resolve => setImmediate(resolve)); assert.equal(f.runtime.proof().owner_verified, true);
    f.clients[0].options.onHelloOk({ ...goodHello, auth: { method: 'tailscale', role: 'operator', scopes: [...OWNER_SCOPES, 'operator.admin'] } });
    assert.equal(f.runtime.proof().owner_verified, false);
  } finally { f.runtime.dispose(); }
  for (const profile of [{ id: 'gateway-owner', mergedInto: null }, { id: OWNER_ID, mergedInto: 'another-profile' }]) {
    const wrong = fixture(o => o.onHelloOk(goodHello), async () => ({ profile }));
    try { await assert.rejects(wrong.runtime.open(), e => e.code === 'OWNER_IDENTITY_REJECTED' && e.diagnostic.category === 'identity-mismatch'); }
    finally { wrong.runtime.dispose(); }
  }
});
