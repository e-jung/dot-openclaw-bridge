import test from 'node:test';
import assert from 'node:assert/strict';
import { createOwnerAuthRuntime, prepareOwnerAuthRuntime, OWNER_ENDPOINT, OWNER_SCOPES } from '../src/owner-auth.mjs';
import { SESSION_ADVERTISED_METHODS } from '../src/session-gateway.mjs';
import { OWNER_ID } from '../src/session-policy.mjs';
const identity = { deviceId: 'mock-device-public-id', privateKeyPem: 'MOCK-PRIVATE-KEY', publicKeyPem: 'MOCK-PUBLIC-KEY' };
function fixture(overrides = {}) {
  const options = []; const wire = []; let hello; let owner = OWNER_ID; let pending;
  const goodHello = { protocol: 4, auth: { method: 'tailscale', role: 'operator', scopes: OWNER_SCOPES, deviceToken: 'MOCK-RETURNED-TOKEN' }, features: { methods: SESSION_ADVERTISED_METHODS } };
  class MockClient {
    constructor(opts) { options.push(opts); }
    start() { const opts=options.at(-1); if(pending) opts.onConnectError({details:pending}); else opts.onHelloOk(hello ?? {...goodHello,...overrides}); }
    stop() {}
    async request(method, params) { wire.push({method,params}); return {profile:{id:owner,mergedInto:null}}; }
  }
  return { runtime:createOwnerAuthRuntime({GatewayClient:MockClient,identity:{...identity},policy:{agent:'main'}}), options,wire,
    owner:v=>{owner=v;},hello:v=>{hello=v;},pending:v=>{pending=v;},goodHello };
}
test('live preparation refuses absent enrollment authorization before generating keys or networking',async()=>{
  await assert.rejects(prepareOwnerAuthRuntime(),/OWNER_ENROLLMENT_NOT_APPROVED/);
});
test('native identity transport uses fixed WSS, ceiling, read-only storage and no credential fallback',async()=>{
  const f=fixture();const backend=await f.runtime.open();
  const o=f.options[0]; assert.equal(o.url,OWNER_ENDPOINT);assert.equal(o.role,'operator');assert.equal(o.mode,'backend');
  assert.equal(o.hostDeps.loadDeviceAuthToken(),null);assert.equal(o.hostDeps.loadOrCreateDeviceIdentity(),undefined);assert.equal(o.edgeAuthHeaders['X-OpenClaw-Scopes'],'operator.read,operator.write');
  for(const key of ['token','password','deviceToken','bootstrapToken','approvalRuntimeToken','agentRuntimeIdentityToken','tlsFingerprint','origin']) assert.equal(o[key],undefined);
  assert.equal(o.deviceIdentity.privateKeyPem,identity.privateKeyPem);assert.deepEqual(f.wire.map(x=>x.method),['users.self']);
  assert.equal(f.runtime.proof().owner_id,OWNER_ID);assert.equal(backend.request,undefined);assert.equal(backend.dispatch,undefined);f.runtime.dispose();
});
test('wrong auth methods, roles, scopes, protocol or methods fail before owner/session RPCs',async()=>{
  for(const patch of [{auth:{method:'token',role:'operator',scopes:OWNER_SCOPES}},{auth:{method:'tailscale',role:'operator',scopes:[...OWNER_SCOPES,'operator.admin']}},{auth:{method:'tailscale',role:'node',scopes:OWNER_SCOPES}},{auth:{method:'tailscale',role:'operator',scopes:['operator.read']}},{protocol:3},{features:{methods:[]}}]){
    const f=fixture(patch);await assert.rejects(f.runtime.open(),/OWNER_HELLO_REJECTED/);assert.equal(f.wire.length,0);assert.equal(f.runtime.proof().owner_verified,false);f.runtime.dispose();
  }
});
test('server identity mismatch denies backend and clears authenticated readiness',async()=>{
  const f=fixture();f.owner('gateway-owner');await assert.rejects(f.runtime.open(),/OWNER_IDENTITY_REJECTED/);assert.equal(f.runtime.proof().owner_verified,false);assert.deepEqual(f.wire.map(x=>x.method),['users.self']);f.runtime.dispose();
});
test('same-process reconnect keeps dedicated key, offers no issued token and repeats owner gates',async()=>{
  const f=fixture();await f.runtime.open();await f.runtime.reconnect();assert.equal(f.options[0].deviceIdentity,f.options[1].deviceIdentity);
  assert.deepEqual(f.wire.map(x=>x.method),['users.self','users.self']);assert.equal(f.options[1].deviceToken,undefined);
  f.owner('other');await assert.rejects(f.runtime.reconnect(),/OWNER_IDENTITY_REJECTED/);assert.equal(f.runtime.proof().owner_verified,false);f.runtime.dispose();
});
test('pairing response exposes only exact bound public request; no approval or latest selection RPC',async()=>{
  const f=fixture();f.pending({code:'PAIRING_REQUIRED',requestId:'request-uuid',deviceId:identity.deviceId,requestedRole:'operator',requestedScopes:OWNER_SCOPES,token:'PRIVATE'});
  await assert.rejects(f.runtime.open(),e=>{assert.equal(e.code,'OWNER_DEVICE_APPROVAL_REQUIRED');assert.equal(e.pending.request_id,'request-uuid');assert.doesNotMatch(JSON.stringify(e.pending),/PRIVATE|MOCK-PRIVATE|token/);return true;});
  assert.equal(f.wire.length,0);f.pending({code:'PAIRING_REQUIRED',requestId:'request-uuid',deviceId:'another',requestedRole:'operator',requestedScopes:OWNER_SCOPES});
  await assert.rejects(f.runtime.open(),e=>e.pending===null);f.runtime.dispose();
});
test('closed/disposed runtime rejects access, retains no proof and cannot restart',async()=>{
  const f=fixture();const backend=await f.runtime.open();backend.close();await assert.rejects(backend.verifyOwner(),/OWNER_AUTH_UNAVAILABLE/);f.runtime.dispose();
  await assert.rejects(f.runtime.open(),/OWNER_AUTH_DISPOSED/);assert.equal(f.runtime.proof().owner_verified,false);
});
