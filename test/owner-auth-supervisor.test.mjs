import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createOwnerAuthSupervisor } from '../src/owner-auth-supervisor.mjs';
import { createOwnerAuthRuntime, OwnerAuthError, OWNER_SCOPES } from '../src/owner-auth.mjs';
import { OWNER_ID } from '../src/session-policy.mjs';
import { SESSION_ADVERTISED_METHODS } from '../src/session-gateway.mjs';
import { JobStore } from '../src/jobs.mjs';
import { SessionStore } from '../src/session-store.mjs';
import { SessionWorker } from '../src/session-worker.mjs';
const INITIAL = 'Do not use tools. Reply exactly SESSION_TEST_OK.';
const FOLLOWUP = 'Do not use tools. Reply exactly SESSION_FOLLOWUP_OK.';

function fixture(t, overrides = {}) {
  let clock = Date.now(); let verified = false; let pending = true; let owner = OWNER_ID; let jobEnabled = false;
  let preparations = 0; let starts = 0; let disposed = 0; let runnerClosed = 0; let ticks = 0;
  const policy = { enabled: true, kind: 'sessions', owner: OWNER_ID, agent: 'main', expiresAt: new Date(clock + 1800_000).toISOString(),
    timeoutSeconds: 120, createTasks: [INITIAL], followupTasks: [FOLLOWUP], maxCreations: 1, maxFollowups: 1, maxAssignments: 1, allowedSessionKeys: [] };
  let approval = policy;
  const calls = []; const backend = { verifyOwner: async () => { if (!verified || owner !== OWNER_ID) throw new Error(); } };
  const runtime = {
    async open() { calls.push('open'); verified = false; if (pending) throw new OwnerAuthError('OWNER_DEVICE_APPROVAL_REQUIRED', { request_id: 'mock-exact-request', device_id: 'mock-public-device' }); verified = owner === OWNER_ID; await backend.verifyOwner(); return backend; },
    async reconnect() { calls.push('reconnect'); verified = owner === OWNER_ID; await backend.verifyOwner(); return backend; },
    proof: () => ({ device_id: 'mock-public-device', owner_verified: verified, owner_id: verified ? OWNER_ID : null }),
    dispose() { disposed++; verified = false; },
  };
  let seen;
  const supervisor = createOwnerAuthSupervisor({ ownerEnrollmentApproved: true,
    prepareRuntime: async () => { preparations++; return runtime; }, sessionApproval: () => approval, jobApproval: () => jobEnabled ? {} : null,
    sessionRunner: async args => { starts++; seen = args; return { tick: async () => { ticks++; }, heartbeat() {}, close() { runnerClosed++; } }; },
    now: () => clock, ...overrides });
  t.after(() => supervisor.close());
  return { supervisor, runtime, backend, policy, calls, pending: value => { pending = value; }, owner: value => { owner = value; },
    approval: value => { approval = value; }, jobs: value => { jobEnabled = value; }, advance: ms => { clock += ms; },
    counts: () => ({ preparations, starts, disposed, runnerClosed, ticks }), seen: () => seen };
}
async function proven(f) { f.pending(false); await f.supervisor.authenticate(); await f.supervisor.proveReconnect(); }

test('supervisor requires enrollment permission; CLI refuses noninteractive or unapproved launch before live preparation', () => {
  let invoked = false;
  assert.throws(() => createOwnerAuthSupervisor({ prepareRuntime: () => { invoked = true; } }), /OWNER_ENROLLMENT_NOT_APPROVED/);
  assert.equal(invoked, false);
  for (const args of [[], ['--enrollment-approved']]) {
    const result = spawnSync(process.execPath, ['src/owner-auth-supervisor.mjs', ...args], { encoding: 'utf8' });
    assert.equal(result.status, 1); assert.match(result.stderr, /OWNER_ENROLLMENT_NOT_APPROVED/); assert.equal(result.stdout, '');
  }
});

test('pairing wait, owner proof, reconnect and worker use one runtime and same authenticated backend', async t => {
  const f = fixture(t);
  await assert.rejects(f.supervisor.authenticate(), e => e.pending.request_id === 'mock-exact-request');
  assert.equal(f.counts().starts, 0);
  await proven(f);
  await f.supervisor.startSessions({ sessionTestApproved: true });
  await f.supervisor.tick();
  assert.deepEqual(f.calls, ['open', 'open', 'reconnect']);
  assert.equal(f.counts().preparations, 1); assert.equal(f.counts().starts, 1); assert.equal(f.counts().ticks, 1);
  assert.equal(f.seen().gateway, f.backend);
  await assert.rejects(f.supervisor.startSessions({ sessionTestApproved: true }), /OWNER_SESSION_STAGE_CONSUMED/);
  await assert.rejects(f.supervisor.authenticate(), /OWNER_SESSION_STAGE_CONSUMED/);
  f.supervisor.close(); assert.equal(f.counts().disposed, 1); assert.equal(f.counts().runnerClosed, 1);
});

test('session worker cannot start without reconnect proof, separate approval, or with job admission enabled', async t => {
  const f = fixture(t); f.pending(false);
  await f.supervisor.authenticate();
  await assert.rejects(f.supervisor.startSessions({ sessionTestApproved: true }), /OWNER_RECONNECT_NOT_READY/);
  await f.supervisor.proveReconnect();
  await assert.rejects(f.supervisor.startSessions(), /SESSION_TEST_NOT_APPROVED/);
  f.jobs(true);
  await assert.rejects(f.supervisor.startSessions({ sessionTestApproved: true }), /JOB_ADMISSION_MUST_BE_DISABLED/);
  f.jobs(false); f.approval(null);
  await assert.rejects(f.supervisor.startSessions({ sessionTestApproved: true }), /SESSION_TEST_NOT_APPROVED/);
  assert.equal(f.counts().starts, 0);
});

test('expired, broader, or altered task/target test policies never start a session worker', async t => {
  const f = fixture(t); await proven(f);
  for (const patch of [{ expiresAt: new Date(Date.now() - 1000).toISOString() },
    { expiresAt: new Date(Date.now() + 3600_000).toISOString() }, { createTasks: ['Another task'] },
    { followupTasks: [] }, { allowedSessionKeys: ['agent:main:existing'] }, { maxAssignments: 0 }]) {
    f.approval({ ...f.policy, ...patch });
    await assert.rejects(f.supervisor.startSessions({ sessionTestApproved: true }), /SESSION_TEST_NOT_APPROVED/);
  }
  // A fresh 30-minute policy is still invalid if it outlives this retained-key trial.
  f.advance(10_000);
  f.approval({ ...f.policy, expiresAt: new Date(Date.parse(f.policy.expiresAt) + 1000).toISOString() });
  await assert.rejects(f.supervisor.startSessions({ sessionTestApproved: true }), /SESSION_TEST_NOT_APPROVED/);
  assert.equal(f.counts().starts, 0);
});

test('changed owner, renewed policy, or trial expiry stop access without regenerating an identity or renewing approval', async t => {
  const wrong = fixture(t); await proven(wrong); wrong.owner('other');
  await assert.rejects(wrong.supervisor.startSessions({ sessionTestApproved: true })); assert.equal(wrong.counts().starts, 0);
  const renewed = fixture(t); await proven(renewed); await renewed.supervisor.startSessions({ sessionTestApproved: true });
  renewed.advance(1000); renewed.approval({ ...renewed.policy, expiresAt: new Date(Date.parse(renewed.policy.expiresAt) + 500).toISOString() });
  await assert.rejects(renewed.supervisor.tick(), /SESSION_TEST_NOT_APPROVED/);
  assert.equal(renewed.counts().runnerClosed, 1); assert.equal(renewed.counts().disposed, 1);
  const expired = fixture(t); expired.advance(1800_000);
  await assert.rejects(expired.supervisor.authenticate(), /OWNER_TRIAL_EXPIRED/);
  assert.equal(expired.counts().preparations, 0);
});

test('stop during asynchronous runtime preparation disposes the prepared identity without starting a connection', async t => {
  let complete; let disposed = 0; let opened = 0;
  const f = fixture(t, { prepareRuntime: () => new Promise(resolve => { complete = resolve; }) });
  const waiting = f.supervisor.authenticate();
  f.supervisor.close();
  complete({ open: () => { opened++; }, dispose: () => { disposed++; } });
  await assert.rejects(waiting, /OWNER_TRIAL_STOPPED/);
  assert.equal(disposed, 1); assert.equal(opened, 0);
});

test('supervisor connects native-auth mock to the real session ledger/worker without token transport or rekeying', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'owner-supervisor-mock-'));
  const options = []; const wire = []; const rows = new Map(); const replies = new Map();
  const identity = { deviceId: 'mock-public-device', publicKeyPem: 'MOCK-PUBLIC', privateKeyPem: 'MOCK-PRIVATE' };
  const now = Date.now();
  const policy = { enabled: true, kind: 'sessions', owner: OWNER_ID, agent: 'main', expiresAt: new Date(now + 1800_000).toISOString(),
    timeoutSeconds: 120, createTasks: [INITIAL], followupTasks: [FOLLOWUP], maxCreations: 1, maxFollowups: 1, maxAssignments: 1, allowedSessionKeys: [] };
  class MockClient {
    constructor(opts) { this.options = opts; options.push(opts); }
    start() { this.options.onHelloOk({ protocol: 4, auth: { method: 'tailscale', role: 'operator', scopes: OWNER_SCOPES }, features: { methods: SESSION_ADVERTISED_METHODS } }); }
    stop() {}
    async request(method, args) {
      wire.push({ method, args });
      if (method === 'users.self') return { profile: { id: OWNER_ID, mergedInto: null } };
      if (method === 'sessions.describe') return { session: rows.get(args.key) };
      if (method === 'sessions.create') {
        rows.set(args.key, { key: args.key, sessionId: 'mock-session', status: 'done' }); replies.set('mock-first-run', 'SESSION_TEST_OK');
        return { ok: true, key: args.key, runId: 'mock-first-run' };
      }
      if (method === 'sessions.assignOwner') { rows.get(args.key).owner = { actor: args.owner }; return { ok: true, key: args.key, owner: { actor: args.owner } }; }
      if (method === 'sessions.get') return { messages: [{ role: 'assistant', content: 'SESSION_TEST_OK' }] };
      if (method === 'sessions.send') { replies.set('mock-followup-run', 'SESSION_FOLLOWUP_OK'); return { status: 'started', runId: 'mock-followup-run' }; }
      if (method === 'agent.wait') return { runId: args.runId, status: 'ok', stopReason: 'stop', endedAt: Date.now(), terminalReply: { disposition: 'visible', text: replies.get(args.runId) } };
      throw new Error('Unexpected mock RPC');
    }
  }
  let jobs; let store;
  const supervisor = createOwnerAuthSupervisor({ ownerEnrollmentApproved: true, jobApproval: () => null, sessionApproval: () => policy,
    prepareRuntime: async ({ policy: authPolicy }) => createOwnerAuthRuntime({ GatewayClient: MockClient, identity, policy: authPolicy }),
    sessionRunner: async ({ gateway, policy: testPolicy, approval }) => {
      jobs = new JobStore(join(dir, 'jobs.sqlite')); store = new SessionStore(jobs);
      const worker = new SessionWorker(store, gateway, testPolicy, { approval });
      return { tick: () => worker.tick(), heartbeat: () => jobs.heartbeat(worker.token), close() { worker.close(); jobs.close(); } };
    } });
  t.after(() => { supervisor.close(); rmSync(dir, { recursive: true, force: true }); });
  await supervisor.authenticate(); await supervisor.proveReconnect();
  assert.equal(jobs, undefined);
  await supervisor.startSessions({ sessionTestApproved: true }); await supervisor.tick();
  const create = store.enqueue('create_session', { task: INITIAL, idempotency_key: 'supervised-create-01' }, policy);
  await supervisor.tick(); const created = store.get({ operation_id: create.operation_id }, policy);
  assert.equal(created.result.response, 'SESSION_TEST_OK');
  const assign = store.enqueue('assign_session_to_me', { session_key: created.session_key, idempotency_key: 'supervised-assign-01' }, policy);
  await supervisor.tick(); assert.equal(store.get({ operation_id: assign.operation_id }, policy).result.owner_id, OWNER_ID);
  const read = store.enqueue('get_session', { session_key: created.session_key, limit: 10 }, policy);
  await supervisor.tick(); assert.equal(store.get({ operation_id: read.operation_id }, policy).result.messages[0].text, 'SESSION_TEST_OK');
  const send = store.enqueue('send_session_message', { session_key: created.session_key, message: FOLLOWUP, idempotency_key: 'supervised-followup-01' }, policy);
  await supervisor.tick(); assert.equal(store.get({ operation_id: send.operation_id }, policy).result.response, 'SESSION_FOLLOWUP_OK');
  assert.equal(options.length, 2); assert.equal(options[0].deviceIdentity, options[1].deviceIdentity);
  assert.ok(options.every(option => option.token === undefined && option.deviceToken === undefined && option.hostDeps.loadDeviceAuthToken() === null));
  assert.deepEqual(wire.filter(call => ['sessions.create', 'sessions.assignOwner', 'sessions.send'].includes(call.method)).map(call => call.method),
    ['sessions.create', 'sessions.assignOwner', 'sessions.send']);
});
