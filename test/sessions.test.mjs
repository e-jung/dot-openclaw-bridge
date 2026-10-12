import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { JobStore } from '../src/jobs.mjs';
import { SessionStore } from '../src/session-store.mjs';
import { SessionWorker } from '../src/session-worker.mjs';
import { createSessionGateway } from '../src/session-gateway.mjs';
import { OWNER_ID, SESSION_INPUTS, SESSION_NAMES, loadSessionApproval } from '../src/session-policy.mjs';
import { createMcpServer } from '../src/server.mjs';
const INITIAL = 'Do not use tools. Reply exactly SESSION_TEST_OK.';
const FOLLOW = 'Do not use tools. Reply exactly SESSION_FOLLOWUP_OK.';
function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'dot-session-mock-'));
  let now = Date.now(); let owner = OWNER_ID; let visible = true; let pending = false; let uncertain = false; let current;
  const jobs = new JobStore(join(dir, 'jobs.sqlite'), { now: () => now });
  const store = new SessionStore(jobs);
  const policy = { enabled: true, kind: 'sessions', owner: OWNER_ID, agent: 'main', expiresAt: new Date(now + 1800_000).toISOString(), timeoutSeconds: 120,
    createTasks: [INITIAL], followupTasks: [FOLLOW], maxCreations: 1, maxFollowups: 1, maxAssignments: 1, allowedSessionKeys: [] };
  current = policy;
  const wire = []; const rows = new Map(); const results = new Map();
  const request = async (method, args) => {
    wire.push({ method, args: structuredClone(args) });
    if (method === 'users.self') return { profile: { id: owner, mergedInto: null } };
    if (method === 'sessions.list') return { sessions: visible ? [...rows.values()] : [] };
    if (method === 'sessions.describe') return { session: visible ? rows.get(args.key) ?? null : null };
    if (method === 'sessions.get') return { messages: [
      { role: 'user', content: INITIAL },
      { role: 'assistant', content: [{ type: 'thinking', text: 'PRIVATE-THOUGHT' }, { type: 'text', text: 'SESSION_TEST_OK MOCK-SECRET' }, { type: 'toolCall', arguments: 'PRIVATE-ARGS' }] },
      { role: 'toolResult', content: 'PRIVATE-TOOL-RESULT' },
    ] };
    if (method === 'sessions.create') {
      rows.set(args.key, { key: args.key, sessionId: 'session-uuid', displayName: 'Test session', status: 'done', privatePath: '/secret/path' });
      const runId = 'initial-run'; results.set(runId, 'SESSION_TEST_OK');
      if (uncertain) throw new Error('PRIVATE ERROR MOCK-SECRET');
      return { ok: true, key: args.key, runId, runStarted: true };
    }
    if (method === 'sessions.assignOwner') {
      rows.get(args.key).owner = { actor: args.owner }; return { ok: true, key: args.key, owner: { actor: args.owner } };
    }
    if (method === 'sessions.send') {
      results.set(args.idempotencyKey, 'SESSION_FOLLOWUP_OK');
      if (uncertain) throw new Error('PRIVATE ERROR MOCK-SECRET');
      return { status: 'started', runId: args.idempotencyKey };
    }
    if (method === 'agent.wait') return pending ? { runId: args.runId, status: 'timeout' } : { runId: args.runId, status: 'ok', stopReason: 'stop', endedAt: now,
      terminalReply: { disposition: 'visible', text: results.get(args.runId) ?? '' } };
    if (method === 'sessions.abort') return { status: 'aborted', abortedRunId: args.runId };
    throw new Error('UNEXPECTED RPC');
  };
  const gateway = createSessionGateway(request, policy, s => s.replaceAll('MOCK-SECRET', '[REDACTED]'));
  const worker = new SessionWorker(store, gateway, policy, { approval: () => current });
  t.after(() => { worker.close(); jobs.close(); rmSync(dir, { recursive: true, force: true }); });
  return { dir, jobs, store, policy, worker, gateway, wire, rows, results,
    advance: ms => { now += ms; }, owner: v => { owner = v; }, visible: v => { visible = v; }, pending: v => { pending = v; }, uncertain: v => { uncertain = v; }, approve: v => { current = v; } };
}
const input = { task: INITIAL, idempotency_key: 'session-create-01' };
async function create(f) {
  await f.worker.tick();
  const op = f.store.enqueue('create_session', input, f.policy);
  await f.worker.tick();
  return f.store.get({ operation_id: op.operation_id }, f.policy);
}

test('native create → assign → bounded history → follow-up uses verified identity and exact contracts', async t => {
  const f = fixture(t); const created = await create(f);
  assert.equal(created.status, 'completed'); assert.equal(created.result.response, 'SESSION_TEST_OK');
  assert.match(created.session_key, /^agent:main:dot-session:/);
  const assignment = f.store.enqueue('assign_session_to_me', { session_key: created.session_key, idempotency_key: 'session-assign-01' }, f.policy);
  await f.worker.tick();
  assert.equal(f.store.get({ operation_id: assignment.operation_id }, f.policy).result.owner_id, OWNER_ID);
  const read = f.store.enqueue('get_session', { session_key: created.session_key, limit: 10 }, f.policy);
  await f.worker.tick();
  const result = f.store.get({ operation_id: read.operation_id }, f.policy).result;
  assert.equal(result.session.status, 'done'); assert.equal(result.messages.length, 2);
  assert.match(result.messages[1].text, /\[REDACTED\]/);
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE|secret\/path|MOCK-SECRET|toolResult/);
  const follow = f.store.enqueue('send_session_message', { session_key: created.session_key, message: FOLLOW, idempotency_key: 'session-follow-01' }, f.policy);
  await f.worker.tick();
  assert.equal(f.store.get({ operation_id: follow.operation_id }, f.policy).result.response, 'SESSION_FOLLOWUP_OK');
  assert.equal(f.store.enqueue('assign_session_to_me', { session_key: created.session_key, idempotency_key: 'session-assign-01' }, f.policy).duplicate, true);
  assert.throws(() => f.store.enqueue('assign_session_to_me', { session_key: created.session_key, idempotency_key: 'second-assign-01' }, f.policy), /APPROVAL_EXHAUSTED/);
  assert.throws(() => f.store.enqueue('send_session_message', { session_key: created.session_key, message: FOLLOW, idempotency_key: 'second-follow-01' }, f.policy), /APPROVAL_EXHAUSTED/);
  const writes = f.wire.filter(x => ['sessions.create','sessions.assignOwner','sessions.send'].includes(x.method));
  assert.deepEqual(writes.map(x => x.method), ['sessions.create','sessions.assignOwner','sessions.send']);
  assert.deepEqual(writes[1].args.owner, { type: 'human', id: OWNER_ID });
  assert.equal(writes[0].args.incognito, false); assert.equal(writes[0].args.visibility, 'draft');
  assert.equal(writes[0].args.task, INITIAL); assert.equal(writes[2].args.message, FOLLOW);
  assert.ok(writes.every(x => x.args.agentId === 'main' && x.args.timeoutMs === undefined || x.args.timeoutMs <= 120000));
});

test('identity is server-verified and caller owner, RPC, agent and override fields are rejected', async t => {
  const f = fixture(t); f.owner('gateway-owner'); await f.worker.tick();
  assert.equal(f.store.ready(f.policy), false);
  assert.throws(() => f.store.enqueue('create_session', input, f.policy), /SESSION_ACCESS_DISABLED/);
  assert.equal(f.wire.filter(x => x.method !== 'users.self').length, 0);
  for (const name of SESSION_NAMES) {
    const base = name === 'create_session' ? input : name === 'send_session_message' ? { session_key: 'agent:main:test', message: FOLLOW, idempotency_key: 'follow-test' } : name === 'assign_session_to_me' ? { session_key: 'agent:main:test', idempotency_key: 'assign-test' } : name === 'get_session' ? { session_key: 'agent:main:test' } : name === 'get_session_operation' ? { operation_id: '675b16a1-1a04-4ee8-a5f7-86f918241c45' } : {};
    for (const field of ['owner_id','owner','agent','rpc','shell','timeout','model','visibility']) assert.equal(SESSION_INPUTS[name].safeParse({ ...base, [field]: 'BAD' }).success, false);
  }
});

test('invisible targets deny history, assignment, follow-up and cached response', async t => {
  const f = fixture(t); const created = await create(f); f.visible(false);
  const read = f.store.enqueue('get_session', { session_key: created.session_key }, f.policy);
  await f.worker.tick(); assert.equal(f.store.get({ operation_id: read.operation_id }, f.policy).error, 'SESSION_NOT_VISIBLE');
  assert.equal(f.wire.filter(x => x.method === 'sessions.get').length, 0);
  const assign = f.store.enqueue('assign_session_to_me', { session_key: created.session_key, idempotency_key: 'assign-hidden' }, f.policy);
  await f.worker.tick(); assert.equal(f.store.get({ operation_id: assign.operation_id }, f.policy).error, 'SESSION_NOT_VISIBLE');
  assert.equal(f.wire.filter(x => x.method === 'sessions.assignOwner').length, 0);
  f.advance(1100); assert.equal(f.store.get({ operation_id: created.operation_id }, f.policy).result, null);
  await f.worker.tick(); assert.equal(f.store.get({ operation_id: created.operation_id }, f.policy).result, null);
});

test('duplicate create and follow-up are durably deduplicated across frontend reopen', async t => {
  const f = fixture(t); const created = await create(f);
  const reopenedJobs = new JobStore(join(f.dir, 'jobs.sqlite'), { now: f.jobs.now }); const reopened = new SessionStore(reopenedJobs);
  try {
    assert.equal(reopened.enqueue('create_session', input, f.policy).operation_id, created.operation_id);
    assert.throws(() => reopened.enqueue('create_session', { ...input, task: FOLLOW }, f.policy), /IDEMPOTENCY_CONFLICT/);
    const args = { session_key: created.session_key, message: FOLLOW, idempotency_key: 'follow-reopen-01' };
    const first = f.store.enqueue('send_session_message', args, f.policy);
    assert.equal(reopened.enqueue('send_session_message', args, f.policy).operation_id, first.operation_id);
    await f.worker.tick();
    assert.equal(reopened.enqueue('send_session_message', args, f.policy).duplicate, true);
    assert.throws(() => reopened.enqueue('send_session_message', { ...args, message: INITIAL }, f.policy), /IDEMPOTENCY_CONFLICT/);
    assert.equal(f.wire.filter(x => x.method === 'sessions.create').length, 1);
    assert.equal(f.wire.filter(x => x.method === 'sessions.send').length, 1);
  } finally { reopenedJobs.close(); }
});

test('uncertain create/send never replay, hold concurrency slot and expose only sanitized errors', async t => {
  for (const kind of ['create_session','send_session_message']) {
    const f = fixture(t); let created;
    if (kind === 'send_session_message') created = await create(f); else await f.worker.tick();
    f.uncertain(true);
    const args = kind === 'create_session' ? input : { session_key: created.session_key, message: FOLLOW, idempotency_key: 'uncertain-follow' };
    const op = f.store.enqueue(kind, args, f.policy); await f.worker.tick();
    assert.equal(f.store.get({ operation_id: op.operation_id }, f.policy).status, 'unknown');
    for (let i = 0; i < 3; i++) { f.store.enqueue(kind, args, f.policy); await f.worker.tick(); }
    assert.equal(f.wire.filter(x => x.method === (kind === 'create_session' ? 'sessions.create' : 'sessions.send')).length, 1);
    assert.doesNotMatch(JSON.stringify(f.store.get({ operation_id: op.operation_id }, f.policy)), /PRIVATE|MOCK-SECRET/);
  }
});

test('worker reconnect observes accepted run without another write and requires fresh owner proof', async t => {
  const f = fixture(t); await f.worker.tick(); f.pending(true);
  const op = f.store.enqueue('create_session', input, f.policy); await f.worker.tick();
  assert.equal(f.store.get({ operation_id: op.operation_id }, f.policy).status, 'running');
  f.worker.close();
  const next = new SessionWorker(f.store, f.gateway, f.policy);
  try {
    assert.throws(() => f.store.get({ operation_id: op.operation_id }, f.policy), /SESSION_ACCESS_DISABLED/);
    f.pending(false); await next.tick();
    assert.equal(f.store.get({ operation_id: op.operation_id }, f.policy).result.response, 'SESSION_TEST_OK');
    assert.equal(f.wire.filter(x => x.method === 'sessions.create').length, 1);
    f.owner('other-owner'); await next.tick();
    assert.equal(f.store.ready(f.policy), false);
  } finally { next.close(); }
});

test('approval revocation before mutation makes no write; exact tasks, targets and caps enforced', async t => {
  const f = fixture(t); await f.worker.tick();
  assert.throws(() => f.store.enqueue('create_session', { ...input, task: 'Unapproved' }, f.policy), /TASK_NOT_APPROVED/);
  assert.throws(() => f.store.enqueue('send_session_message', { session_key: 'agent:main:foreign', message: FOLLOW, idempotency_key: 'target-test-01' }, f.policy), /TARGET_NOT_APPROVED/);
  const op = f.store.enqueue('create_session', input, f.policy); f.approve(null); await f.worker.tick();
  assert.equal(f.wire.filter(x => x.method === 'sessions.create').length, 0);
  assert.equal(f.store.ready(f.policy), false);
  assert.throws(() => f.store.get({ operation_id: op.operation_id }, f.policy), /SESSION_ACCESS_DISABLED/);
});

test('separate approval is absent, strict, private, bounded and cannot renew itself', t => {
  const f = fixture(t); const path = join(f.dir, 'session-approval.json');
  assert.equal(loadSessionApproval(path), null);
  writeFileSync(path, JSON.stringify(f.policy), { mode: 0o600 });
  assert.deepEqual(loadSessionApproval(path), f.policy);
  chmodSync(path, 0o644); assert.equal(loadSessionApproval(path), null); chmodSync(path, 0o600);
  for (const patch of [{ owner: 'other' }, { enabled: false }, { maxFollowups: 2 }, { expiresAt: new Date(Date.now() + 3 * 3600_000).toISOString() }, { shell: true }]) {
    writeFileSync(path, JSON.stringify({ ...f.policy, ...patch })); assert.equal(loadSessionApproval(path), null);
  }
});

test('real MCP SDK discovers strict session tools; disabled frontend never resolves credentials', async t => {
  const f = fixture(t);
  const server = createMcpServer(18789, { stdio: true, jobs: f.jobs, sessions: f.store, sessionApproval: () => f.policy });
  const [a, b] = InMemoryTransport.createLinkedPair(); const client = new Client({ name: 'session-mock', version: '1' });
  await server.connect(b); await client.connect(a);
  t.after(async () => { await client.close(); await server.close(); });
  const tools = (await client.listTools()).tools;
  assert.deepEqual(tools.map(x => x.name), ['health','submit_job','get_job','cancel_job', ...SESSION_NAMES]);
  assert.ok(tools.every(x => x.inputSchema.additionalProperties === false));
  const denied = await client.callTool({ name: 'create_session', arguments: input });
  assert.equal(denied.isError, true); assert.match(JSON.stringify(denied), /SESSION_ACCESS_DISABLED/);
  await f.worker.tick();
  const created = await client.callTool({ name: 'create_session', arguments: input });
  await f.worker.tick();
  const result = await client.callTool({ name: 'get_session_operation', arguments: { operation_id: created.structuredContent.operation_id } });
  assert.equal(result.structuredContent.result.response, 'SESSION_TEST_OK');
  assert.equal(result.isError, undefined);
});

test('expiry/timeout bounds, one active run, and one creation/follow-up/assignment per approval', async t => {
  const f = fixture(t); await f.worker.tick(); f.pending(true);
  const op = f.store.enqueue('create_session', input, f.policy); await f.worker.tick();
  assert.throws(() => f.store.enqueue('create_session', { ...input, idempotency_key: 'another-create' }, f.policy), /BUSY/);
  f.advance(120001); await f.worker.tick();
  assert.equal(f.store.get({ operation_id: op.operation_id }, f.policy).status, 'timed_out');
  assert.equal(f.wire.filter(x => x.method === 'sessions.abort').length, 1);
  assert.throws(() => f.store.enqueue('create_session', { ...input, idempotency_key: 'another-create' }, f.policy), /APPROVAL_EXHAUSTED/);
  f.advance(1800_000); await f.worker.tick(); assert.equal(f.store.ready(f.policy), false);
});

test('completed operations survive new approved worker but hidden results are freshly denied', async t => {
  const f = fixture(t); const created = await create(f); f.worker.close();
  const policy = { ...f.policy, expiresAt: new Date(Date.parse(f.policy.expiresAt) + 1000).toISOString() };
  const next = new SessionWorker(f.store, f.gateway, policy);
  try {
    await next.tick(); assert.equal(f.store.get({ operation_id: created.operation_id }, policy).result, null);
    await next.tick(); assert.equal(f.store.get({ operation_id: created.operation_id }, policy).result.response, 'SESSION_TEST_OK');
    f.visible(false); f.advance(1100); f.store.get({ operation_id: created.operation_id }, policy); await next.tick();
    assert.equal(f.store.get({ operation_id: created.operation_id }, policy).error, 'SESSION_NOT_VISIBLE');
    assert.equal(f.wire.filter(x => x.method === 'sessions.create').length, 1);
  } finally { next.close(); }
});

test('bounded history omits tools/thinking and enforces per-message and total byte limits', async () => {
  const key = 'agent:main:test';
  const gateway = createSessionGateway(async method => {
    if (method === 'users.self') return { profile: { id: OWNER_ID } };
    if (method === 'sessions.describe') return { session: { key, status: 'running', sessionId: 's' } };
    if (method === 'sessions.get') return { messages: Array.from({ length: 20 }, () => ({ role: 'assistant', content: [{ type: 'thinking', text: 'PRIVATE' }, { type: 'text', text: '🧠'.repeat(2000) }] })) };
    throw new Error();
  }, { agent: 'main' });
  const result = await gateway.read('get_session', { session_key: key, limit: 20 });
  assert.equal(result.truncated, true); assert.ok(result.messages.every(x => x.text.length <= 1024));
  assert.ok(result.messages.reduce((n, x) => n + Buffer.byteLength(x.text), 0) <= 8192);
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE/);
});

test('fresh MCP client retrieves completed session operation after original client closes', async t => {
  const f = fixture(t); const created = await create(f);
  for (let i = 0; i < 2; i++) {
    const server = createMcpServer(18789, { stdio: true, jobs: f.jobs, sessions: f.store, sessionApproval: () => f.policy });
    const [a,b] = InMemoryTransport.createLinkedPair(); const client = new Client({ name: 'fresh-client', version: '1' });
    await server.connect(b); await client.connect(a);
    try {
      const result = await client.callTool({ name: 'get_session_operation', arguments: { operation_id: created.operation_id } });
      assert.equal(result.structuredContent.result.response, 'SESSION_TEST_OK');
    } finally { await client.close(); await server.close(); }
  }
  assert.equal(f.wire.filter(x => x.method === 'sessions.create').length, 1);
});

test('crash during dispatch never replays a persisted mutation after worker restart', async t => {
  const f = fixture(t); await f.worker.tick();
  const op = f.store.enqueue('create_session', input, f.policy);
  f.store.patch(op.operation_id, { status: 'dispatching' }); f.worker.close();
  const next = new SessionWorker(f.store, f.gateway, f.policy);
  try {
    await next.tick();
    assert.equal(f.store.get({ operation_id: op.operation_id }, f.policy).status, 'unknown');
    assert.equal(f.wire.filter(x => x.method === 'sessions.create').length, 0);
    assert.equal(f.store.row(op.operation_id).args, '{}');
  } finally { next.close(); }
});

test('visibility revoked during history fetch suppresses the entire read result', async () => {
  const key = 'agent:other:test'; let visible = true; const wire = [];
  const g = createSessionGateway(async (method, args) => {
    wire.push({ method, args });
    if (method === 'users.self') return { profile: { id: OWNER_ID } };
    if (method === 'sessions.describe') return { session: visible ? { key, sessionId: 's' } : null };
    if (method === 'sessions.get') { visible = false; return { messages: [{ role: 'assistant', content: 'PRIVATE' }] }; }
    throw new Error();
  }, { agent: 'main' });
  await assert.rejects(g.read('get_session', { session_key: key, limit: 1 }), /SESSION_NOT_VISIBLE/);
  assert.equal(wire.find(x => x.method === 'sessions.get').args.agentId, 'other');
});
