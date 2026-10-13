import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, chmodSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { fork } from 'node:child_process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { createMcpServer } from '../src/server.mjs';
import { JobStore } from '../src/jobs.mjs';
import { JobWorker } from '../src/worker.mjs';
import { loadApproval, ROOT, LIMITS } from '../src/policy.mjs';

const TASK = 'Do not use tools. Reply exactly BRIDGE_TEST_OK.';
function fixture(t, options = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'dot-bridge-test-'));
  const path = join(directory, 'jobs.sqlite');
  let now = Date.now();
  const store = new JobStore(path, { now: () => now });
  const policy = { enabled: true, agent: 'main', expiresAt: new Date(now + 3600_000).toISOString(),
    maxAdmissions: 2, tasks: [TASK, 'Wait, then reply OK.'], timeoutSeconds: 120 };
  const calls = [];
  const gateway = {
    async dispatch(row) { calls.push(['dispatch', { ...row }]); return { runId: row.run_id, status: 'accepted' }; },
    async observe(row) { calls.push(['observe', { ...row }]); return { runId: row.run_id, status: 'timeout' }; },
    async abort(row) { calls.push(['abort', { ...row }]); return { status: 'aborted', abortedRunId: row.run_id }; },
    sanitize: text => text.replaceAll('PRIVATE-GATEWAY-CREDENTIAL', '[REDACTED]'),
    ...options,
  };
  const worker = new JobWorker(store, gateway, policy);
  const closeables = [];
  t.after(async () => { for (const close of closeables) await close(); worker.close(); store.close(); rmSync(directory, { recursive: true, force: true }); });
  return { store, worker, policy, gateway, calls, path, directory, closeables, advance: ms => { now += ms; } };
}
const input = (key = 'request_0001', task = TASK) => ({ task, idempotency_key: key });

test('no approval or absent independent worker means no durable admission or dispatch', t => {
  const f = fixture(t);
  assert.throws(() => f.store.submit(input(), null), /DISPATCH_DISABLED/);
  f.worker.close();
  assert.throws(() => f.store.submit(input(), f.policy), /DISPATCH_DISABLED/);
  assert.equal(f.store.active().length, 0);
  assert.equal(f.calls.length, 0);
});

test('idempotency survives reopen, changed requests conflict, duplicate is safe with dispatch off', t => {
  const f = fixture(t);
  const first = f.store.submit(input(), f.policy);
  const other = new JobStore(f.path);
  try {
    const retry = other.submit(input(), null);
    assert.equal(retry.job_id, first.job_id);
    assert.equal(retry.duplicate, true);
    assert.throws(() => other.submit(input('request_0001', 'Wait, then reply OK.'), f.policy), /IDEMPOTENCY_CONFLICT/);
  } finally { other.close(); }
  assert.equal(f.store.active().length, 1);
});

test('one active job, two approved admissions, exact approved task, bounded strict inputs', t => {
  const f = fixture(t);
  assert.throws(() => f.store.submit(input('request_0001', 'Unapproved action'), f.policy), /TASK_NOT_APPROVED/);
  for (const candidate of [
    { ...input(), agent: 'other' }, { ...input(), session: 'unrelated' },
    { ...input(), timeout: 1000 }, input('bad'), input('request_0001', 'x'.repeat(2001)),
    input('request_0001', '🧠'.repeat(1100)), input('request_0001', '\0'),
  ]) assert.throws(() => f.store.submit(candidate, f.policy));
  const first = f.store.submit(input(), f.policy);
  assert.throws(() => f.store.submit(input('request_0002'), f.policy), /BUSY/);
  f.store.cancel({ job_id: first.job_id });
  const second = f.store.submit(input('request_0002'), f.policy);
  f.store.cancel({ job_id: second.job_id });
  assert.throws(() => f.store.submit(input('request_0003'), f.policy), /APPROVAL_EXHAUSTED/);
});

test('queued cancellation is durable and does not contact Gateway', async t => {
  const f = fixture(t);
  const job = f.store.submit(input(), f.policy);
  assert.equal(f.store.cancel({ job_id: job.job_id }).status, 'cancelled');
  await f.worker.tick();
  assert.deepEqual(f.calls, []);
  assert.equal(f.store.cancel({ job_id: job.job_id }).status, 'cancelled');
});

test('dispatch uses persisted generated session/run and cannot access unrelated jobs', async t => {
  const f = fixture(t);
  const job = f.store.submit(input(), f.policy);
  await f.worker.tick();
  const row = f.calls[0][1];
  assert.equal(row.agent, 'main');
  assert.equal(row.session_key, `agent:main:dot-bridge:${job.job_id}`);
  assert.notEqual(row.run_id, 'request_0001');
  assert.equal(f.store.get({ job_id: job.job_id }).status, 'running');
  assert.throws(() => f.store.get({ job_id: randomUUID() }), /JOB_NOT_FOUND/);
  assert.throws(() => f.store.cancel({ job_id: randomUUID() }), /JOB_NOT_FOUND/);
  assert.throws(() => f.store.get({ job_id: job.job_id, run_id: row.run_id }));
});

test('final reply is secret-redacted, byte bounded and durable; raw errors never escape', async t => {
  const f = fixture(t, { async observe(row) { return { runId: row.run_id, status: 'ok', endedAt: Date.now(),
    terminalReply: { disposition: 'visible', text: 'PRIVATE-GATEWAY-CREDENTIAL sk-abcdefghijklmno ' + '🧠'.repeat(6000) },
    error: 'other private detail', terminalReceipt: { private: 'never return' } }; } });
  const job = f.store.submit(input(), f.policy);
  await f.worker.tick();
  const other = new JobStore(f.path);
  try {
    const result = other.get({ job_id: job.job_id });
    assert.equal(result.status, 'completed');
    assert.equal(result.result_truncated, true);
    assert.ok(Buffer.byteLength(result.result) <= LIMITS.resultBytes);
    assert.doesNotMatch(JSON.stringify(result), /PRIVATE-GATEWAY|sk-abcdefgh|other private|never return|run_id|session_key/);
  } finally { other.close(); }
});

test('normal Gateway stop preserves a successful exact reply across ledger reopen', async t => {
  const f = fixture(t, { async observe(row) {
    return { runId: row.run_id, status: 'ok', stopReason: 'stop', endedAt: Date.now(),
      terminalReply: { disposition: 'visible', text: 'BRIDGE_TEST_OK' } };
  } });
  const job = f.store.submit(input(), f.policy);
  await f.worker.tick();
  const reopened = new JobStore(f.path);
  try {
    const result = reopened.get({ job_id: job.job_id });
    assert.equal(result.status, 'completed');
    assert.equal(result.result, 'BRIDGE_TEST_OK');
    assert.equal(result.cancellation_requested, false);
    assert.equal(result.error, null);
    assert.equal(f.calls.filter(x => x[0] === 'abort').length, 0);
  } finally { reopened.close(); }
});

test('normal stop does not override terminal failure or execution timeout', async t => {
  for (const [status, expected, error] of [['error', 'failed', 'AGENT_FAILED'], ['timeout', 'timed_out', null]]) {
    await t.test(status, async t => {
      const f = fixture(t, { async observe(row) {
        return { runId: row.run_id, status, stopReason: 'stop', endedAt: Date.now() };
      } });
      const job = f.store.submit(input(), f.policy);
      await f.worker.tick();
      const result = f.store.get({ job_id: job.job_id });
      assert.equal(result.status, expected);
      assert.equal(result.error, error);
      assert.equal(f.calls.filter(x => x[0] === 'abort').length, 0);
    });
  }
});

test('normal completion wins an owner-cancel or deadline observation race without an abort', async t => {
  for (const reason of ['owner', 'deadline']) {
    await t.test(reason, async t => {
      const f = fixture(t);
      const job = f.store.submit(input(), f.policy);
      await f.worker.tick();
      if (reason === 'owner') f.store.cancel({ job_id: job.job_id });
      else f.advance(120001);
      f.gateway.observe = async row => ({ runId: row.run_id, status: 'ok', stopReason: 'stop',
        endedAt: Date.now(), terminalReply: { disposition: 'visible', text: 'COMPLETION_WON' } });
      await f.worker.tick();
      const result = f.store.get({ job_id: job.job_id });
      assert.equal(result.status, 'completed');
      assert.equal(result.result, 'COMPLETION_WON');
      assert.equal(result.cancellation_requested, reason === 'owner');
      assert.equal(f.calls.filter(x => x[0] === 'abort').length, 0);
    });
  }
});

test('exact terminal RPC-stop receipts remain cancellation evidence, not ordinary failure or timeout', async t => {
  for (const status of ['error', 'timeout']) {
    for (const reason of [null, 'owner', 'deadline']) {
      await t.test(`${status}/${reason ?? 'external'}`, async t => {
        const f = fixture(t);
        const job = f.store.submit(input(), f.policy);
        await f.worker.tick();
        if (reason) f.store.update(job.job_id, { cancel_reason: reason });
        f.gateway.observe = async row => ({ runId: row.run_id, status, stopReason: 'rpc', endedAt: Date.now() });
        await f.worker.tick();
        const result = f.store.get({ job_id: job.job_id });
        assert.equal(result.status, reason === 'deadline' ? 'timed_out' : 'cancelled');
        assert.equal(result.result, null);
        assert.equal(result.error, null);
        assert.equal(f.calls.filter(x => x[0] === 'abort').length, 0);
      });
    }
  }
});

test('normal stop without a recoverable terminal reply remains unknown, not cancelled or completed', async t => {
  const f = fixture(t, { async observe(row) {
    return { runId: row.run_id, status: 'ok', stopReason: 'stop', endedAt: Date.now() };
  } });
  const job = f.store.submit(input(), f.policy);
  await f.worker.tick();
  const result = f.store.get({ job_id: job.job_id });
  assert.equal(result.status, 'unknown');
  assert.equal(result.error, 'RESULT_UNAVAILABLE');
  assert.equal(result.result, null);
});

test('normal silent or empty completion retains an empty stored result', async t => {
  for (const disposition of ['silent', 'empty']) {
    await t.test(disposition, async t => {
      const f = fixture(t, { async observe(row) {
        return { runId: row.run_id, status: 'ok', stopReason: 'stop', endedAt: Date.now(),
          terminalReply: { disposition } };
      } });
      const job = f.store.submit(input(), f.policy);
      await f.worker.tick();
      const result = f.store.get({ job_id: job.job_id });
      assert.equal(result.status, 'completed');
      assert.equal(result.result, '');
      assert.equal(result.error, null);
    });
  }
});

test('observation timeout, pending error, wrong run and yielded state never report completion', async t => {
  const f = fixture(t);
  const job = f.store.submit(input(), f.policy);
  await f.worker.tick();
  const row = f.store.row(job.job_id);
  for (const result of [
    { runId: row.run_id, status: 'timeout' },
    { runId: row.run_id, status: 'timeout', pendingError: true, endedAt: Date.now() },
    { runId: randomUUID(), status: 'ok', endedAt: Date.now() },
    { runId: row.run_id, status: 'ok', yielded: true, endedAt: Date.now() },
    { runId: row.run_id, status: 'ok', stopReason: 'stop' },
    { runId: row.run_id, status: 'error', stopReason: 'rpc' },
    { runId: row.run_id, status: 'error', stopReason: 'rpc', pendingError: true, endedAt: Date.now() },
    { runId: row.run_id, status: 'error', stopReason: 'rpc', yielded: true, endedAt: Date.now() },
    { runId: randomUUID(), status: 'error', stopReason: 'rpc', endedAt: Date.now() },
  ]) assert.equal(f.worker.settle(row, result), false);
  assert.equal(f.store.get({ job_id: job.job_id }).status, 'running');
});

test('crash during dispatch is unknown and reconciled without redispatch', async t => {
  const f = fixture(t, { async dispatch(row) { f.calls.push(['dispatch', row]); throw new Error('SECRET TOKEN'); } });
  const job = f.store.submit(input(), f.policy);
  await f.worker.tick();
  assert.equal(f.store.get({ job_id: job.job_id }).status, 'unknown');
  f.worker.close();
  const next = new JobWorker(f.store, f.gateway, f.policy);
  try {
    f.gateway.observe = async row => ({ runId: row.run_id, status: 'ok', endedAt: Date.now(), terminalReply: { disposition: 'visible', text: 'Recovered' } });
    await next.tick();
    assert.equal(f.store.get({ job_id: job.job_id }).result, 'Recovered');
    assert.equal(f.calls.filter(x => x[0] === 'dispatch').length, 1);
  } finally { next.close(); }
});

test('lost dispatching state on restart is not replayed', async t => {
  const f = fixture(t);
  const job = f.store.submit(input(), f.policy);
  f.store.update(job.job_id, { status: 'dispatching' });
  f.worker.close();
  const next = new JobWorker(f.store, f.gateway, f.policy);
  try {
    await next.tick();
    assert.equal(f.store.get({ job_id: job.job_id }).status, 'unknown');
    assert.equal(f.calls.filter(x => x[0] === 'dispatch').length, 0);
  } finally { next.close(); }
});

test('running cancellation targets the exact created run; confirmation is durable', async t => {
  const f = fixture(t);
  const job = f.store.submit(input(), f.policy);
  await f.worker.tick();
  const pending = f.store.cancel({ job_id: job.job_id });
  assert.equal(pending.status, 'running');
  assert.equal(pending.cancellation_requested, true);
  await f.worker.tick();
  assert.equal(f.store.get({ job_id: job.job_id }).status, 'cancelled');
  const aborted = f.calls.find(x => x[0] === 'abort')[1];
  assert.equal(aborted.session_key, `agent:main:dot-bridge:${job.job_id}`);
  assert.equal(aborted.run_id, f.store.row(job.job_id).run_id);
  await f.worker.tick();
  assert.equal(f.calls.filter(x => x[0] === 'abort').length, 1);
});

test('no-active-run and mismatched or failed abort are not proof of cancellation', async t => {
  for (const [name, abort] of [
    ['no active run', async () => ({ status: 'no-active-run', abortedRunId: null })],
    ['wrong run', async () => ({ status: 'aborted', abortedRunId: randomUUID() })],
    ['wrong status', async row => ({ status: 'no-active-run', abortedRunId: row.run_id })],
    ['transport loss', async () => { throw new Error('PRIVATE-ABORT-ERROR'); }],
  ]) {
    await t.test(name, async t => {
      const f = fixture(t, { abort });
      const job = f.store.submit(input(), f.policy);
      await f.worker.tick();
      f.store.cancel({ job_id: job.job_id });
      await f.worker.tick();
      const result = f.store.get({ job_id: job.job_id });
      assert.equal(result.status, 'unknown');
      assert.equal(result.error, 'CANCELLATION_UNCONFIRMED');
      assert.doesNotMatch(JSON.stringify(result), /PRIVATE-ABORT-ERROR/);
    });
  }
});

test('deadline cancels exact job; queued expiry never dispatches', async t => {
  const f = fixture(t);
  const first = f.store.submit(input(), f.policy);
  await f.worker.tick();
  f.advance(120001);
  await f.worker.tick();
  assert.equal(f.store.get({ job_id: first.job_id }).status, 'timed_out');
  const second = f.store.submit(input('request_0002'), f.policy);
  f.advance(120001);
  await f.worker.tick();
  assert.equal(f.store.get({ job_id: second.job_id }).status, 'timed_out');
  assert.equal(f.calls.filter(x => x[0] === 'dispatch').length, 1);
});

test('worker singleton, stale lease and expiry gate new admissions', t => {
  const f = fixture(t);
  assert.throws(() => new JobWorker(f.store, f.gateway, f.policy), /WORKER_ALREADY_RUNNING/);
  f.advance(5001);
  assert.throws(() => f.store.submit(input(), f.policy), /DISPATCH_DISABLED/);
  f.advance(3600_000);
  assert.equal(f.store.ready(f.policy), false);
});

test('approval file must be owner-private, active, strict and bounded', t => {
  const f = fixture(t);
  const path = join(f.directory, 'approval.json');
  writeFileSync(path, JSON.stringify(f.policy), { mode: 0o600 });
  assert.deepEqual(loadApproval(path), f.policy);
  chmodSync(path, 0o644);
  assert.equal(loadApproval(path), null);
  chmodSync(path, 0o600);
  writeFileSync(path, JSON.stringify({ ...f.policy, shell: true }));
  assert.equal(loadApproval(path), null);
  assert.equal(statSync(f.path).mode & 0o077, 0);
});

async function mcp(store, approval) {
  const server = createMcpServer(18789, { stdio: true, jobs: store, approval });
  const client = new Client({ name: 'job-test', version: '1' });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(a);
  await client.connect(b);
  return { client, server };
}
test('MCP private-stdio schemas reject arbitrary control and disabled dispatch', async t => {
  const f = fixture(t);
  const { client, server } = await mcp(f.store, () => null);
  try {
    const tools = (await client.listTools()).tools;
    assert.deepEqual(tools.map(x => x.name), ['health', 'submit_job', 'get_job', 'cancel_job']);
    assert.ok(tools.every(x => x.inputSchema.additionalProperties === false));
    assert.match(JSON.stringify(await client.callTool({ name: 'submit_job', arguments: input() })), /DISPATCH_DISABLED/);
    for (const name of ['shell', 'rpc', 'chat.history', 'list_sessions']) assert.equal((await client.callTool({ name, arguments: {} })).isError, true);
    assert.equal((await client.callTool({ name: 'submit_job', arguments: { ...input(), agent: 'other' } })).isError, true);
  } finally { await client.close(); await server.close(); }
});

test('voice-style MCP disconnect and fresh chat connection retain job and completed result', async t => {
  const f = fixture(t);
  const voice = await mcp(f.store, () => f.policy);
  const submitted = await voice.client.callTool({ name: 'submit_job', arguments: input() });
  const id = submitted.structuredContent.job_id;
  await voice.client.close(); await voice.server.close();
  f.gateway.observe = async row => ({ runId: row.run_id, status: 'ok', stopReason: 'stop', endedAt: Date.now(), terminalReply: { disposition: 'visible', text: 'BRIDGE_TEST_OK' } });
  await f.worker.tick();
  const chatStore = new JobStore(f.path);
  const chat = await mcp(chatStore, () => null);
  try {
    const received = await chat.client.callTool({ name: 'get_job', arguments: { job_id: id } });
    assert.equal(received.structuredContent.status, 'completed');
    assert.equal(received.structuredContent.result, 'BRIDGE_TEST_OK');
  } finally { await chat.client.close(); await chat.server.close(); chatStore.close(); }
});

test('actual stdio entry discovers job and gated session tools but cannot dispatch or expose auth', async t => {
  // Never point a test client at the real ledger/approval: npm test is safe even
  // while the owner's approved live worker is running.
  const f = fixture(t);
  f.worker.close();
  const client = new Client({ name: 'stdio-smoke', version: '1' });
  try {
    await client.connect(new StdioClientTransport({ command: 'node', args: [`${ROOT}src/stdio.mjs`], stderr: 'ignore',
      env: { ...process.env, DOT_BRIDGE_STATE_PATH: f.path,
        DOT_BRIDGE_SESSION_APPROVAL_PATH: join(f.directory, 'absent-session-approval.json'),
        DOT_BRIDGE_APPROVAL_PATH: join(f.directory, 'absent-approval.json') } }));
    assert.deepEqual((await client.listTools()).tools.map(x => x.name), ['health', 'submit_job', 'get_job', 'cancel_job', 'list_sessions', 'get_session', 'create_session', 'assign_session_to_me', 'send_session_message', 'get_session_operation']);
    assert.match(JSON.stringify(await client.callTool({ name: 'submit_job', arguments: input() })), /DISPATCH_DISABLED/);
    assert.equal((await client.callTool({ name: 'health', arguments: {} })).structuredContent.capabilities.agentDispatch, false);
  } finally { await client.close(); }
});

test('separate mock worker completes after real stdio frontend exits; fresh stdio retrieves disk result', async t => {
  const f = fixture(t);
  f.worker.close();
  const approvalPath = join(f.directory, 'approval.json');
  writeFileSync(approvalPath, JSON.stringify(f.policy), { mode: 0o600 });
  const child = fork(`${ROOT}test/fixtures/mock-worker.mjs`, [f.path, JSON.stringify(f.policy)], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
  const message = expected => new Promise((resolve, reject) => {
    const timeout = setTimeout(() => { child.off('message', receive); reject(new Error('Mock worker timeout')); }, 5000);
    const receive = value => { if (value === expected) { clearTimeout(timeout); child.off('message', receive); resolve(); } };
    child.on('message', receive);
  });
  const completed = message('completed');
  f.closeables.push(async () => {
    if (child.connected) child.send('close');
    if (child.exitCode === null) await new Promise(resolve => child.once('exit', resolve));
  });
  await message('ready');
  const connect = async () => {
    const client = new Client({ name: 'process-reconnect', version: '1' });
    await client.connect(new StdioClientTransport({ command: 'node', args: [`${ROOT}src/stdio.mjs`], stderr: 'ignore',
      env: { ...process.env, DOT_BRIDGE_STATE_PATH: f.path, DOT_BRIDGE_SESSION_APPROVAL_PATH: join(f.directory, 'absent-session-approval.json'), DOT_BRIDGE_APPROVAL_PATH: approvalPath } }));
    return client;
  };
  const voice = await connect();
  const job = (await voice.callTool({ name: 'submit_job', arguments: input() })).structuredContent;
  await voice.close();
  await completed;
  const chat = await connect();
  try {
    const result = (await chat.callTool({ name: 'get_job', arguments: { job_id: job.job_id } })).structuredContent;
    assert.equal(result.status, 'completed');
    assert.equal(result.result, 'PROCESS_RECONNECT_OK');
  } finally { await chat.close(); }
});

test('cancellation requested during dispatch acknowledgement is preserved and confirmed', async t => {
  const f = fixture(t);
  const job = f.store.submit(input(), f.policy);
  f.gateway.dispatch = async row => {
    f.store.cancel({ job_id: job.job_id });
    return { runId: row.run_id, status: 'accepted' };
  };
  await f.worker.tick();
  assert.equal(f.store.get({ job_id: job.job_id }).status, 'cancelled');
  assert.equal(f.store.get({ job_id: job.job_id }).cancellation_requested, true);
});

test('displaced stale worker cannot mutate or redispatch after an awaited acknowledgement', async t => {
  const f = fixture(t);
  const job = f.store.submit(input(), f.policy);
  f.gateway.dispatch = async row => {
    f.advance(5001);
    const next = new JobWorker(f.store, f.gateway, f.policy);
    f.closeables.push(() => next.close());
    return { runId: row.run_id, status: 'accepted' };
  };
  await assert.rejects(f.worker.tick(), /WORKER_LEASE_LOST/);
  assert.equal(f.store.get({ job_id: job.job_id }).status, 'unknown');
});

test('new approval reconciles accepted owned run but never replays old queued work', async t => {
  const f = fixture(t);
  const job = f.store.submit(input(), f.policy);
  await f.worker.tick();
  f.worker.close();
  const renewed = { ...f.policy, expiresAt: new Date(Date.now() + 7200_000).toISOString() };
  f.gateway.observe = async row => ({ runId: row.run_id, status: 'ok', endedAt: Date.now(), terminalReply: { disposition: 'visible', text: 'RECOVERED_OLD_JOB' } });
  const next = new JobWorker(f.store, f.gateway, renewed);
  try { await next.tick(); assert.equal(f.store.get({ job_id: job.job_id }).result, 'RECOVERED_OLD_JOB'); }
  finally { next.close(); }
});
