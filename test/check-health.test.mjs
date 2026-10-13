import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { ROOT } from '../src/policy.mjs';
import { JobStore } from '../src/jobs.mjs';

const run = promisify(execFile);
const TASK = 'Do not use tools. Reply exactly BRIDGE_TEST_OK.';

// Executes the documented administrator health check end-to-end with an
// env-overridden approval path and the worker lease src/worker.mjs maintains
// (claimWorker plus heartbeat). The spawned stdio server must receive the
// same environment and the check must report the live approved worker.
test('check-health honors env-overridden approval and reports the live worker', async t => {
  const directory = mkdtempSync(join(tmpdir(), 'dot-bridge-health-'));
  const statePath = join(directory, 'jobs.sqlite');
  const approvalPath = join(directory, 'approval.json');
  const policy = { enabled: true, agent: 'main', expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    maxAdmissions: 1, tasks: [TASK], timeoutSeconds: 120 };
  writeFileSync(approvalPath, JSON.stringify(policy), { mode: 0o600 });
  const store = new JobStore(statePath);
  const token = randomUUID();
  store.claimWorker(policy, token);
  const heartbeat = setInterval(() => store.heartbeat(token), 1000);
  t.after(() => { clearInterval(heartbeat); store.close(); rmSync(directory, { recursive: true, force: true }); });
  const { stdout } = await run(process.execPath, [`${ROOT}scripts/check-health.mjs`], {
    env: { ...process.env, DOT_BRIDGE_APPROVAL_PATH: approvalPath, DOT_BRIDGE_STATE_PATH: statePath,
      DOT_BRIDGE_SESSION_APPROVAL_PATH: join(directory, 'absent-session-approval.json') } });
  const report = JSON.parse(stdout.trim().split('\n').at(-1));
  assert.deepEqual(report.tools, ['health', 'submit_job', 'get_job', 'cancel_job', 'list_sessions', 'get_session',
    'create_session', 'assign_session_to_me', 'send_session_message', 'get_session_operation']);
  assert.equal(report.health.capabilities.jobControl, true);
  assert.equal(report.health.capabilities.agentDispatch, true);
  assert.equal(report.health.capabilities.sessionAccess, false);
  assert.equal(report.health.gateway.rpcAuthorization, 'authenticated-worker');
});
