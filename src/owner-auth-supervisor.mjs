import { pathToFileURL } from 'node:url';
import { createInterface } from 'node:readline';
import { prepareOwnerAuthRuntime, OwnerAuthError } from './owner-auth.mjs';
import { loadApproval, policyHash } from './policy.mjs';
import { loadSessionApproval, SESSION_APPROVAL_SCHEMA } from './session-policy.mjs';

const WINDOW_MS = 30 * 60_000;
const CREATE_TASK = 'Do not use tools. Reply exactly SESSION_TEST_OK.';
const FOLLOWUP_TASK = 'Do not use tools. Reply exactly SESSION_FOLLOWUP_OK.';

// OwnerAuthError contains only bridge-created public selectors/fixed categories.
// Never serialize the source error, stack, message, cause or native payload.
export function ownerAuthFailureReport(error) {
  return { error: error instanceof OwnerAuthError ? error.code : 'OWNER_SUPERVISOR_FAILED',
    ...(error instanceof OwnerAuthError && error.diagnostic ? { diagnostic: error.diagnostic } : {}),
    ...(error instanceof OwnerAuthError && error.pending ? { pending: error.pending } : {}) };
}

function boundedPolicy(value, now) {
  const policy = SESSION_APPROVAL_SCHEMA.safeParse(value);
  if (!policy.success) throw new OwnerAuthError('SESSION_TEST_NOT_APPROVED');
  const p = policy.data;
  const remaining = Date.parse(p.expiresAt) - now;
  if (remaining <= 0 || remaining > WINDOW_MS || p.createTasks.length !== 1 || p.createTasks[0] !== CREATE_TASK
    || p.followupTasks.length !== 1 || p.followupTasks[0] !== FOLLOWUP_TASK || p.allowedSessionKeys.length
    || p.maxCreations !== 1 || p.maxAssignments !== 1 || p.maxFollowups !== 1) {
    throw new OwnerAuthError('SESSION_TEST_NOT_APPROVED');
  }
  return p;
}

// No ledger, lease, session RPC, or worker is constructed during auth-only stages.
async function makeSessionRunner({ gateway, policy, approval }) {
  const [{ JobStore }, { SessionStore }, { SessionWorker }] = await Promise.all([
    import('./jobs.mjs'), import('./session-store.mjs'), import('./session-worker.mjs'),
  ]);
  const jobs = new JobStore();
  let worker;
  try { worker = new SessionWorker(new SessionStore(jobs), gateway, policy, { approval }); }
  catch (error) { jobs.close(); throw error; }
  return {
    tick: () => worker.tick(), heartbeat: () => jobs.heartbeat(worker.token),
    close() { try { worker.close(); } finally { jobs.close(); } },
  };
}

// One supervisor owns one dedicated identity for its complete bounded lifetime.
// These booleans are call-site guards, never a substitute for the owner's permission.
export function createOwnerAuthSupervisor({ ownerEnrollmentApproved = false,
  prepareRuntime = prepareOwnerAuthRuntime, sessionRunner = makeSessionRunner,
  sessionApproval = loadSessionApproval, jobApproval = loadApproval, now = Date.now } = {}) {
  if (ownerEnrollmentApproved !== true) throw new OwnerAuthError('OWNER_ENROLLMENT_NOT_APPROVED');
  const expiresAt = now() + WINDOW_MS;
  let runtime; let gateway; let runner; let reconnectProven = false; let sessionStarted = false;
  let disposed = false; let stageBusy = false; let approvedPolicyHash;

  function close() {
    if (disposed) return;
    disposed = true; reconnectProven = false; gateway = null;
    try { runner?.close(); } finally { runner = null; runtime?.dispose(); }
  }
  function active() {
    if (disposed) throw new OwnerAuthError('OWNER_TRIAL_STOPPED');
    if (now() >= expiresAt) { close(); throw new OwnerAuthError('OWNER_TRIAL_EXPIRED'); }
  }
  async function stage(operation) {
    active();
    if (stageBusy) throw new OwnerAuthError('OWNER_STAGE_BUSY');
    stageBusy = true;
    try { return await operation(); } finally { stageBusy = false; }
  }
  function currentApproval() {
    try {
      const policy = boundedPolicy(sessionApproval(), now());
      if (Date.parse(policy.expiresAt) > expiresAt) return null;
      return approvedPolicyHash && policyHash(policy) !== approvedPolicyHash ? null : policy;
    } catch { return null; }
  }

  return {
    async authenticate() {
      return stage(async () => {
        if (sessionStarted) throw new OwnerAuthError('OWNER_SESSION_STAGE_CONSUMED');
        reconnectProven = false; gateway = null;
        // A pairing rejection retains this runtime/key for the owner's retry.
        if (!runtime) {
          const prepared = await prepareRuntime({ ownerEnrollmentApproved: true, policy: { agent: 'main', timeoutSeconds: 120 } });
          try { active(); } catch (error) { prepared.dispose(); throw error; }
          runtime = prepared;
        }
        active();
        const connected = await runtime.open();
        active(); gateway = connected;
        return runtime.proof();
      });
    },
    async proveReconnect() {
      return stage(async () => {
        if (sessionStarted || !gateway || !runtime?.proof().owner_verified) throw new OwnerAuthError('OWNER_RECONNECT_NOT_READY');
        reconnectProven = false; gateway = null;
        const connected = await runtime.reconnect();
        active(); gateway = connected;
        if (!runtime.proof().owner_verified) throw new OwnerAuthError('OWNER_RECONNECT_NOT_READY');
        reconnectProven = true;
        return runtime.proof();
      });
    },
    async startSessions({ sessionTestApproved = false } = {}) {
      return stage(async () => {
        if (sessionTestApproved !== true) throw new OwnerAuthError('SESSION_TEST_NOT_APPROVED');
        if (sessionStarted) throw new OwnerAuthError('OWNER_SESSION_STAGE_CONSUMED');
        if (!gateway || !reconnectProven || !runtime?.proof().owner_verified) throw new OwnerAuthError('OWNER_RECONNECT_NOT_READY');
        if (jobApproval()) throw new OwnerAuthError('JOB_ADMISSION_MUST_BE_DISABLED');
        const policy = boundedPolicy(sessionApproval(), now());
        approvedPolicyHash = policyHash(policy);
        await gateway.verifyOwner(); active();
        if (!currentApproval()) throw new OwnerAuthError('SESSION_TEST_NOT_APPROVED');
        // No second connectLocalGateway call: the worker uses this exact socket/key.
        const prepared = await sessionRunner({ gateway, policy, approval: currentApproval });
        try { active(); } catch (error) { prepared.close(); throw error; }
        runner = prepared;
        sessionStarted = true;
        active();
        return { session_worker_started: true, expires_at: policy.expiresAt, ...runtime.proof() };
      });
    },
    async tick() {
      active();
      if (!runner) return;
      if (jobApproval()) { close(); throw new OwnerAuthError('JOB_ADMISSION_MUST_BE_DISABLED'); }
      if (!currentApproval()) { close(); throw new OwnerAuthError('SESSION_TEST_NOT_APPROVED'); }
      await runner.tick(); active();
    },
    heartbeat() { active(); runner?.heartbeat(); },
    status() {
      active();
      return { trial_expires_at: new Date(expiresAt).toISOString(), reconnect_proven: reconnectProven,
        session_worker_started: Boolean(runner), ...runtime?.proof() };
    },
    close,
  };
}

async function main() {
  if (process.argv.slice(2).join(' ') !== '--enrollment-approved' || !process.stdin.isTTY) {
    throw new OwnerAuthError('OWNER_ENROLLMENT_NOT_APPROVED');
  }
  process.umask(0o077);
  delete process.env.CONTROL_PLANE_API_KEY;
  const supervisor = createOwnerAuthSupervisor({ ownerEnrollmentApproved: true });
  const input = createInterface({ input: process.stdin });
  const output = value => process.stdout.write(`${JSON.stringify(value)}\n`);
  const report = error => output(ownerAuthFailureReport(error));
  let stopping = false; let ticking; let fatal = false;
  const stopInput = () => { stopping = true; input.close(); };
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, stopInput);
  const timer = setInterval(() => {
    if (stopping) return;
    try { supervisor.heartbeat(); }
    catch (error) { fatal = true; report(error); stopInput(); return; }
    if (!ticking) ticking = supervisor.tick().catch(error => { fatal = true; report(error); stopInput(); }).finally(() => { ticking = null; });
  }, 1000);
  try {
    output({ commands: ['auth', 'reconnect', 'status', 'sessions-approved', 'stop'],
      note: 'Owner-authorized trial only. This process cannot approve devices or enable/renew session approval.' });
    for await (const line of input) {
      const command = line.trim();
      if (command === 'stop') break;
      try {
        if (command === 'auth') output(await supervisor.authenticate());
        else if (command === 'reconnect') output(await supervisor.proveReconnect());
        else if (command === 'status') output(supervisor.status());
        else if (command === 'sessions-approved') output(await supervisor.startSessions({ sessionTestApproved: true }));
        else output({ error: 'OWNER_COMMAND_NOT_SUPPORTED' });
      } catch (error) { report(error); }
    }
  } finally {
    stopping = true; clearInterval(timer); input.close();
    try { await ticking; } finally { supervisor.close(); }
    for (const signal of ['SIGINT', 'SIGTERM']) process.removeListener(signal, stopInput);
    output({ stopped: true, native_device_cleanup: 'Owner must revoke/remove the exact temporary device; stopping alone does not revoke it.' });
    if (fatal) process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => { process.stderr.write(`${error instanceof OwnerAuthError ? error.code : 'OWNER_SUPERVISOR_FAILED'}\n`); process.exitCode = 1; });
}
