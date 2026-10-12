import { pathToFileURL } from 'node:url';
import { createInterface } from 'node:readline';
import { prepareOwnerAuthRuntime, OwnerAuthError } from './owner-auth.mjs';
import { ownerAuthFailureReport } from './owner-auth-supervisor.mjs';
import { storedIdentity } from './standing-identity.mjs';
import { loadStandingPolicy } from './standing-policy.mjs';
import { loadApproval, policyHash } from './policy.mjs';
import { loadSessionApproval } from './session-policy.mjs';
import { JobStore } from './jobs.mjs';
import { SessionStore } from './session-store.mjs';
import { SessionWorker } from './session-worker.mjs';

async function main() {
  const flag = process.argv.slice(2).join(' ');
  const enrollment = flag === '--enroll';
  if (!enrollment && flag !== '--run' || enrollment && !process.stdin.isTTY) throw new Error();
  process.umask(0o077);
  delete process.env.CONTROL_PLANE_API_KEY;
  const policy = loadStandingPolicy();
  if (!policy || loadApproval() || loadSessionApproval()) throw new Error();
  const runtime = await prepareOwnerAuthRuntime({ ownerEnrollmentApproved: true, policy,
    identityProvider: generate => storedIdentity(generate, { enrollment }) });
  const emit = value => process.stdout.write(`${JSON.stringify(value)}\n`);
  let backend; let reconnectProven = false; let stopping = false;
  try {
    if (enrollment) {
      const input = createInterface({ input: process.stdin });
      const stop = () => input.close();
      for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, stop);
      // Bounded enrollment interaction; the resulting identity is persistent.
      const timer = setTimeout(stop, 30 * 60_000);
      emit({ enrollment: true, device_id: runtime.publicDeviceId, commands: ['auth', 'reconnect', 'status', 'stop'] });
      try {
        for await (const line of input) {
          const command = line.trim();
          if (command === 'stop') break;
          try {
            if (command === 'auth') { reconnectProven = false; backend = await runtime.open(); emit(runtime.proof()); }
            else if (command === 'reconnect' && runtime.proof().owner_verified) { backend = await runtime.reconnect(); reconnectProven = true; emit({ ...runtime.proof(), reconnect_proven: true }); }
            else if (command === 'status') emit({ ...runtime.proof(), reconnect_proven: reconnectProven });
            else emit({ error: 'OWNER_COMMAND_NOT_SUPPORTED' });
          } catch (error) { emit(ownerAuthFailureReport(error)); }
        }
      } finally { clearTimeout(timer); input.close(); for (const signal of ['SIGINT', 'SIGTERM']) process.removeListener(signal, stop); }
      return;
    }
    // Restarts reload exactly the stored device, never enroll/approve/rekey.
    await runtime.open(); backend = await runtime.reconnect();
    const jobs = new JobStore(); let worker;
    const stop = () => { stopping = true; };
    for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, stop);
    let heartbeat;
    try {
      worker = new SessionWorker(new SessionStore(jobs), backend, policy, { approval: () =>
        loadApproval() || loadSessionApproval() ? null : loadStandingPolicy() });
      heartbeat = setInterval(() => { try { jobs.heartbeat(worker.token); } catch { stopping = true; } }, 1000);
      emit({ ...runtime.proof(), standing_worker_started: true });
      while (!stopping) {
        if (!loadStandingPolicy() || policyHash(loadStandingPolicy()) !== policyHash(policy) || loadApproval() || loadSessionApproval()) break;
        // Loss of owner proof ends this process; service reconnect uses same key.
        if (!runtime.proof().owner_verified) throw new OwnerAuthError('OWNER_TRANSPORT_FAILED');
        await worker.tick();
        await new Promise(resolve => setTimeout(resolve, 250));
      }
    } finally {
      clearInterval(heartbeat); worker?.close(); jobs.close();
      for (const signal of ['SIGINT', 'SIGTERM']) process.removeListener(signal, stop);
    }
  } finally { runtime.dispose(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    process.stderr.write(`${JSON.stringify(ownerAuthFailureReport(error))}\n`);
    // Pairing/auth/contracts require human action; never restart-loop enrollment.
    process.exitCode = ['OWNER_TRANSPORT_FAILED','OWNER_TLS_FAILED','OWNER_AUTH_TIMEOUT'].includes(error?.code) ? 1 : 78;
  });
}
