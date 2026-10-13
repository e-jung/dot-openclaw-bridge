import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { loadApproval, policyHash } from './policy.mjs';
import { boundedText, TERMINAL } from './jobs.mjs';

// Gateway owns execution; this worker owns observation, deadlines and durable
// replies. Its lifetime is independent of MCP stdin or a voice conversation.
export class JobWorker {
  constructor(store, gateway, policy) {
    this.store = store; this.gateway = gateway; this.policy = policy;
    this.token = randomUUID(); this.stopped = false;
    store.claimWorker(policy, this.token);
  }
  async tick() {
    if (this.stopped) return;
    this.store.heartbeat(this.token);
    for (let row of this.store.active()) {
      if (row.agent !== this.policy.agent) continue;
      if (row.status === 'queued') {
        // BEGIN IMMEDIATE prevents a cancel/claim race with the stdio frontend.
        const claimed = this.store.tx(() => {
          row = this.store.row(row.id);
          if (row.status !== 'queued') return false;
          if (row.policy !== policyHash(this.policy) || this.store.now() >= row.deadline || this.store.now() >= Date.parse(this.policy.expiresAt)) {
            this.store.update(row.id, { status: 'timed_out', task: '', error: 'ADMISSION_EXPIRED' });
            return false;
          }
          this.store.update(row.id, { status: 'dispatching' });
          return true;
        });
        if (!claimed) continue;
        let ack;
        try { ack = await this.gateway.dispatch(row); }
        catch { /* Acceptance may already have happened. Never replay. */ }
        // Check lease OUTSIDE the transport catch: a displaced worker must not
        // write state, claim more work, or issue cancellation after resuming.
        this.store.heartbeat(this.token);
        try {
          if (ack?.runId !== row.run_id || !['accepted', 'in_flight'].includes(ack.status) ||
            (ack.agentId && ack.agentId !== row.agent) || (ack.sessionKey && ack.sessionKey !== row.session_key)) throw new Error();
          this.store.update(row.id, { status: 'running', task: '' });
        } catch {
          this.store.update(row.id, { status: 'unknown', task: '', error: 'DISPATCH_UNCERTAIN' });
        }
      }
      row = this.store.row(row.id);
      if (TERMINAL.has(row.status)) continue;
      let observation;
      try { observation = await this.gateway.observe(row); }
      catch { /* Transport loss never means completed or cancelled. */ }
      this.store.heartbeat(this.token);
      if (this.settle(row, observation)) continue;
      row = this.store.row(row.id);
      if (!row.cancel_reason && this.store.now() >= row.deadline) {
        this.store.update(row.id, { cancel_reason: 'deadline' });
        row = this.store.row(row.id);
      }
      if (row.cancel_reason && !row.abort_attempted) {
        this.store.update(row.id, { abort_attempted: 1, status: 'cancelling' });
        let receipt;
        try { receipt = await this.gateway.abort(row); }
        catch { /* An unconfirmed stop is not cancellation. */ }
        this.store.heartbeat(this.token);
        {
          // Source awaits terminal persistence before this exact-run receipt.
          if (receipt?.status === 'aborted' && receipt.abortedRunId === row.run_id) {
            this.store.update(row.id, { status: row.cancel_reason === 'deadline' ? 'timed_out' : 'cancelled', error: null });
          } else this.store.update(row.id, { status: 'unknown', error: 'CANCELLATION_UNCONFIRMED' });
        }
      }
    }
  }
  settle(row, value) {
    if (value?.runId !== row.run_id || value.pendingError === true || value.yielded === true) return false;
    // A plain agent.wait timeout is an observation timeout, NOT terminal evidence.
    if (typeof value.endedAt !== 'number') return false;
    let status;
    // Installed agent.wait preserves the model's normal stopReason="stop"
    // even when status="ok". Only an explicit RPC stop/cancel is cancellation
    // evidence; normal stops must retain the terminal status and reply.
    if (value.stopReason === 'rpc' || value.status === 'cancelled') {
      status = row.cancel_reason === 'deadline' ? 'timed_out' : 'cancelled';
    } else if (value.status === 'timeout') status = 'timed_out';
    else if (value.status === 'error') status = 'failed';
    else if (value.status === 'ok') status = 'completed';
    else return false;
    let result = null;
    let truncated = false;
    let error = status === 'failed' ? 'AGENT_FAILED' : null;
    if (status === 'completed') {
      if (value.terminalReply?.disposition === 'visible' && typeof value.terminalReply.text === 'string') {
        ({ text: result, truncated } = boundedText(this.gateway.sanitize(value.terminalReply.text)
          .replace(/\bsk-[A-Za-z0-9_-]{12,}/g, '[REDACTED]')));
      } else if (['silent', 'empty'].includes(value.terminalReply?.disposition)) result = '';
      else { status = 'unknown'; error = 'RESULT_UNAVAILABLE'; }
    }
    this.store.update(row.id, { status, result, truncated: truncated ? 1 : 0, error, task: '' });
    return status !== 'unknown';
  }
  close() { this.stopped = true; this.store.releaseWorker(this.token); this.gateway.close?.(); }
}

async function main() {
  if (process.argv.slice(2).join(' ') === '--sessions-approved') return sessionMain();
  // No installed service, automatic startup, detached daemon or credential grant.
  // Starting this manually is the separate, explicit approval step.
  if (process.argv.slice(2).join(' ') !== '--approved') throw new Error();
  const policy = loadApproval();
  if (!policy) throw new Error();
  process.umask(0o077);
  delete process.env.CONTROL_PLANE_API_KEY;
  const { JobStore } = await import('./jobs.mjs');
  const { connectLocalGateway } = await import('./gateway.mjs');
  const store = new JobStore();
  let gateway;
  let worker;
  try {
    gateway = await connectLocalGateway(policy);
    worker = new JobWorker(store, gateway, policy);
  } catch { gateway?.close(); store.close(); throw new Error(); }
  let stopping = false;
  const heartbeat = setInterval(() => {
    try { store.heartbeat(worker.token); }
    catch { stopping = true; }
  }, 1000);
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { stopping = true; });
  process.stderr.write('Approved bridge worker ready; no credentials logged.\n');
  try {
    while (!stopping) {
      await worker.tick();
      // No new admissions after expiry. Finish/cancel accepted work first.
      if (Date.now() >= Date.parse(policy.expiresAt) + 30_000) break;
      if (Date.now() >= Date.parse(policy.expiresAt) && store.active().length === 0) break;
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  } finally { clearInterval(heartbeat); worker.close(); store.close(); }
}
async function sessionMain() {
  process.umask(0o077);
  delete process.env.CONTROL_PLANE_API_KEY;
  const { loadSessionApproval } = await import('./session-policy.mjs');
  const { SessionStore } = await import('./session-store.mjs');
  const { SessionWorker } = await import('./session-worker.mjs');
  const { JobStore } = await import('./jobs.mjs');
  const { connectLocalGateway } = await import('./gateway.mjs');
  const approval = () => loadSessionApproval();
  const policy = approval();
  if (!policy) throw new Error();
  const jobs = new JobStore();
  const store = new SessionStore(jobs);
  let gateway; let worker;
  try {
    gateway = await connectLocalGateway(policy);
    worker = new SessionWorker(store, gateway, policy, { approval });
    let stopping = false;
    for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { stopping = true; });
    const heartbeat = setInterval(() => {
      try { jobs.heartbeat(worker.token); } catch { stopping = true; }
    }, 1000);
    process.stderr.write('Approved session worker ready; no credentials logged.\n');
    try {
      while (!stopping && approval()) {
        await worker.tick();
        await new Promise(resolve => setTimeout(resolve, 250));
      }
    } finally { clearInterval(heartbeat); }
  } finally { worker?.close(); if (!worker) gateway?.close(); jobs.close(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => { process.stderr.write('Bridge worker unavailable; inspect local approval and Gateway prerequisites.\n'); process.exitCode = 1; });
}
