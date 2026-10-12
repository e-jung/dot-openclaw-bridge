import { randomUUID } from 'node:crypto';
import { policyHash, policyExpiry } from './policy.mjs';
import { SESSION_WRITES, SessionError } from './session-store.mjs';
import { SESSION_ACCESS_SCHEMA } from './standing-policy.mjs';
const safeErrors = new Set(['CONNECTED_OWNER_MISMATCH','SESSION_NOT_VISIBLE','SESSION_RESPONSE_INVALID','SESSION_APPROVAL_EXPIRED']);
export class SessionWorker {
  constructor(store, gateway, policy, { approval = () => policy } = {}) {
    SESSION_ACCESS_SCHEMA.parse(policy);
    this.store = store; this.gateway = gateway; this.policy = policy; this.approval = approval;
    this.token = randomUUID(); this.stopped = false;
    if (store.jobs.active().length) throw new SessionError('BUSY');
    store.jobs.claimWorker(policy, this.token);
    // A crashed dispatch may have been accepted: retain evidence, never resend.
    store.db.prepare("UPDATE session_operations SET status='unknown', error='SESSION_DISPATCH_UNCERTAIN', args='{}', needs_verify=1 WHERE status='dispatching'").run();
  }
  approved() {
    const current = this.approval();
    if (!current || policyHash(current) !== policyHash(this.policy) || this.store.now() >= policyExpiry(current)) throw new SessionError('SESSION_APPROVAL_EXPIRED');
  }
  async tick() {
    if (this.stopped) return;
    // Keep the last fresh proof during routine revalidation; it expires after
    // three seconds. A failed verification clears it immediately.
    try { this.approved(); await this.gateway.verifyOwner(); this.approved(); this.store.prove(this.token); }
    catch { this.store.clearProof(this.token); return; }
    const rows = this.store.db.prepare("SELECT * FROM session_operations WHERE owner=? AND (status IN ('queued','running') OR status='unknown' AND run_id IS NOT NULL OR needs_verify=1 AND result IS NOT NULL) ORDER BY created LIMIT 20").all(this.policy.owner);
    for (let row of rows) {
      if (row.policy !== policyHash(this.policy) && row.status === 'queued') {
        this.store.patch(row.id, { status: 'failed', error: 'SESSION_APPROVAL_EXPIRED', args: '{}' }); continue;
      }
      try {
        this.approved(); this.store.jobs.heartbeat(this.token);
        if (row.status === 'queued') {
          if (this.store.now() >= row.deadline) { this.store.patch(row.id, { status: 'timed_out', error: 'SESSION_APPROVAL_EXPIRED', args: '{}' }); continue; }
          const args = JSON.parse(row.args);
          // Claim before any await: a second frontend cannot duplicate a write.
          this.store.patch(row.id, { status: 'dispatching' });
          if (SESSION_WRITES.has(row.kind)) {
            let ack;
            try { ack = await this.gateway.mutate(row, args, () => { this.approved(); this.store.jobs.heartbeat(this.token); }); }
            catch (e) {
              this.store.jobs.heartbeat(this.token);
              this.store.patch(row.id, { status: ['CONNECTED_OWNER_MISMATCH','SESSION_NOT_VISIBLE','SESSION_APPROVAL_EXPIRED'].includes(e.code) ? 'failed' : 'unknown', error: safeErrors.has(e.code) ? e.code : 'SESSION_DISPATCH_UNCERTAIN', args: '{}' }); continue;
            }
            this.store.jobs.heartbeat(this.token);
            if (ack.done) this.finish(row, 'completed', ack.result);
            else this.store.patch(row.id, { status: 'running', run_id: ack.run_id, args: '{}', error: null });
          } else {
            const result = await this.gateway.read(row.kind, args);
            this.store.jobs.heartbeat(this.token); this.approved(); this.finish(row, 'completed', result);
          }
        }
        row = this.store.row(row.id);
        if (row.status === 'running' || row.status === 'unknown' && row.run_id) {
          const observed = await this.gateway.observe(row);
          this.store.jobs.heartbeat(this.token);
          if (observed) this.finish(row, observed.status, observed.result ?? null, observed.error ?? null);
          else if (this.store.now() >= row.deadline && row.error !== 'SESSION_TIMEOUT_UNCONFIRMED') {
            // One bounded exact-run abort attempt. No replay after uncertainty.
            this.store.patch(row.id, { status: 'unknown', error: 'SESSION_TIMEOUT_UNCONFIRMED' });
            if (row.policy !== policyHash(this.policy)) continue;
            const receipt = await this.gateway.abort(row);
            this.store.jobs.heartbeat(this.token);
            if (receipt?.status === 'aborted' && receipt.abortedRunId === row.run_id) this.finish(row, 'timed_out', null, 'SESSION_RUN_TIMEOUT');
          }
        } else if (row.needs_verify && row.result) {
          // Historical snapshots may be released only after fresh owner/target
          // validation, including a reconnect or fresh MCP client.
          await this.gateway.verifyOwner();
          if (row.session_key) await this.gateway.visible(row.session_key);
          else { this.finish(row, row.status, await this.gateway.read(row.kind, JSON.parse(row.args))); continue; }
          this.store.jobs.heartbeat(this.token); this.approved();
          this.store.patch(row.id, { needs_verify: 0, verified: this.store.now(), lease: this.token });
        }
      } catch (error) {
        this.store.jobs.heartbeat(this.token);
        const latest = this.store.row(row.id);
        if (latest.run_id && ['running', 'unknown'].includes(latest.status)) {
          // Accepted execution remains unresolved across observation/auth loss.
          this.store.patch(row.id, { status: 'unknown', result: null, needs_verify: 1, error: latest.error === 'SESSION_TIMEOUT_UNCONFIRMED' ? latest.error : 'SESSION_OBSERVATION_UNCERTAIN' });
        } else this.finish(row, 'failed', null, safeErrors.has(error.code) ? error.code : 'SESSION_REQUEST_FAILED');
      }
    }
    // Authorization can disappear during an awaited RPC. Readiness must reflect
    // the final authenticated connection, never just an old hello/lease.
    try { await this.gateway.verifyOwner(); this.approved(); this.store.prove(this.token); }
    catch { this.store.clearProof(this.token); }
  }
  finish(row, status, result, error = null) {
    this.store.patch(row.id, { status, result: result ? JSON.stringify(result) : null, error,
      args: SESSION_WRITES.has(row.kind) ? '{}' : row.args, needs_verify: 0, verified: this.store.now(), lease: this.token });
  }
  close() { this.stopped = true; this.store.clearProof(this.token); this.store.jobs.releaseWorker(this.token); this.gateway.close?.(); }
}
