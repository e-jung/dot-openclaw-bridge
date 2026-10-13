import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, openSync, closeSync, statSync, constants } from 'node:fs';
import { dirname } from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { LIMITS, ROOT, SUBMIT_SCHEMA, JOB_SCHEMA, policyHash, policyExpiry } from './policy.mjs';

export const TERMINAL = new Set(['completed', 'failed', 'cancelled', 'timed_out']);
const HASH = s => createHash('sha256').update(s).digest('hex');
export class JobError extends Error {
  constructor(code) { super(code); this.code = code; }
}
export function boundedText(text) {
  let value = '';
  let bytes = 0;
  let chars = 0;
  for (const ch of text) {
    const size = Buffer.byteLength(ch);
    if (chars >= LIMITS.resultChars || bytes + size > LIMITS.resultBytes) break;
    value += ch; bytes += size; chars++;
  }
  return { text: value, truncated: value !== text };
}

export class JobStore {
  constructor(path = `${ROOT}state/jobs.sqlite`, { now = Date.now } = {}) {
    this.now = now;
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const dir = statSync(dirname(path));
    if (dir.uid !== process.getuid() || (dir.mode & 0o077)) throw new JobError('STATE_PERMISSIONS');
    const fd = openSync(path, constants.O_CREAT | constants.O_RDWR | constants.O_NOFOLLOW, 0o600);
    closeSync(fd);
    const stat = statSync(path);
    if (stat.uid !== process.getuid() || (stat.mode & 0o077)) throw new JobError('STATE_PERMISSIONS');
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA busy_timeout=3000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS jobs (
        id TEXT PRIMARY KEY, idem TEXT UNIQUE NOT NULL, request_hash TEXT NOT NULL,
        policy TEXT NOT NULL, agent TEXT NOT NULL, session_key TEXT NOT NULL,
        run_id TEXT NOT NULL, task TEXT NOT NULL, status TEXT NOT NULL,
        created INTEGER NOT NULL, updated INTEGER NOT NULL, deadline INTEGER NOT NULL,
        cancel_reason TEXT, abort_attempted INTEGER NOT NULL DEFAULT 0,
        result TEXT, truncated INTEGER NOT NULL DEFAULT 0, error TEXT);
      CREATE TABLE IF NOT EXISTS worker (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), token TEXT NOT NULL,
        policy TEXT NOT NULL, heartbeat INTEGER NOT NULL, expires INTEGER NOT NULL);`);
  }
  tx(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const value = fn(); this.db.exec('COMMIT'); return value; }
    catch (e) { this.db.exec('ROLLBACK'); throw e; }
  }
  row(id) { return this.db.prepare('SELECT * FROM jobs WHERE id=?').get(id); }
  view(row) {
    if (!row) throw new JobError('JOB_NOT_FOUND');
    return { job_id: row.id, status: row.status, created_at: new Date(row.created).toISOString(),
      updated_at: new Date(row.updated).toISOString(), cancellation_requested: !!row.cancel_reason,
      result: row.result ?? null, result_truncated: !!row.truncated, error: row.error ?? null };
  }
  get(input) { return this.view(this.row(JOB_SCHEMA.parse(input).job_id)); }
  ready(policy) {
    if (!policy || policyExpiry(policy) <= this.now()) return false;
    const lease = this.db.prepare('SELECT * FROM worker WHERE singleton=1').get();
    return !!lease && lease.policy === policyHash(policy) && lease.heartbeat > this.now() - 5000 && lease.expires > this.now();
  }
  submit(input, policy) {
    const { task, idempotency_key } = SUBMIT_SCHEMA.parse(input);
    return this.tx(() => {
      const old = this.db.prepare('SELECT * FROM jobs WHERE idem=?').get(idempotency_key);
      if (old) {
        if (old.request_hash !== HASH(task)) throw new JobError('IDEMPOTENCY_CONFLICT');
        return { ...this.view(old), duplicate: true };
      }
      if (!this.ready(policy)) throw new JobError('DISPATCH_DISABLED');
      if (this.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='session_operations'").get() && this.db.prepare("SELECT count(*) AS n FROM session_operations WHERE kind IN ('create_session','assign_session_to_me','send_session_message') AND status IN ('queued','dispatching','running','unknown')").get().n) throw new JobError('BUSY');
      if (!policy.tasks.includes(task)) throw new JobError('TASK_NOT_APPROVED');
      if (this.db.prepare('SELECT count(*) AS n FROM jobs').get().n >= LIMITS.maxJobs) throw new JobError('STORE_FULL');
      if (this.db.prepare('SELECT count(*) AS n FROM jobs WHERE policy=?').get(policyHash(policy)).n >= policy.maxAdmissions) throw new JobError('APPROVAL_EXHAUSTED');
      if (this.db.prepare("SELECT count(*) AS n FROM jobs WHERE status NOT IN ('completed','failed','cancelled','timed_out')").get().n >= LIMITS.maxActive) throw new JobError('BUSY');
      const id = randomUUID();
      const run = randomUUID();
      const now = this.now();
      this.db.prepare('INSERT INTO jobs (id,idem,request_hash,policy,agent,session_key,run_id,task,status,created,updated,deadline) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
        .run(id, idempotency_key, HASH(task), policyHash(policy), policy.agent,
          `agent:${policy.agent}:dot-bridge:${id}`, run, task, 'queued', now, now,
          Math.min(now + policy.timeoutSeconds * 1000, policyExpiry(policy)));
      return { ...this.view(this.row(id)), duplicate: false };
    });
  }
  cancel(input) {
    const id = JOB_SCHEMA.parse(input).job_id;
    return this.tx(() => {
      const row = this.row(id);
      if (!row) throw new JobError('JOB_NOT_FOUND');
      if (TERMINAL.has(row.status)) return this.view(row);
      if (row.status === 'queued') this.update(id, { status: 'cancelled', cancel_reason: 'owner', task: '' });
      else this.update(id, { cancel_reason: row.cancel_reason ?? 'owner' });
      return this.view(this.row(id));
    });
  }
  update(id, patch) {
    const allowed = new Set(['status', 'cancel_reason', 'abort_attempted', 'result', 'truncated', 'error', 'task']);
    if (Object.keys(patch).some(k => !allowed.has(k))) throw new JobError('INVALID_UPDATE');
    const fields = Object.keys(patch);
    this.db.prepare(`UPDATE jobs SET ${fields.map(k => `${k}=?`).join(',')},updated=? WHERE id=?`)
      .run(...fields.map(k => patch[k]), this.now(), id);
  }
  claimWorker(policy, token) {
    this.tx(() => {
      const old = this.db.prepare('SELECT * FROM worker WHERE singleton=1').get();
      if (old && old.heartbeat > this.now() - 5000 && old.expires > this.now()) throw new JobError('WORKER_ALREADY_RUNNING');
      this.db.prepare('INSERT OR REPLACE INTO worker VALUES (1,?,?,?,?)')
        .run(token, policyHash(policy), this.now(), policyExpiry(policy));
      // Accepted run IDs are known before dispatch (installed runId=idempotencyKey).
      // A stale dispatch is observable but NEVER replayed.
      this.db.prepare("UPDATE jobs SET status='unknown', error='DISPATCH_UNCERTAIN', task='',updated=? WHERE status='dispatching'").run(this.now());
    });
  }
  heartbeat(token) {
    if (this.db.prepare('UPDATE worker SET heartbeat=? WHERE singleton=1 AND token=?').run(this.now(), token).changes !== 1) throw new JobError('WORKER_LEASE_LOST');
  }
  releaseWorker(token) { this.db.prepare('DELETE FROM worker WHERE singleton=1 AND token=?').run(token); }
  active() { return this.db.prepare("SELECT * FROM jobs WHERE status NOT IN ('completed','failed','cancelled','timed_out') ORDER BY created").all(); }
  close() { this.db.close(); }
}
