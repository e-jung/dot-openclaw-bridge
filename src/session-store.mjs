import { randomUUID, createHash } from 'node:crypto';
import { SESSION_INPUTS, OWNER_ID } from './session-policy.mjs';
import { policyHash, policyExpiry } from './policy.mjs';
import { SESSION_ACCESS_SCHEMA } from './standing-policy.mjs';
export class SessionError extends Error { constructor(code) { super(code); this.code = code; } }
export const SESSION_WRITES = new Set(['create_session', 'assign_session_to_me', 'send_session_message']);
const hash = value => createHash('sha256').update(value).digest('hex');
export class SessionStore {
  constructor(jobs) {
    this.jobs = jobs; this.db = jobs.db; this.now = jobs.now;
    this.db.exec(`CREATE TABLE IF NOT EXISTS session_operations (
      id TEXT PRIMARY KEY, kind TEXT NOT NULL, owner TEXT NOT NULL, idem TEXT UNIQUE, request_hash TEXT NOT NULL,
      args TEXT NOT NULL, policy TEXT NOT NULL, session_key TEXT, run_id TEXT, status TEXT NOT NULL,
      result TEXT, error TEXT, created INTEGER NOT NULL, deadline INTEGER NOT NULL,
      needs_verify INTEGER NOT NULL DEFAULT 1, verified INTEGER NOT NULL DEFAULT 0, lease TEXT);
      CREATE TABLE IF NOT EXISTS session_worker (singleton INTEGER PRIMARY KEY CHECK(singleton=1),
      token TEXT NOT NULL, owner TEXT NOT NULL, verified INTEGER NOT NULL);`);
  }
  ready(policy) {
    if (!SESSION_ACCESS_SCHEMA.safeParse(policy).success || !this.jobs.ready(policy)) return false;
    const proof = this.db.prepare('SELECT * FROM session_worker WHERE singleton=1').get();
    const lease = this.db.prepare('SELECT * FROM worker WHERE singleton=1').get();
    return !!proof && proof.token === lease.token && proof.owner === OWNER_ID && proof.verified > this.now() - 3000;
  }
  row(id) { return this.db.prepare('SELECT * FROM session_operations WHERE id=? AND owner=?').get(id, OWNER_ID); }
  view(row, duplicate = false) {
    if (!row) throw new SessionError('OPERATION_NOT_FOUND');
    return { operation_id: row.id, status: row.needs_verify && row.result ? 'awaiting_verification' : row.status,
      session_key: row.session_key ?? null, run_id: row.run_id ?? null,
      result: row.needs_verify ? null : row.result ? JSON.parse(row.result) : null,
      error: row.error ?? null, duplicate };
  }
  enqueue(kind, raw, policy) {
    const args = SESSION_INPUTS[kind].parse(raw);
    if (policy?.mode === 'standing' && args.session_key && !args.session_key.startsWith('agent:main:')) throw new SessionError('SESSION_TARGET_NOT_APPROVED');
    if (!this.ready(policy)) throw new SessionError('SESSION_ACCESS_DISABLED');
    return this.jobs.tx(() => {
      const fingerprint = hash(JSON.stringify({ kind, args }));
      const old = args.idempotency_key && this.db.prepare('SELECT * FROM session_operations WHERE idem=? AND owner=?').get(args.idempotency_key, OWNER_ID);
      if (old) {
        if (old.request_hash !== fingerprint) throw new SessionError('IDEMPOTENCY_CONFLICT');
        return this.get({ operation_id: old.id }, policy, true);
      }
      if (policy.mode !== 'standing' && this.db.prepare('SELECT count(*) AS n FROM session_operations').get().n >= 100) throw new SessionError('SESSION_STORE_FULL');
      if (SESSION_WRITES.has(kind)) {
        if (this.jobs.active().length || this.db.prepare("SELECT count(*) AS n FROM session_operations WHERE kind IN ('create_session','assign_session_to_me','send_session_message') AND status IN ('queued','dispatching','running','unknown')").get().n) throw new SessionError('BUSY');
        if (policy.mode === 'standing') {
          const used = this.db.prepare("SELECT count(*) AS n FROM session_operations WHERE owner=? AND kind IN ('create_session','send_session_message') AND created>?").get(OWNER_ID, this.now() - 86400000).n;
          if (['create_session','send_session_message'].includes(kind) && used >= policy.maxModelTurnsPerDay) throw new SessionError('SESSION_DAILY_LIMIT');
        } else {
        const cap = { create_session: 'maxCreations', assign_session_to_me: 'maxAssignments', send_session_message: 'maxFollowups' }[kind];
        if (this.db.prepare('SELECT count(*) AS n FROM session_operations WHERE policy=? AND kind=?').get(policyHash(policy), kind).n >= policy[cap]) throw new SessionError('SESSION_APPROVAL_EXHAUSTED');
        if (kind === 'create_session' && !policy.createTasks.includes(args.task) || kind === 'send_session_message' && !policy.followupTasks.includes(args.message)) throw new SessionError('SESSION_TASK_NOT_APPROVED');
        }
        if (args.session_key && !this.allowedTarget(args.session_key, policy)) throw new SessionError('SESSION_TARGET_NOT_APPROVED');
      }
      const id = randomUUID();
      const sessionKey = kind === 'create_session' ? `agent:${policy.agent}:dot-session:${id}` : args.session_key ?? null;
      this.db.prepare('INSERT INTO session_operations (id,kind,owner,idem,request_hash,args,policy,session_key,status,created,deadline) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
        .run(id, kind, OWNER_ID, args.idempotency_key ?? null, fingerprint, JSON.stringify(args), policyHash(policy), sessionKey, 'queued', this.now(), Math.min(this.now() + policy.timeoutSeconds * 1000, policyExpiry(policy)));
      return this.view(this.row(id));
    });
  }
  allowedTarget(key, policy) {
    if (policy.mode === 'standing') return key.startsWith('agent:main:');
    return key.startsWith(`agent:${policy.agent}:`) && (policy.allowedSessionKeys.includes(key) || !!this.db.prepare("SELECT id FROM session_operations WHERE kind='create_session' AND policy=? AND session_key=? AND status='completed'").get(policyHash(policy), key));
  }
  get(raw, policy, duplicate = false) {
    const { operation_id } = SESSION_INPUTS.get_session_operation.parse(raw);
    if (!this.ready(policy)) throw new SessionError('SESSION_ACCESS_DISABLED');
    let row = this.row(operation_id);
    if (!row) throw new SessionError('OPERATION_NOT_FOUND');
    const lease = this.db.prepare('SELECT token FROM worker WHERE singleton=1').get();
    if (row.result && (row.lease !== lease.token || row.verified < this.now() - 1000)) {
      this.patch(row.id, { needs_verify: 1 }); row = this.row(row.id);
    }
    return this.view(row, duplicate);
  }
  async poll(raw, approval, { waitMs = 5000 } = {}) {
    // Slow clients must not have to catch a one-second cached-result window.
    // Request verification once, then collect its fresh result in THIS call.
    // Every check reloads approval/lease/owner readiness through get(); no wider
    // freshness interval or frontend Gateway credential is introduced.
    const deadline = Date.now() + Math.max(0, Math.min(5000, waitMs));
    let result = this.get(raw, approval());
    while (result.status === 'awaiting_verification' && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 25));
      result = this.get(raw, approval());
    }
    return result;
  }
  patch(id, fields) {
    const allowed = new Set(['args', 'run_id', 'status', 'result', 'error', 'needs_verify', 'verified', 'lease']);
    if (Object.keys(fields).some(k => !allowed.has(k))) throw new SessionError('INVALID_SESSION_UPDATE');
    this.db.prepare(`UPDATE session_operations SET ${Object.keys(fields).map(k => `${k}=?`).join(',')} WHERE id=? AND owner=?`).run(...Object.values(fields), id, OWNER_ID);
  }
  prove(token) {
    this.jobs.heartbeat(token);
    this.db.prepare('INSERT OR REPLACE INTO session_worker VALUES (1,?,?,?)').run(token, OWNER_ID, this.now());
  }
  clearProof(token) { this.db.prepare('DELETE FROM session_worker WHERE token=?').run(token); }
}
