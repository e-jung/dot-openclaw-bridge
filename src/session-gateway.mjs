import { OWNER_ID } from './session-policy.mjs';
import { SessionError } from './session-store.mjs';
import { boundedText } from './jobs.mjs';
export const SESSION_METHODS = ['users.self', 'sessions.list', 'sessions.describe', 'sessions.get', 'sessions.create', 'sessions.assignOwner', 'sessions.send', 'agent.wait', 'sessions.abort'];
// The installed core registry deliberately marks sessions.get advertise:false.
// It remains gated by owner checks, native visibility and response validation.
export const SESSION_ADVERTISED_METHODS = SESSION_METHODS.filter(m => m !== 'sessions.get');
// Only called with the installed client's private request closure. No MCP RPC tool.
export function createSessionGateway(request, policy, sanitize = s => s) {
  const clean = (s, max = 1024) => boundedText(sanitize(String(s ?? '')).replace(/\bsk-[A-Za-z0-9_-]{12,}/g, '[REDACTED]').slice(0, max)).text;
  async function verifyOwner() {
    const value = await request('users.self', {});
    if (value?.profile?.id !== OWNER_ID || value.profile.mergedInto) throw new SessionError('CONNECTED_OWNER_MISMATCH');
  }
  async function describe(key) {
    // Native describe returns null for sessions hidden from the authenticated
    // principal, and checks authority again after materializing its projection.
    const value = await request('sessions.describe', { key, agentId: key.split(':')[1] });
    if (!value?.session || value.session.key !== key) throw new SessionError('SESSION_NOT_VISIBLE');
    return value.session;
  }
  const summary = row => ({ session_key: clean(row.key, 256), session_id: clean(row.sessionId, 128),
    title: clean(row.displayName ?? row.label, 160), status: clean(row.status ?? 'unknown', 32),
    owner_id: clean(row.owner?.actor?.id, 128) });
  return {
    verifyOwner,
    async visible(key) { await verifyOwner(); return summary(await describe(key)); },
    async read(kind, args) {
      await verifyOwner();
      if (kind === 'list_sessions') {
        const value = await request('sessions.list', { limit: args.limit, offset: args.offset, includeDerivedTitles: false, includeLastMessage: false, ...(policy.mode === 'standing' ? { agentId: 'main' } : {}) });
        if (!Array.isArray(value?.sessions)) throw new SessionError('SESSION_RESPONSE_INVALID');
        return { sessions: value.sessions.filter(row => policy.mode !== 'standing' || row.key?.startsWith('agent:main:')).slice(0, args.limit).map(summary), truncated: value.sessions.length >= args.limit };
      }
      const row = await describe(args.session_key);
      const history = await request('sessions.get', { key: args.session_key, agentId: args.session_key.split(':')[1], limit: args.limit });
      // Recheck visibility after the history read, in addition to native checks.
      await describe(args.session_key);
      if (!Array.isArray(history?.messages)) throw new SessionError('SESSION_RESPONSE_INVALID');
      let bytes = 0; let truncated = history.messages.length > args.limit;
      const messages = [];
      for (const message of history.messages.slice(-args.limit)) {
        if (!['user', 'assistant'].includes(message?.role)) continue;
        // Only visible text. Never return tool arguments/results, reasoning,
        // attachments, transport metadata, paths, or raw session entry fields.
        const source = typeof message.content === 'string' ? message.content : Array.isArray(message.content)
          ? message.content.filter(p => p?.type === 'text' && typeof p.text === 'string').map(p => p.text).join('\n') : '';
        const text = clean(source);
        if (text.length < source.length) truncated = true;
        if (bytes + Buffer.byteLength(text) > 8192) { truncated = true; break; }
        messages.push({ role: message.role, text }); bytes += Buffer.byteLength(text);
      }
      return { session: summary(row), messages, truncated };
    },
    async mutate(row, args, assertApproved) {
      await verifyOwner();
      if (row.kind !== 'create_session') await describe(row.session_key);
      // This synchronous guard reloads the separate approval immediately before
      // the RPC. Gateway then enforces its own current mutation authority.
      assertApproved();
      const timeoutMs = Math.max(1, Math.min(policy.timeoutSeconds * 1000, row.deadline - Date.now()));
      let ack;
      if (row.kind === 'create_session') ack = await request('sessions.create', {
        key: row.session_key, agentId: policy.agent, incognito: false, visibility: 'draft',
        task: args.task, timeoutMs, idempotencyKey: row.id,
      });
      else if (row.kind === 'assign_session_to_me') ack = await request('sessions.assignOwner', {
        key: row.session_key, agentId: policy.agent, owner: { type: 'human', id: OWNER_ID },
      });
      else ack = await request('sessions.send', {
        key: row.session_key, agentId: policy.agent, message: args.message, timeoutMs, idempotencyKey: row.id,
      });
      if (row.kind === 'assign_session_to_me') {
        if (ack?.ok !== true || ack.key !== row.session_key || ack.owner?.actor?.type !== 'human' || ack.owner?.actor?.id !== OWNER_ID) throw new SessionError('SESSION_RESPONSE_INVALID');
        return { done: true, result: { owner_id: OWNER_ID } };
      }
      if (row.kind === 'create_session' && (ack?.ok !== true || ack.key !== row.session_key || ack.runError)) throw new SessionError('SESSION_RESPONSE_INVALID');
      if (typeof ack?.runId !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(ack.runId)) throw new SessionError('SESSION_RESPONSE_INVALID');
      return { done: false, run_id: ack.runId };
    },
    async observe(row) {
      await verifyOwner(); await describe(row.session_key);
      const value = await request('agent.wait', { runId: row.run_id, timeoutMs: 0 });
      if (value?.runId !== row.run_id || value.pendingError || value.yielded || typeof value.endedAt !== 'number') return null;
      if (value.status !== 'ok' || value.stopReason === 'rpc') return { status: value.status === 'timeout' ? 'timed_out' : 'failed', error: 'SESSION_RUN_FAILED' };
      if (!['visible', 'silent', 'empty'].includes(value.terminalReply?.disposition)) return { status: 'unknown', error: 'SESSION_RESULT_UNAVAILABLE' };
      const raw = value.terminalReply.disposition === 'visible' ? value.terminalReply.text : '';
      if (typeof raw !== 'string') return { status: 'unknown', error: 'SESSION_RESULT_UNAVAILABLE' };
      const bounded = boundedText(sanitize(raw).replace(/\bsk-[A-Za-z0-9_-]{12,}/g, '[REDACTED]'));
      return { status: 'completed', result: { response: bounded.text, truncated: bounded.truncated } };
    },
    async abort(row) {
      await verifyOwner(); await describe(row.session_key);
      return request('sessions.abort', { key: row.session_key, agentId: policy.agent, runId: row.run_id });
    },
  };
}
