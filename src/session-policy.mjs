import { z } from 'zod/v4';
import { readFileSync, lstatSync } from 'node:fs';
import { ROOT, TASK_SCHEMA } from './policy.mjs';
export const OWNER_ID = process.env.DOT_BRIDGE_OWNER_ID || '00000000-0000-4000-8000-000000000001';
const key = z.string().min(1).max(256).regex(/^agent:[a-z0-9_-]+:[^\s\0]+$/);
const idem = z.string().min(8).max(128).regex(/^[A-Za-z0-9_.:-]+$/);
export const SESSION_INPUTS = {
  list_sessions: z.strictObject({ limit: z.number().int().min(1).max(20).default(10), offset: z.number().int().min(0).max(1000).default(0) }),
  get_session: z.strictObject({ session_key: key, limit: z.number().int().min(1).max(20).default(10) }),
  create_session: z.strictObject({ task: TASK_SCHEMA, idempotency_key: idem }),
  assign_session_to_me: z.strictObject({ session_key: key, idempotency_key: idem }),
  send_session_message: z.strictObject({ session_key: key, message: TASK_SCHEMA, idempotency_key: idem }),
  get_session_operation: z.strictObject({ operation_id: z.string().uuid() }),
};
export const SESSION_APPROVAL_SCHEMA = z.strictObject({
  enabled: z.literal(true), kind: z.literal('sessions'), owner: z.literal(OWNER_ID),
  agent: z.literal('main'), expiresAt: z.string().datetime(), timeoutSeconds: z.number().int().min(1).max(120),
  createTasks: z.array(TASK_SCHEMA).max(1), followupTasks: z.array(TASK_SCHEMA).max(1),
  maxCreations: z.number().int().min(0).max(1), maxFollowups: z.number().int().min(0).max(1), maxAssignments: z.number().int().min(0).max(1),
  allowedSessionKeys: z.array(key).max(5),
});
// Separate, absent-by-default approval; no MCP tool writes or enables it.
export function loadSessionApproval(path = `${ROOT}state/session-approval.json`, now = Date.now()) {
  try {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o077) || stat.size > 8192) return null;
    const policy = SESSION_APPROVAL_SCHEMA.parse(JSON.parse(readFileSync(path, 'utf8')));
    const remaining = Date.parse(policy.expiresAt) - now;
    return remaining > 0 && remaining <= 2 * 3600_000 ? policy : null;
  } catch { return null; }
}
export const SESSION_NAMES = Object.keys(SESSION_INPUTS);
