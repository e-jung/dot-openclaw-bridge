import { readFileSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { z } from 'zod/v4';

export const ROOT = fileURLToPath(new URL('../', import.meta.url));
export const LIMITS = Object.freeze({ taskChars: 2000, taskBytes: 4096, resultChars: 4096,
  resultBytes: 8192, timeoutSeconds: 120, maxActive: 1, maxJobs: 100 });
export const TASK_SCHEMA = z.string().min(1).max(LIMITS.taskChars)
  .refine(s => s.trim().length > 0 && Buffer.byteLength(s) <= LIMITS.taskBytes && !s.includes('\0'));
export const SUBMIT_SCHEMA = z.strictObject({ task: TASK_SCHEMA,
  idempotency_key: z.string().regex(/^[A-Za-z0-9_-]{8,128}$/) });
export const JOB_SCHEMA = z.strictObject({ job_id: z.string().uuid() });
export const APPROVAL_SCHEMA = z.strictObject({ enabled: z.literal(true),
  agent: z.string().regex(/^[a-z][a-z0-9_-]{0,63}$/),
  expiresAt: z.string().datetime(), maxAdmissions: z.number().int().min(1).max(2),
  tasks: z.array(TASK_SCHEMA).min(1).max(2),
  timeoutSeconds: z.number().int().min(1).max(LIMITS.timeoutSeconds) });

// Only the local owner can create this file after explicit approval. No tool can
// enable dispatch, change limits, select an agent or supply authentication.
export function loadApproval(path = `${ROOT}approval.json`, now = Date.now()) {
  try {
    const stat = statSync(path);
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o077)) return null;
    const approval = APPROVAL_SCHEMA.parse(JSON.parse(readFileSync(path, 'utf8')));
    if (Date.parse(approval.expiresAt) <= now || Date.parse(approval.expiresAt) - now > 2 * 3600_000) return null;
    return approval;
  } catch { return null; }
}
export function policyHash(policy) {
  return createHash('sha256').update(JSON.stringify(policy)).digest('hex');
}

// Standing access is an explicit distinct policy, never an expiry renewal.
export const policyExpiry = policy => policy?.kind === "sessions" && policy.mode === "standing" ? Number.MAX_SAFE_INTEGER : Date.parse(policy?.expiresAt);
