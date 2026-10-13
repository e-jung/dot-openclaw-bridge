import { z } from 'zod/v4';
import { readFileSync, lstatSync } from 'node:fs';
import { ROOT } from './policy.mjs';
import { OWNER_ID, SESSION_APPROVAL_SCHEMA, loadSessionApproval } from './session-policy.mjs';

// A distinct explicit standing grant, never a renewal of a bounded test grant.
export const STANDING_POLICY_SCHEMA = z.strictObject({
  enabled: z.literal(true), kind: z.literal('sessions'), mode: z.literal('standing'),
  owner: z.literal(OWNER_ID), agent: z.literal('main'), targets: z.literal('visible-main'),
  policyId: z.string().uuid(), timeoutSeconds: z.number().int().min(1).max(120),
  maxModelTurnsPerDay: z.number().int().min(1).max(1000),
});
export const SESSION_ACCESS_SCHEMA = z.union([SESSION_APPROVAL_SCHEMA, STANDING_POLICY_SCHEMA]);
export function loadStandingPolicy(path = `${ROOT}state/standing-session-policy.json`) {
  try {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o077) || stat.size > 8192) return null;
    return STANDING_POLICY_SCHEMA.parse(JSON.parse(readFileSync(path, 'utf8')));
  } catch { return null; }
}
export function loadSessionAccessPolicy() {
  const bounded = loadSessionApproval(process.env.DOT_BRIDGE_SESSION_APPROVAL_PATH);
  const standing = loadStandingPolicy(process.env.DOT_BRIDGE_STANDING_POLICY_PATH);
  // Simultaneous grants are ambiguous; never pick the broader one silently.
  return bounded && standing ? null : bounded || standing;
}
