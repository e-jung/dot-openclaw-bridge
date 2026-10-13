import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

function prepare(env) {
  return spawnSync(process.execPath, ['--input-type=module', '-e', `
    import { prepareOwnerAuthRuntime } from './src/owner-auth.mjs';
    try { await prepareOwnerAuthRuntime({ownerEnrollmentApproved:true,
      identityProvider:()=>{ throw new Error('IDENTITY_REACHED'); }}); }
    catch (e) { process.stdout.write(e.code || e.message); }
  `], { cwd: new URL('..', import.meta.url), env: { ...process.env,
    DOT_BRIDGE_OWNER_ID: '', DOT_BRIDGE_GATEWAY_URL: '', ...env }, encoding: 'utf8' });
}
test('production preparation rejects missing settings before identity access', () => {
  const p = prepare({}); assert.equal(p.status, 0); assert.equal(p.stdout, 'OWNER_CONFIGURATION_REQUIRED');
});
test('production preparation rejects unsafe endpoint and malformed owner', () => {
  for (const [owner,url] of [
    ['invalid','wss://gateway.example.invalid'],
    ['00000000-0000-4000-8000-000000000002','ws://gateway.example.invalid'],
    ['00000000-0000-4000-8000-000000000002','wss://user:password@gateway.example.invalid'],
  ]) { const p=prepare({DOT_BRIDGE_OWNER_ID:owner,DOT_BRIDGE_GATEWAY_URL:url});
    assert.equal(p.status,0);assert.equal(p.stdout,'OWNER_CONFIGURATION_INVALID'); }
});
test('valid local configuration reaches identity preparation', () => {
  const p=prepare({DOT_BRIDGE_OWNER_ID:'00000000-0000-4000-8000-000000000002',DOT_BRIDGE_GATEWAY_URL:'wss://gateway.example.invalid'});
  assert.equal(p.status,0);assert.equal(p.stdout,'IDENTITY_REACHED');
});
