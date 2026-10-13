import { constants, fsyncSync, openSync, closeSync, fstatSync, readFileSync, writeFileSync, mkdirSync, lstatSync } from 'node:fs';
import { dirname } from 'node:path';
import { createPublicKey, createPrivateKey, createHash } from 'node:crypto';
import { ROOT } from './policy.mjs';
import { OwnerAuthError } from './owner-auth.mjs';

export const DEVICE_PATH = `${ROOT}state/credentials/owner-device.json`;
// Dedicated bridge identity only. Never load the browser/CLI identity or tokens.
export function storedIdentity(generate, { enrollment = false, path = DEVICE_PATH } = {}) {
  let fd;
  try {
    if (enrollment) {
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
      const dir = lstatSync(dirname(path));
      if (!dir.isDirectory() || dir.uid !== process.getuid() || (dir.mode & 0o077)) throw new Error();
      fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      const identity = generate();
      writeFileSync(fd, JSON.stringify(identity));
      fsyncSync(fd);
      closeSync(fd); fd = undefined;
      return identity;
    }
    const dir = lstatSync(dirname(path));
    if (!dir.isDirectory() || dir.uid !== process.getuid() || (dir.mode & 0o077)) throw new Error();
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o077) || stat.size > 8192) throw new Error();
    const identity = JSON.parse(readFileSync(fd, 'utf8'));
    const pub = createPublicKey(identity.publicKeyPem);
    const priv = createPrivateKey(identity.privateKeyPem);
    if (pub.asymmetricKeyType !== 'ed25519' || priv.asymmetricKeyType !== 'ed25519') throw new Error();
    const der = pub.export({ type: 'spki', format: 'der' });
    if (!der.equals(createPublicKey(priv).export({ type: 'spki', format: 'der' }))) throw new Error();
    // Native fingerprint is SHA-256 of canonical 32-byte Ed25519 public key.
    if (der.length !== 44 || createHash('sha256').update(der.subarray(-32)).digest('hex') !== identity.deviceId) throw new Error();
    return identity;
  } catch { throw new OwnerAuthError(enrollment ? 'STANDING_IDENTITY_ENROLLMENT_FAILED' : 'STANDING_IDENTITY_UNAVAILABLE'); }
  finally { if (fd !== undefined) closeSync(fd); }
}
