import { generateKeyPairSync, createPublicKey, createHash, sign } from 'node:crypto';

// Official GatewayClient deliberately delegates identity/signing/storage to
// the host. Never borrow a CLI/browser identity or cached bearer credential.
export function generateBridgeIdentity() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  return { deviceId: createHash('sha256').update(rawPublicKey(publicKeyPem)).digest('hex'), publicKeyPem, privateKeyPem };
}

function rawPublicKey(pem) {
  const key = createPublicKey(pem);
  const der = key.export({ type: 'spki', format: 'der' });
  if (key.asymmetricKeyType !== 'ed25519' || der.length !== 44) throw new Error('BRIDGE_IDENTITY_INVALID');
  return der.subarray(-32);
}

export function bridgeIdentityHostDeps() {
  return {
    loadOrCreateDeviceIdentity: () => undefined,
    loadDeviceAuthToken: () => null,
    storeDeviceAuthToken() {},
    clearDeviceAuthToken() {},
    signDevicePayload: (pem, payload) => sign(null, Buffer.from(payload, 'utf8'), pem).toString('base64url'),
    publicKeyRawBase64UrlFromPem: pem => rawPublicKey(pem).toString('base64url'),
    logDebug() {},
    logError() {},
  };
}
