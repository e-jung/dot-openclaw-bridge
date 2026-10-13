import { GatewayClient } from '@openclaw/gateway-client';
import { PROTOCOL_VERSION } from '@openclaw/gateway-protocol/version';
import { generateBridgeIdentity, bridgeIdentityHostDeps } from './official-client.mjs';
import { OWNER_ID } from './session-policy.mjs';
import { createSessionGateway, SESSION_ADVERTISED_METHODS } from './session-gateway.mjs';
export const OWNER_ENDPOINT = process.env.DOT_BRIDGE_GATEWAY_URL || 'wss://gateway.example.invalid';
const zOwnerId = value => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
export const OWNER_SCOPES = ['operator.read', 'operator.write'];
export class OwnerAuthError extends Error {
  constructor(code, pending = null, diagnostic = null) { super(code); this.code = code; this.pending = pending; this.diagnostic = diagnostic; }
}
const exactScopes = value => Array.isArray(value) && value.length === 2 && new Set(value).size === 2 && OWNER_SCOPES.every(s => value.includes(s));
const AUTH_DETAIL_CODES = new Set([
  'AUTH_REQUIRED', 'AUTH_UNAUTHORIZED', 'AUTH_TOKEN_MISSING', 'AUTH_TOKEN_MISMATCH', 'AUTH_TOKEN_NOT_CONFIGURED',
  'AUTH_PASSWORD_MISSING', 'AUTH_PASSWORD_MISMATCH', 'AUTH_PASSWORD_NOT_CONFIGURED', 'AUTH_BOOTSTRAP_TOKEN_INVALID',
  'AUTH_DEVICE_TOKEN_MISMATCH', 'AUTH_RATE_LIMITED', 'AUTH_TAILSCALE_IDENTITY_MISSING', 'AUTH_TAILSCALE_PROXY_MISSING',
  'AUTH_TAILSCALE_WHOIS_FAILED', 'AUTH_TAILSCALE_IDENTITY_MISMATCH', 'AUTH_IDENTITY_HEADER_REQUIRED',
  'AUTH_VERIFIED_USER_REQUIRED', 'AUTHENTICATED_PROFILE_UNAVAILABLE', 'OPERATOR_ACCESS_DENIED',
  'CONTROL_UI_DEVICE_IDENTITY_REQUIRED', 'DEVICE_IDENTITY_REQUIRED', 'DEVICE_AUTH_INVALID',
  'DEVICE_AUTH_DEVICE_ID_MISMATCH', 'DEVICE_AUTH_SIGNATURE_EXPIRED', 'DEVICE_AUTH_NONCE_REQUIRED',
  'DEVICE_AUTH_NONCE_MISMATCH', 'DEVICE_AUTH_SIGNATURE_INVALID', 'DEVICE_AUTH_PUBLIC_KEY_INVALID',
]);
const CONTRACT_DETAIL_CODES = new Set(['CONTROL_UI_BUILD_MISMATCH', 'CONTROL_UI_ORIGIN_NOT_ALLOWED', 'PROTOCOL_MISMATCH', 'CLIENT_VERSION_MISMATCH']);
const GATEWAY_CODES = new Set(['NOT_PAIRED', 'INVALID_REQUEST', 'UNAVAILABLE', 'FORBIDDEN', 'UNAUTHORIZED']);
const TLS_CODES = new Set(['ERR_TLS_CERT_ALTNAME_INVALID', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'ERR_SSL_WRONG_VERSION_NUMBER']);
const TRANSPORT_CODES = new Set(['ECONNREFUSED', 'ECONNRESET', 'EHOSTUNREACH', 'ENETUNREACH', 'ENOTFOUND', 'EAI_AGAIN', 'ETIMEDOUT', 'EPIPE']);

// Never attach a raw error/cause/message, payload, URL, header or recovery advice.
// Unknown codes remain unknown; pairing records and text are not auth evidence.
function connectFailure(error, publicDevice) {
  const d = error?.details;
  const gatewayCode = GATEWAY_CODES.has(error?.gatewayCode) ? error.gatewayCode : null;
  const detailCode = [...AUTH_DETAIL_CODES, ...CONTRACT_DETAIL_CODES, 'PAIRING_REQUIRED', 'AUTH_SCOPE_MISMATCH'].includes(d?.code) ? d.code : null;
  const diagnostic = { stage: 'connect', device_id: publicDevice,
    ...(gatewayCode ? { gateway_code: gatewayCode } : {}), ...(detailCode ? { detail_code: detailCode } : {}) };
  const failure = (code, category, extra = {}, pending = null) => new OwnerAuthError(code, pending, { ...diagnostic, category, ...extra });
  if (detailCode === 'PAIRING_REQUIRED') {
    const field = (value, valid) => value === undefined || value === null ? 'missing' : valid ? 'valid' : 'invalid';
    const fields = {
      request_id: field(d.requestId, typeof d.requestId === 'string' && /^[A-Za-z0-9-]{1,128}$/.test(d.requestId)),
      device_id: field(d.deviceId, d.deviceId === publicDevice),
      role: field(d.requestedRole, d.requestedRole === 'operator'),
      scopes: field(d.requestedScopes, exactScopes(d.requestedScopes)),
    };
    const reason = ['not-paired', 'role-upgrade', 'scope-upgrade', 'metadata-upgrade'].includes(d.reason) ? d.reason : null;
    const extra = { pairing_fields: fields, ...(reason ? { pairing_reason: reason } : {}) };
    if (Object.values(fields).every(v => v === 'valid')) {
      const pending = { request_id: d.requestId, device_id: publicDevice, role: 'operator', scopes: [...OWNER_SCOPES], client: 'gateway-client', mode: 'backend' };
      return failure('OWNER_DEVICE_APPROVAL_REQUIRED', 'pairing-required', extra, pending);
    }
    // A missing optional requestId is allowed by the native response contract,
    // but is not an actionable selector. Never recover it from raw text/latest.
    if (Array.isArray(d.requestedScopes) && !exactScopes(d.requestedScopes)) return failure('OWNER_SCOPE_MISMATCH', 'scope-mismatch', extra);
    return failure('OWNER_PAIRING_DETAILS_INVALID', 'pairing-details-invalid', extra);
  }
  if (detailCode === 'AUTH_SCOPE_MISMATCH') return failure('OWNER_SCOPE_MISMATCH', 'scope-mismatch');
  if (AUTH_DETAIL_CODES.has(detailCode)) return failure('OWNER_AUTH_REJECTED', 'authentication-failed');
  if (CONTRACT_DETAIL_CODES.has(detailCode)) return failure('OWNER_GATEWAY_REJECTED', 'gateway-contract-rejected');
  if (d?.reason === 'websocket-upgrade-rejected') return failure('OWNER_TRANSPORT_FAILED', 'websocket-upgrade-rejected',
    Number.isInteger(d.httpStatus) && d.httpStatus >= 100 && d.httpStatus <= 599 ? { http_status: d.httpStatus } : {});
  // These pinned native classes inherit Error.name unchanged; use their fixed
  // constructor names for classification only, never echo an arbitrary name.
  if (error?.constructor?.name === 'GatewayWebSocketTlsPinError') return failure('OWNER_TLS_FAILED', 'tls-failed');
  if (['GatewayWebSocketTransportConfigurationError', 'GatewayClientTransportPolicyError'].includes(error?.constructor?.name)) {
    return failure('OWNER_TRANSPORT_FAILED', 'transport-policy-rejected');
  }
  if (TLS_CODES.has(error?.code)) return failure('OWNER_TLS_FAILED', 'tls-failed', { transport_code: error.code });
  if (TRANSPORT_CODES.has(error?.code)) return failure('OWNER_TRANSPORT_FAILED', 'transport-failed', { transport_code: error.code });
  if (error?.code === 'CLIENT_TIMEOUT') return failure('OWNER_AUTH_TIMEOUT', 'timeout');
  if (gatewayCode === 'NOT_PAIRED') return failure('OWNER_PAIRING_DETAILS_INVALID', 'pairing-details-missing');
  if (gatewayCode) return failure('OWNER_GATEWAY_REJECTED', 'gateway-rejected');
  return failure('OWNER_CONNECT_UNKNOWN', 'connect-failure-unknown');
}
// Creating a live runtime requires separate owner approval;
// this flag is a caller guard, not a substitute for the human's authorization.
export async function prepareOwnerAuthRuntime({ ownerEnrollmentApproved = false, policy = { agent: 'main' }, identityProvider } = {}) {
  if (!ownerEnrollmentApproved) throw new OwnerAuthError('OWNER_ENROLLMENT_NOT_APPROVED');
  if (!process.env.DOT_BRIDGE_OWNER_ID || !process.env.DOT_BRIDGE_GATEWAY_URL) throw new OwnerAuthError('OWNER_CONFIGURATION_REQUIRED');
  let endpoint;
  try { endpoint = new URL(OWNER_ENDPOINT); } catch { throw new OwnerAuthError('OWNER_CONFIGURATION_INVALID'); }
  if (!zOwnerId(OWNER_ID) || endpoint.protocol !== 'wss:' || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) throw new OwnerAuthError('OWNER_CONFIGURATION_INVALID');
  // Use the reviewed, lockfile-pinned public client instead of private CLI
  // build artifacts. Wire/role/scope/method/owner gates are enforced on every
  // hello and RPC; an incompatible protocol still fails closed.
  if (PROTOCOL_VERSION !== 4) throw new OwnerAuthError('OWNER_AUTH_VERSION_CHANGED');
  return createOwnerAuthRuntime({ GatewayClient,
    identity: identityProvider ? await identityProvider(generateBridgeIdentity) : generateBridgeIdentity(), policy });
}
// Mock seam. No general RPC object, token fallback, enrollment approval action,
// worker activation or admission is exposed through this runtime.
export function createOwnerAuthRuntime({ GatewayClient, identity, policy, timeoutMs = 5000 }) {
  let client; let connected = false; let ownerVerified = false; let epoch = 0; let disposed = false;
  const secrets = new Set([identity.privateKeyPem]);
  const publicDevice = identity.deviceId;
  const sanitize = text => [...secrets].reduce((s, secret) => secret ? s.split(secret).join('[REDACTED]') : s, text);
  const request = async (method, params, requestTimeout = 5000) => {
    if (!connected || !ownerVerified && method !== 'users.self') throw new OwnerAuthError('OWNER_AUTH_UNAVAILABLE');
    const generation = epoch;
    let value;
    try { value = await client.request(method, params, { timeoutMs: requestTimeout, expectFinal: false }); }
    catch { throw new OwnerAuthError('OWNER_RPC_UNCERTAIN'); }
    if (!connected || epoch !== generation) throw new OwnerAuthError('OWNER_RPC_UNCERTAIN');
    return value;
  };
  const backend = createSessionGateway(request, policy, sanitize);
  function stopConnection() {
    connected = false; ownerVerified = false; epoch++;
    const previous = client; client = null;
    // Native stop can synchronously notify onConnectError and later onClose.
    // Detach first so neither callback can replace the failure or a newer proof.
    try { previous?.stop(); } catch { /* Never replace a primary failure with raw stop errors. */ }
  }
  async function open() {
    if (disposed) throw new OwnerAuthError('OWNER_AUTH_DISPOSED');
    stopConnection();
    await new Promise((resolve, reject) => {
      let failed = false; let attempt;
      const fail = error => {
        if (failed) return;
        failed = true; clearTimeout(timer); reject(error); stopConnection();
      };
      const timer = setTimeout(() => fail(new OwnerAuthError('OWNER_AUTH_TIMEOUT', null,
        { stage: 'connect', category: 'timeout', device_id: publicDevice })), timeoutMs);
      const current = () => !failed && client === attempt && !disposed;
      try {
        attempt = new GatewayClient({ url: OWNER_ENDPOINT, deviceIdentity: identity,
          role: 'operator', scopes: [...OWNER_SCOPES], edgeAuthHeaders: { 'X-OpenClaw-Scopes': 'operator.read,operator.write' },
          // Preserve the already-paired Linux metadata; the public client does not
          // add OpenClaw's host-wrapper deviceFamily default.
          clientName: 'gateway-client', mode: 'backend', platform: 'linux', deviceFamily: 'Linux',
          clientDisplayName: 'Dot bridge temporary owner-auth backend',
          minProtocol: 4, maxProtocol: 4, requestTimeoutMs: 5000,
          hostDeps: bridgeIdentityHostDeps(),
          onClose(code, _reason, info) {
            if (!current()) return;
            if (!connected) {
              fail(info?.connectError ? connectFailure(info.connectError, publicDevice) : new OwnerAuthError('OWNER_TRANSPORT_FAILED', null,
                { stage: 'connect', category: 'transport-closed', device_id: publicDevice,
                  ...Number.isInteger(code) && code >= 1000 && code <= 4999 ? { close_code: code } : {} }));
            } else { connected = false; ownerVerified = false; epoch++; }
          },
          onConnectError(error) {
            if (current()) fail(connectFailure(error, publicDevice));
          },
          onHelloOk(hello) {
            if (!current()) return;
            connected = false; ownerVerified = false; epoch++;
            if (typeof hello?.auth?.deviceToken === 'string') secrets.add(hello.auth.deviceToken);
            const category = hello?.protocol !== 4 ? 'protocol-mismatch' : hello.auth?.method !== 'tailscale' ? 'auth-method-mismatch'
              : hello.auth?.role !== 'operator' ? 'role-mismatch' : !exactScopes(hello.auth.scopes) ? 'scope-mismatch'
              : !Array.isArray(hello.features?.methods) || !SESSION_ADVERTISED_METHODS.every(m => hello.features.methods.includes(m)) ? 'methods-mismatch' : null;
            if (category) {
              fail(new OwnerAuthError('OWNER_HELLO_REJECTED', null, { stage: 'hello', category, device_id: publicDevice })); return;
            }
            connected = true; ownerVerified = false; epoch++; const generation = epoch;
            backend.verifyOwner().then(() => {
              if (!connected || epoch !== generation) throw new OwnerAuthError('OWNER_AUTH_UNCERTAIN');
              ownerVerified = true; clearTimeout(timer); resolve();
            }).catch(error => {
              if (current()) fail(new OwnerAuthError('OWNER_IDENTITY_REJECTED', null, { stage: 'owner', device_id: publicDevice,
                category: error?.code === 'CONNECTED_OWNER_MISMATCH' ? 'identity-mismatch' : 'identity-unavailable' }));
            });
          },
        });
        client = attempt; client.start();
      } catch (error) { fail(connectFailure(error, publicDevice)); }
    });
    return { ...backend, close: stopConnection };
  }
  return { open, reconnect: open, publicDeviceId: publicDevice,
    proof() { return { device_id: publicDevice, owner_verified: connected && ownerVerified, owner_id: connected && ownerVerified ? OWNER_ID : null,
      auth_method: connected && ownerVerified ? 'tailscale' : null, scopes: connected && ownerVerified ? [...OWNER_SCOPES] : [] }; },
    dispose() { stopConnection(); disposed = true; identity = null; secrets.clear(); },
  };
}
