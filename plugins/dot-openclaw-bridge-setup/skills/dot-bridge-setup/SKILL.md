---
name: dot-bridge-setup
description: Install, connect, or diagnose the self-hosted dot / OpenClaw session MCP bridge using the user's own Gateway and private OpenAI tunnel. Use for this bridge, not general Gateway or plugin setup.
---

# Dot / OpenClaw bridge setup

This bundle contains guidance only. Bridge code, Node dependencies and tunnel-client are installed separately. Do not claim installation alone enables access.

## Source and supported path

Use https://github.com/e-jung/dot-openclaw-bridge, runtime release `v0.3.0`, commit `3d993c2e014475d23c3b63df8a8e8f67d6803977`. Clone into a new user-chosen directory, check out that commit, and read its README.md, SECURITY.md and docs/OPERATIONS.md before deployment. Use `npm ci` and `npm test` from that checkout. Never overwrite an existing checkout or deploy into the installed plugin bundle directory.

Use the README's standing-session path. Bounded session trials are legacy/advanced and are not a supported setup. Bounded job dispatch is separate and should remain disabled for session-only setup.

## Inspect, configure, connect

1. Inspect any existing bridge services, checkout, state and tunnel first. For an upgrade, back up code/config and use SQLite's online backup API for a live ledger. Check for pending or uncertain operations before a restart; preserve them, do not replay them. Never restore a stale ledger as a code rollback.
2. Obtain the user's own Gateway human profile UUID and authenticated `wss://` endpoint. Set `DOT_BRIDGE_OWNER_ID` and `DOT_BRIDGE_GATEWAY_URL` consistently for both the worker and the stdio adapter (including the tunnel's child environment). Do not infer an owner from a display name or copy another user's settings. Prerequisites: Node.js 24+, supported Gateway protocol/client compatibility, and authenticated Tailscale Serve access. Check versions against the pinned release documentation.
3. Follow the standing policy example. Use a fresh policy UUID and owner identity, review limits with the user within their authorized scope, keep state mode 0700 and private files 0600. Do not enable concurrent bounded grants. For a new deployment, guide the user through interactive `node src/standing-worker.mjs --enroll` and approval of only its dedicated device with exactly `operator.read` and `operator.write`. Do not self-approve pairing, reuse another client's key, or reenroll an existing deployment to repair a transport failure.
4. Configure the supplied user service with correct absolute checkout/Node paths and environment. Preserve existing service settings; retain the documented 60-second retry and fail-closed exit 78 behavior. Do not restart the Gateway as a bridge setup shortcut. For non-systemd hosts, explain that supervision needs separate configuration/verification.
5. Use the official tunnel-client and current guide at https://developers.openai.com/api/docs/guides/secure-mcp-tunnels. Create the user's own tunnel in their own permitted organization/workspace. Store runtime credentials locally using the supported protected mechanism; never put them in source, arguments, logs or chat. The private MCP command is `node /absolute/checkout/src/stdio.mjs`. Prefer the official tunnel setup workflow when available instead of inventing transport machinery.
6. Guide the user to ChatGPT Plugins → Add custom MCP server → Connection: Tunnel → select their tunnel → configure required authentication → Create as a plugin. Account/workspace permissions and tunnel availability must be verified, not assumed. A reusable instruction package does not retarget someone else's registered connection. Secure MCP Tunnels do not support public ChatGPT plugin-directory distribution.

## Verify and hand over

Run `npm run check:health` with the same owner/endpoint environment. Require `sessionAccess=true` and `rpcAuthorization=authenticated-worker`; check tunnel readiness independently. Have the user ask the actual dot chat to list sessions. Session calls can return a queued operation: poll `get_session_operation` using the same operation ID at a bounded interval until terminal, without resubmitting a write. Preserve idempotency keys for write retries.

Report local readiness separately from actual chat success. Test creation/follow-up only when authorized and report voice separately; chat success does not certify voice. The release caps operations at 120 seconds and is not a durable long-running delegation service. Do not promise automatic wakeups or complete session history.

For failures, inspect service state, redacted errors, owner/endpoint consistency, policy, worker authorization and tunnel readiness. Never broaden permissions or replace identity/grants as a shortcut. End with source version, verified checks, remaining account-side steps and the code-only rollback location.
