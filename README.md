# dot / OpenClaw bridge

Experimental, self-hosted MCP bridge for owner-bound OpenClaw session access. MIT licensed. Run **one private instance per owner**; this is not a hosted multi-tenant service.

## Features

- MCP stdio health, bounded jobs, session list/read/create/assign/follow-up tools.
- SQLite operation ledger and stable idempotency keys.
- Dedicated device identity, exact read/write scopes, owner verification and native session visibility enforcement.
- Official, lockfile-pinned OpenClaw Gateway client; no private build imports.
- Fail-closed grants and systemd worker recovery after transient Gateway outages.

## Requirements and setup

Node.js 24+, Linux for the supplied systemd unit, and an OpenClaw Gateway with protocol 4 and authenticated Tailscale Serve access. Client/protocol packages are pinned to 2026.8.1. Recovery was live-checked against OpenClaw 2026.10.2; other versions require validation.

```sh
npm ci
npm test
node scripts/check-health.mjs
```

Health/discovery works without granting session access. To enable access deliberately:

1. Set local `DOT_BRIDGE_OWNER_ID` to your Gateway human profile UUID and `DOT_BRIDGE_GATEWAY_URL` to your authenticated `wss://` Gateway endpoint. These are administrator environment settings, never MCP arguments. Both adapter and worker must use the same owner configuration.
2. Create `state/` with mode 0700. Copy `deploy/standing-session-policy.example.json` to `state/standing-session-policy.json` (mode 0600), replace the owner and policy UUID, review limits, and explicitly set `enabled: true`. Do not enable concurrent bounded grants.
3. In an interactive terminal, run `node src/standing-worker.mjs --enroll`. Use `auth`, approve only the displayed dedicated device in your Gateway with exactly `operator.read` and `operator.write`, then use `auth`, `reconnect`, and `stop`. Do not reuse another client's identity. Never reenroll an existing deployment to fix transport failures.
4. For systemd, put the two environment settings in `~/.config/dot-openclaw-bridge/worker.env` (0600). Install the provided user unit after adjusting its checkout and Node paths. It assumes `~/dot-openclaw-bridge`. Run `systemctl --user daemon-reload` and `systemctl --user enable --now dot-bridge-session-worker.service`.
5. Connect your private MCP transport to `node /absolute/path/to/src/stdio.mjs`, with the same environment. Run `npm run check:health` to require authenticated readiness. Keep your tunnel profile and credentials outside Git. A tunnel binary or dot plugin is not bundled.

No tool can approve pairing, change policy, or configure an arbitrary Gateway. Never expose the loopback HTTP adapter directly to the Internet. Deployment is manual and experimental; clean-install and dot chat/voice interoperability are not certified.

## Known limits

- Operations are capped at 120 seconds. This is not yet a long-running background delegation service.
- Lost dispatch acknowledgment can leave an operation `unknown`; it is deliberately not blindly replayed. Some uncertainty needs operator reconciliation.
- No owner-scoped operation search, standing-mode retention policy, or durable event stream yet.
- Gateway restarts do not have a proven durable-history result fallback.
- Local authenticated readiness does not prove dot chat and voice share a route or that completion wakes a disconnected client.

See [architecture and roadmap](docs/ARCHITECTURE.md), [operations](docs/OPERATIONS.md), and [security](SECURITY.md). The existing issue about bounded session-history truncation remains open.
