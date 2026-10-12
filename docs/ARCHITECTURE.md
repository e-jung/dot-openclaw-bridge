# Architecture and roadmap

Private MCP client → private transport → stdio adapter → SQLite ledger → independently supervised worker → official Gateway client → OpenClaw sessions.

The adapter owns admission and bounded result formatting. The worker owns owner-authenticated execution. A frontend disconnect must not own the worker lifetime. HTTP liveness is separate from fresh worker lease and owner proof.

Existing upstream options were reviewed before retaining this layer: native OpenClaw MCP `messages_send` replies outward through a channel route rather than delegating through `sessions.send`; freema/openclaw-mcp 1.7.0 uses process-local, connection-owned task handles. Neither is a drop-in durable session-orchestration replacement.

Next milestones:

1. Reconcile uncertain dispatch acceptance using stable Gateway identifiers, without automatic replay.
2. Separate caller wait from execution lifetime; design explicit exact-run cancellation.
3. Add owner-scoped operation listing/request-key lookup and bounded retention.
4. Recover results from durable history across Gateway restarts; durable event cursors and gap recovery.
5. Test frontend hangup/reconnect, prolonged outages, independent component restarts, duplicate retries, revocation, clean installs and upgrades.

These are planned, not implemented guarantees.
