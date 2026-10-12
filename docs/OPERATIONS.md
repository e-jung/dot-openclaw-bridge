# Operations

The worker retries transient transport failures every 60 seconds. With ten allowed starts per 300 seconds this avoids the observed 10-second retry loop exhausting systemd's start limit during an outage. Exit 78 still prevents automatic retries for permission, pairing and contract errors.

Inspect first:

```sh
systemctl --user status dot-bridge-session-worker.service
journalctl --user -u dot-bridge-session-worker.service -n 30
npm run check:health
```

After correcting a verified transient outage or supervision problem, reset the failed state and start only this worker. Do not restart the Gateway or replace approvals/identity as a recovery shortcut. Review the ledger for pending/uncertain work before activation.

The initial recovery changed only the deployed retry interval and restarted the worker. Local MCP health then returned sessionAccess=true and rpcAuthorization=authenticated-worker. No session operation was dispatched; dot chat/voice tests and prolonged-outage injection were not performed.

Rollback: restore only the prior service configuration or code release, reload systemd, and restart the worker as appropriate. Never restore old ledger snapshots, credentials, identity or grants as part of a code rollback. Keep private backups outside this repository.

This source checkout is separate from the original deployment; importing source does not migrate its live state. Any future deployment must preserve the existing state directory and identity, provide explicit owner/endpoint settings, and verify readiness afterward.
