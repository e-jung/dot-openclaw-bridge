import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createMcpServer } from './server.mjs';
import { SessionStore } from './session-store.mjs';
import { loadSessionAccessPolicy } from './standing-policy.mjs';
import { JobStore } from './jobs.mjs';
import { loadApproval } from './policy.mjs';
process.umask(0o077);
// This key belongs to the tunnel client, not the adapter.
delete process.env.CONTROL_PLANE_API_KEY;
const jobs = new JobStore(process.env.DOT_BRIDGE_STATE_PATH);
const server = createMcpServer(18789, { stdio: true, jobs, sessions: new SessionStore(jobs),
  sessionApproval: loadSessionAccessPolicy,
  approval: () => loadApproval(process.env.DOT_BRIDGE_APPROVAL_PATH) });
await server.connect(new StdioServerTransport(process.stdin, process.stdout, { maxBufferSize: 16 * 1024 }));
let closed = false;
const close = async () => {
  if (closed) return;
  closed = true;
  await server.close();
  jobs.close();
  process.exit(0);
};
process.stdin.once('end', close);
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, close);
