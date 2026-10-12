import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { loadApproval } from '../src/policy.mjs';
import { SESSION_NAMES } from '../src/session-policy.mjs';
import { loadSessionAccessPolicy } from '../src/standing-policy.mjs';
const client = new Client({name:'read-only-discovery-check',version:'1.0.0'});
try {
  await client.connect(new StdioClientTransport({command:'node',args:[new URL('../src/stdio.mjs', import.meta.url).pathname],env:{...process.env},stderr:'ignore'}));
  const {tools}=await client.listTools();
  if (JSON.stringify(tools.map(t=>t.name))!==JSON.stringify(['health','submit_job','get_job','cancel_job',...SESSION_NAMES])) throw new Error('Unexpected tool exposure');
  const result=await client.callTool({name:'health',arguments:{}});
  const data=result.structuredContent;
  if (!data || !data.capabilities.jobControl || data.capabilities.transport!=='stdio') throw new Error('Unexpected capabilities');
  if (data.capabilities.agentDispatch && (!loadApproval(process.env.DOT_BRIDGE_APPROVAL_PATH) || data.gateway.rpcAuthorization!=='authenticated-worker')) throw new Error('Enabled dispatch requires active owner approval and authenticated worker');
  if (data.capabilities.sessionAccess && (!loadSessionAccessPolicy() || data.gateway.rpcAuthorization!=='authenticated-worker')) throw new Error('Enabled sessions require separate approval and owner-verified worker');
  if (process.argv.includes('--require-ready') && (!data.capabilities.sessionAccess || data.gateway.rpcAuthorization !== 'authenticated-worker' || data.gateway.reachability !== 'reachable')) throw new Error('SESSION_WORKER_NOT_READY');
  // Discovery/health only. Never admit jobs, session writes, or session reads.
  process.stdout.write(JSON.stringify({tools:tools.map(t=>t.name),health:data})+'\n');
} finally { await client.close(); }
