import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { startBridge, probeGateway, VERSION } from '../src/server.mjs';

async function mockGateway(status = 200) {
  const requests = [];
  const server = http.createServer((req, res) => {
    requests.push({ method: req.method, path: req.url, authorization: req.headers.authorization });
    res.writeHead(status, { 'Content-Type': 'application/json', ...(status === 302 ? { Location: 'http://127.0.0.1:1/never-follow' } : {}) });
    res.end(JSON.stringify({ status: 'ok', privateDetails: 'must-not-be-returned' }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return {
    port: server.address().port, requests,
    close: () => new Promise(resolve => server.close(resolve)),
  };
}

async function fixture(t) {
  const gateway = await mockGateway();
  const bridge = await startBridge({ port: 0, gatewayPort: gateway.port });
  t.after(async () => { await bridge.close(); await gateway.close(); });
  return { gateway, bridge };
}

async function connect(t, bridge) {
  const client = new Client({ name: 'phase-1-test', version: '1.0.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(bridge.url)));
  t.after(() => client.close());
  return client;
}

function request(bridge, { headers = {}, body = '{}', method = 'POST', path = '/mcp', chunked = false } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(bridge.url);
    const req = http.request({ hostname: url.hostname, port: url.port, path, method,
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', ...headers } }, res => {
      const parts = [];
      res.on('data', part => parts.push(part));
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(parts).toString('utf8') }));
    });
    req.on('error', reject);
    if (chunked) { req.write(body.slice(0, 10)); req.write(body.slice(10)); req.end(); }
    else req.end(body);
  });
}

test('SDK initialization, tool discovery, schemas, annotations, and sanitized health', async t => {
  const { gateway, bridge } = await fixture(t);
  assert.equal(bridge.address.address, '127.0.0.1');
  const client = await connect(t, bridge);
  assert.equal(client.getServerVersion().version, VERSION);
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map(tool => tool.name), ['health']);
  assert.equal(tools[0].inputSchema.additionalProperties, false);
  assert.equal(tools[0].annotations.readOnlyHint, true);
  assert.equal(tools[0].annotations.destructiveHint, false);
  const result = await client.callTool({ name: 'health', arguments: {} });
  assert.equal(result.isError, undefined);
  assert.equal(result.structuredContent.gateway.reachability, 'reachable');
  assert.equal(result.structuredContent.gateway.rpcAuthorization, 'not-tested');
  assert.equal(result.structuredContent.capabilities.agentDispatch, false);
  assert.equal(result.structuredContent.capabilities.sessionAccess, false);
  assert.equal(result.structuredContent.capabilities.jobControl, false);
  assert.doesNotMatch(JSON.stringify(result), /privateDetails|must-not-be-returned|127\.0\.0\.1|token/i);
  assert.deepEqual(gateway.requests, [{ method: 'GET', path: '/healthz', authorization: undefined }]);
});

test('unknown tools and health arguments cannot become dispatch or arbitrary probes', async t => {
  const { gateway, bridge } = await fixture(t);
  const client = await connect(t, bridge);
  const invalid = await client.callTool({ name: 'health', arguments: { gatewayUrl: 'https://example.com', agent: 'main' } });
  assert.equal(invalid.isError, true);
  for (const name of ['submit_job', 'list_sessions', 'get_job_status', 'get_job_result', 'send_followup', 'cancel_job']) {
    const denied = await client.callTool({ name, arguments: {} });
    assert.equal(denied.isError, true);
    assert.match(JSON.stringify(denied.content), /not found/i);
  }
  assert.equal(gateway.requests.length, 0);
});

test('DNS rebinding, browser origins, and forwarded requests are denied before probing', async t => {
  const { gateway, bridge } = await fixture(t);
  for (const headers of [
    { Host: 'attacker.example:8787' },
    { Origin: 'https://attacker.example' },
    { Origin: 'null' },
    { Forwarded: 'for=127.0.0.1' },
    { 'X-Forwarded-For': '127.0.0.1' },
  ]) assert.equal((await request(bridge, { headers })).status, 403);
  assert.equal(gateway.requests.length, 0);
});

test('path, method, content type, invalid JSON, and declared/chunked body bounds', async t => {
  const { gateway, bridge } = await fixture(t);
  assert.equal((await request(bridge, { path: '/' })).status, 404);
  assert.equal((await request(bridge, { method: 'GET' })).status, 405);
  assert.equal((await request(bridge, { method: 'DELETE' })).status, 405);
  assert.equal((await request(bridge, { headers: { 'Content-Type': 'text/plain' } })).status, 415);
  assert.equal((await request(bridge, { body: '{bad-json' })).status, 400);
  const oversized = JSON.stringify({ message: 'x'.repeat(17000) });
  assert.equal((await request(bridge, { body: oversized, headers: { 'Content-Length': Buffer.byteLength(oversized) } })).status, 413);
  assert.equal((await request(bridge, { body: oversized, chunked: true })).status, 413);
  assert.equal(gateway.requests.length, 0);
});

test('Gateway unavailable and redirect states are sanitized; redirects are not followed', async () => {
  const unavailable = await mockGateway(503);
  const redirect = await mockGateway(302);
  try {
    assert.equal(await probeGateway(unavailable.port), 'not_ready');
    assert.equal(await probeGateway(redirect.port), 'unreachable');
  } finally { await unavailable.close(); await redirect.close(); }
  assert.equal(await probeGateway(unavailable.port), 'unreachable');
});

test('invalid ports fail without binding and public host overrides are unavailable', async t => {
  for (const value of [-1, 65536, 'no', 1.5]) {
    await assert.rejects(startBridge({ port: value }), /Invalid adapter port/);
  }
  await assert.rejects(startBridge({ gatewayPort: 0 }), /Invalid Gateway port/);
  const bridge = await startBridge({ port: 0, host: '0.0.0.0' });
  t.after(() => bridge.close());
  assert.equal(bridge.address.address, '127.0.0.1');
});

test('MCP client disconnect and adapter restart do not create session or dispatch capabilities', async t => {
  const gateway = await mockGateway();
  t.after(() => gateway.close());
  const first = await startBridge({ port: 0, gatewayPort: gateway.port });
  const client = new Client({ name: 'restart-test', version: '1.0.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(first.url)));
  await client.callTool({ name: 'health', arguments: {} });
  await client.close();
  const port = first.address.port;
  await first.close();
  const second = await startBridge({ port, gatewayPort: gateway.port });
  t.after(() => second.close());
  const next = await connect(t, second);
  assert.deepEqual((await next.listTools()).tools.map(tool => tool.name), ['health']);
  assert.equal((await next.callTool({ name: 'health', arguments: {} })).structuredContent.gateway.reachability, 'reachable');
  assert.equal(gateway.requests.length, 2);
});
