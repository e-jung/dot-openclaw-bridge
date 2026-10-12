// Separate process, test-only backend. It never imports Gateway authentication.
import { JobStore } from '../../src/jobs.mjs';
import { JobWorker } from '../../src/worker.mjs';
const [path, rawPolicy] = process.argv.slice(2);
const store = new JobStore(path);
let observations = 0;
const backend = {
  async dispatch(row) { return { runId: row.run_id, status: 'accepted' }; },
  async observe(row) {
    observations++;
    if (observations === 1) return { runId: row.run_id, status: 'timeout' };
    return { runId: row.run_id, status: 'ok', stopReason: 'stop', endedAt: Date.now(), terminalReply: { disposition: 'visible', text: 'PROCESS_RECONNECT_OK' } };
  },
  sanitize: text => text,
};
const worker = new JobWorker(store, backend, JSON.parse(rawPolicy));
process.send('ready');
const tick = async () => {
  await worker.tick();
  if (observations >= 2) { process.send('completed'); return; }
  timer = setTimeout(tick, 100);
};
let timer = setTimeout(tick, 100);
process.on('message', message => {
  if (message === 'close') {
    clearTimeout(timer); worker.close(); store.close(); process.disconnect();
  }
});
