import { spawnSync } from 'node:child_process';
import { connect } from 'node:net';
import { writeFileSync, unlinkSync } from 'node:fs';
import { ScanLedger } from '../ledger/ledger.js';
import { consumeOne } from './outbox-consumer.js';

const file = process.env.SCAN_LEDGER_PATH;
const ready = process.env.SCAN_WORKER_READY_PATH;
if (!file || !ready || !process.env.TRIVY_CACHE_DIR) throw new Error('Worker storage is required');
const ledger = new ScanLedger(file);
const version = spawnSync('trivy', ['--version'], { stdio: 'ignore', timeout: 5000,
  env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp' } });
if (version.status !== 0) throw new Error('Scanner binary unavailable');

function gatewayReady(): Promise<boolean> {
  return new Promise(resolve => {
    const socket = connect({ host: 'egress', port: 8080, timeout: 2000 });
    socket.once('connect', () => { socket.destroy(); resolve(true); });
    socket.once('error', () => { socket.destroy(); resolve(false); });
    socket.once('timeout', () => { socket.destroy(); resolve(false); });
  });
}

let stopping = false;
process.on('SIGTERM', () => { stopping = true; });
process.on('SIGINT', () => { stopping = true; });
try {
  while (!stopping) {
    if (!(await gatewayReady())) {
      try { unlinkSync(ready); } catch { /* absent marker */ }
      await new Promise(resolve => setTimeout(resolve, 2000));
      continue;
    }
    // Heartbeat is ephemeral evidence of a live process, not proof of an intact
    // network boundary. Deployment inspection and negative probes are still required.
    writeFileSync(ready, String(Date.now()), { mode: 0o600 });
    await consumeOne(ledger, { timeoutMs: 60_000, dbDir: process.env.TRIVY_CACHE_DIR! });
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
} finally {
  try { unlinkSync(ready); } catch { /* absent marker */ }
  ledger.close();
}
