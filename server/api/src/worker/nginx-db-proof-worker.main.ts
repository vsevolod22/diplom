import { spawnSync } from 'node:child_process';
import { connect } from 'node:net';
import { existsSync, writeFileSync, unlinkSync } from 'node:fs';
import { ScanLedger } from '../ledger/ledger.js';
import { consumeOne } from './outbox-consumer.js';
import { scanNginxArchive } from './archive-scan-worker.js';
import { recoverArchiveScratch } from '../oci/bounded-image-archive.js';
import { readDbProofConfig } from '../oci/nginx-db-proof-profile.js';

// Only an operator exec inside this disposable project can release the barrier.
// Readiness is the real gateway/live wall-clock heartbeat, even while claims pause.
if (process.env.SCAN_LEDGER_PATH !== '/data/ledger.sqlite' || process.env.SCAN_WORKER_READY_PATH !== '/data/worker.ready' ||
    process.env.TRIVY_CACHE_DIR !== '/tmp/trivy' || process.env.SCAN_JWT_ISSUER !== 'dip-nginx-db-disposable-proof')
  throw new Error('Isolated DB proof worker required');
const { config, vuln } = await readDbProofConfig();
await recoverArchiveScratch();
const ledger = new ScanLedger('/data/ledger.sqlite');
const version = spawnSync('/usr/local/bin/trivy', ['--version'], { timeout: 5000, maxBuffer: 4096, encoding: 'utf8',
  stdio: ['ignore', 'pipe', 'ignore'], env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp' } });
if (version.status !== 0 || !/^Version: 0\.69\.3\r?$/m.test(version.stdout ?? '')) throw new Error('Proof scanner unavailable');
let stopping = false;
process.on('SIGTERM', () => { stopping = true; });
process.on('SIGINT', () => { stopping = true; });
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
async function gatewayReady(): Promise<boolean> {
  return new Promise(resolve => {
    const socket = connect({ host: 'egress', port: 8080, timeout: 2000 });
    socket.once('connect', () => { socket.destroy(); resolve(true); });
    socket.once('error', () => { socket.destroy(); resolve(false); });
    socket.once('timeout', () => { socket.destroy(); resolve(false); });
  });
}
async function heartbeat() {
  if (await gatewayReady()) writeFileSync('/data/worker.ready', String(Date.now()), { mode: 0o600 });
  else { try { unlinkSync('/data/worker.ready'); } catch { /* absent */ } }
}
const archiveRunner: typeof scanNginxArchive = async (...args) => {
  const report = await scanNginxArchive(...args);
  if (config.phase === 'precommit') {
    // No synthetic report: the actual archive/Trivy/parser/final-audit path must
    // have succeeded while fresh before we cross expiry at the consumer boundary.
    if (report.vuln?.outcome !== 'checked' || Date.now() >= Date.parse(report.vuln.db.nextUpdate))
      throw new Error('Precommit phase not observed while fresh');
    writeFileSync('/data/db-proof.stage.json', JSON.stringify({ phase: 'precommit', observedAt: Date.now(),
      nextUpdate: report.vuln.db.nextUpdate, checkedAt: report.checkedAt }), { mode: 0o600 });
    const deadline = Date.now() + 120_000;
    while (!existsSync('/data/db-proof.go')) {
      if (stopping || args[1].signal?.aborted || Date.now() >= deadline) throw new Error('Proof barrier expired');
      await heartbeat(); await sleep(100);
    }
  }
  return report;
};
try {
  while (!stopping) {
    await heartbeat();
    if (config.phase !== 'queued' || existsSync('/data/db-proof.go'))
      await consumeOne(ledger, { timeoutMs: 60_000, dbDir: '/tmp/trivy', vuln, archivePolicy: 'proof' }, undefined, Date.now(), undefined, undefined, archiveRunner);
    await sleep(500);
  }
} finally {
  try { unlinkSync('/data/worker.ready'); } catch { /* absent */ }
  ledger.close();
}
