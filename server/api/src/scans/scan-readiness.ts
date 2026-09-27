import { readFileSync } from 'node:fs';
import { connect } from 'node:net';

function productionBoundaryAccepted(): boolean {
  return false; // Deliberate release gate: outstanding controlled Docker/Trivy proof.
}

function reachable(host: string, port: number, timeout: number): Promise<boolean> {
  return new Promise(resolve => {
    const socket = connect({ host, port, timeout });
    let done = false;
    const end = (value: boolean) => { if (!done) { done = true; socket.destroy(); resolve(value); } };
    socket.once('connect', () => end(true));
    socket.once('error', () => end(false));
    socket.once('timeout', () => end(false));
  });
}

// Operational checks cannot attest to the full scanner/redirect/rebind boundary.
// No new production jobs until controlled production-path negative integration tests
// and same-tag mutation acceptance have passed independent review. Do not replace
// this gate with an environment toggle or a TCP-only health check.
export async function chainReady(): Promise<boolean> {
  if (!productionBoundaryAccepted()) return false;
  const marker = process.env.SCAN_WORKER_READY_PATH;
  if (!marker || !process.env.SCAN_LEDGER_PATH) return false;
  try {
    const raw = readFileSync(marker, 'utf8');
    if (!/^\d{13}$/.test(raw)) return false;
    const age = Date.now() - Number(raw);
    if (age < 0 || age > 5000) return false;
  } catch { return false; }
  const [gateway, bypass] = await Promise.all([
    reachable('egress', 8080, 1000), reachable('1.1.1.1', 443, 1000),
  ]);
  return gateway && !bypass;
}
