import { spawn, type ChildProcess, type SpawnOptions } from 'node:child_process';

type Check = 'secret' | 'sbom' | 'vuln';
// Internal test seam, never sourced from a request, environment or profile.
type Runtime = { launch?: (command: string, args: string[], options: SpawnOptions) => ChildProcess; timeoutMs?: number; fallback?: () => void };
export async function runArchiveProcess(check: Check, archivePath: string, directory: string,
  signal: AbortSignal, runtime: Runtime = {}): Promise<unknown> {
  if (signal.aborted) throw new Error('Archive scanner failed');
  const cap = check === 'vuln' ? 8_000_000 : check === 'sbom' ? 2_000_000 : 1_000_000;
  return new Promise((resolve, reject) => {
    const child = (runtime.launch ?? spawn)('/usr/local/bin/trivy', ['image', '--input', archivePath,
      '--scanners', check === 'sbom' ? 'secret' : check, '--format', check === 'sbom' ? 'cyclonedx' : 'json',
      '--list-all-pkgs', '--skip-db-update', '--skip-java-db-update', '--offline-scan', '--cache-dir',
      `${directory}/cache`, '--timeout', '120s', '--quiet'],
    { shell: false, stdio: ['ignore', 'pipe', 'ignore'], env: {
      PATH: '/usr/local/bin:/usr/bin:/bin', HOME: directory, TMPDIR: directory,
    } });
    let bytes = 0, killed = false;
    const chunks: Buffer[] = [];
    let fallback: ReturnType<typeof setTimeout> | undefined;
    const kill = () => {
      if (killed) return;
      killed = true; chunks.length = 0; child.kill('SIGKILL');
      fallback = setTimeout(runtime.fallback ?? (() => process.exit(1)), 2000);
    };
    const timer = setTimeout(kill, runtime.timeoutMs ?? 120_000);
    signal.addEventListener('abort', kill, { once: true });
    if (signal.aborted) kill();
    child.stdout!.on('data', (chunk: Buffer) => {
      if (killed) return;
      bytes += chunk.length;
      if (bytes > cap) kill(); else chunks.push(Buffer.from(chunk));
    });
    child.on('error', kill);
    child.on('close', code => {
      clearTimeout(timer); clearTimeout(fallback); signal.removeEventListener('abort', kill);
      if (killed || code !== 0 || signal.aborted) { reject(new Error('Archive scanner failed')); return; }
      try { resolve(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)))); }
      catch { reject(new Error('Archive scanner failed')); }
    });
  });
}
