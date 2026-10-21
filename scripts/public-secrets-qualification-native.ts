import '../server/api/node_modules/reflect-metadata/Reflect.js';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { isDeepStrictEqual } from 'node:util';

import type { AddressInfo } from 'node:net';

import type { Job } from '../server/api/src/ledger/ledger.js';
import type { ArchiveBinding } from '../server/api/src/oci/archive-identity.js';
import { makeFixture, hasPrivate, sha } from './public-secrets-qualification-fixture.mjs';
import { prepareBoundedImageArchive } from '../server/api/src/oci/bounded-image-archive.js';
import { inspectPublicImage } from '../server/api/src/oci/public-image-inspection.js';
import { PUBLIC_IMAGE_PROFILE } from '../server/api/src/oci/public-image-policy.js';
import { validateArchiveJson } from '../server/api/src/oci/archive-identity.js';
import { scanPublicImageArchive, type ArchiveScanReport } from '../server/api/src/worker/archive-scan-worker.js';
import { runArchiveProcess } from '../server/api/src/worker/archive-process.js';
import { auditArchiveScratch } from '../server/api/src/worker/archive-scratch.js';
import { parseSecretFindings } from '../server/api/src/worker/secret-findings.js';
import { consumeOne } from '../server/api/src/worker/outbox-consumer.js';
import { PublicImageModule, configurePublicImageIngress } from '../server/api/src/oci/public-image.module.js';
import { ScansService } from '../server/api/src/scans/scans.service.js';
import { LedgerStore } from '../server/api/src/ledger/ledger-store.js';

// Typed views do not project/filter the original native JSON or HTTP bytes.
// Existing validation, redaction and equality assertions remain authoritative.
interface NativeSecretFinding { RuleID: string; }
interface NativeSecretResult { Target: string; Secrets?: NativeSecretFinding[]; }
interface NativeSecretReport { Results: NativeSecretResult[]; }
type PublicationJob = Pick<Job, 'scanId' | 'attempts' | 'leaseToken'>;
type QualificationApplication = Parameters<typeof configurePublicImageIngress>[0];
interface SqliteStatement<Row> {
  get(...parameters: unknown[]): Row | undefined;
  all(...parameters: unknown[]): Row[];
  run(...parameters: unknown[]): unknown;
}
interface SqliteConnection {
  prepare<Row = Record<string, unknown>>(sql: string): SqliteStatement<Row>;
  close(): void;
}
export interface QualificationSnapshot {
  status: { scanId: string; state: string; profile?: string; perCheck?: Record<string, unknown> };
  results: { findings: ReturnType<typeof parseSecretFindings> };
  report: { page?: { totalCount: number } };
  events: string;
}

const require = createRequire('/app/server/api/package.json');
const { NestFactory }: typeof import('../server/api/node_modules/@nestjs/core/index.js') = require('@nestjs/core');
const Database = require('better-sqlite3') as new (path: string, options?: { readonly?: boolean }) => SqliteConnection;
const checks: Record<string, boolean> = {};
let stage = 'initialization';
let failedCheck = 'unclassified';
function check(value: unknown, name: string): asserts value {
  if (!value) { failedCheck = name; throw new Error('Qualification assertion failed'); }
  checks[name] = true;
}
const equal = (a: unknown, b: unknown, name: string) => check(isDeepStrictEqual(a, b), name);
const deferred = () => { let resolve!: () => void; const promise = new Promise<void>(done => { resolve = done; }); return { promise, resolve }; };
const bounded = <T>(work: Promise<T>, ms = 8000): Promise<T> => Promise.race([work, new Promise<never>((_, reject) => {
  const timer = setTimeout(() => reject(new Error('bounded-wait')), ms); timer.unref();
})]);

async function main() {
  process.umask(0o077);
  check(process.getuid?.() === 65532, 'nonroot');
  await mkdir('/tmp/qualification', { mode: 0o700 });
  Object.assign(process.env, { AUTH_DB_PATH: '/tmp/qualification/auth.sqlite', SCAN_LEDGER_PATH: '/tmp/qualification/ledger.sqlite',
    AUTH_ORIGIN: 'http://127.0.0.1:8081', AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true',
    SCAN_BROWSER_ALLOWED_USER_IDS: '', SCAN_VULN_ENABLED: 'false', SCAN_VULN_RELEASE_DIR: '', LLM_ENABLED: 'false' });
  const source = makeFixture();
  const forbidden = [...source.values, source.marker, source.path];
  const password = randomBytes(24).toString('hex'); forbidden.push(password);
  const safe = (value: unknown, name: string) => check(!hasPrivate(value, forbidden), name);
  let app: QualificationApplication | undefined;
  let base = '';
  let nativeCalls = 0, acceptedCheckpoints = 0, archiveCleanups = 0;
  let firstReport: ArchiveScanReport | undefined;
  let firstJob: PublicationJob | undefined;
  let duplicateRows = 0, duplicateInputRows = 0, originalRows = 0, retainedFreshAuditRows = 0;
  let duplicateRawRowsMerge = false;
  const openApi = async () => {
    app = await NestFactory.create<QualificationApplication>(PublicImageModule, { logger: false, bodyParser: false });
    configurePublicImageIngress(app);
    const service = app.get(ScansService);
    // Test-only readiness and transport: never contact the shared worker/egress/registry.
    Object.defineProperty(service, 'readiness', { value: async () => true });
    Object.defineProperty(service, 'inspect', { value: (ref: Parameters<typeof inspectPublicImage>[0]) => inspectPublicImage(ref, source.fetch) });
    await app.listen(0, '127.0.0.1');
    base = `http://127.0.0.1:${(app.getHttpServer().address() as AddressInfo).port}/api/v1`;
    check(!base.includes(':8080/'), 'no8080');
  };
  const call = async <T = unknown>(path: string, cookie?: string, method = 'GET', body?: unknown, expected = 200, headers = {}) => {
    const response = await fetch(base + path, { method, headers: { ...(cookie ? { cookie } : {}),
      ...(method === 'POST' ? { origin: 'http://127.0.0.1:8081', 'content-type': 'application/json' } : {}), ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(5000) });
    check(response.status === expected, `http-${method}-${expected}`);
    const text = await response.text(); safe(text, 'http-redaction');
    if (expected === 200) check(response.headers.get('cache-control') === 'no-store', 'http-no-store');
    return { response, text, json: (text && !path.endsWith('/events') ? JSON.parse(text) : undefined) as T };
  };
  const register = async (name: string) => {
    const result = await call<{ id: string }>('/auth/register', undefined, 'POST', { email: `${name}@example.invalid`, password }, 201);
    const cookie = result.response.headers.get('set-cookie')!.split(';')[0];
    forbidden.push(cookie, cookie.slice(cookie.indexOf('=') + 1));
    return { cookie, id: result.json.id };
  };
  const admission = (key: string, selected = ['secret']) => ({ imageReference: `registry-1.docker.io/${source.target.repository}@${source.target.digest}`,
    scope: 'image', checks: selected, idempotencyKey: key });
  const dbAbsent = () => { throw new Error('CVE DB forbidden in Secrets qualification'); };
  const lifecycle = (mode: string, ready = deferred(), release = deferred()) => ({
    requireScanner() {
      const version = spawnSync('/usr/local/bin/trivy', ['--version'], { timeout: 5000, maxBuffer: 4096,
        encoding: 'utf8', env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp' }, stdio: ['ignore', 'pipe', 'ignore'] });
      check(version.status === 0 && /^Version: 0\.69\.3\r?$/m.test(version.stdout), 'trivy-version');
    },
    prepare: async (signal: AbortSignal | undefined, target: Parameters<typeof prepareBoundedImageArchive>[1]) => {
      const archive = await prepareBoundedImageArchive(signal, target, PUBLIC_IMAGE_PROFILE, source.request);
      equal(archive.receipt.configDigest, source.target.configDigest, 'actual-config-digest');
      equal(archive.receipt.diffIds, [sha(source.layer)], 'actual-diffids');
      equal(archive.receipt.layerDigests, [sha(source.compressed)], 'actual-layer-digests');
      check(sha(await readFile(archive.archivePath)) === archive.receipt.archiveSha256, 'actual-archive-hash');
      return { ...archive, cleanup: async () => { await archive.cleanup(); archiveCleanups++; } };
    },
    invoke: async (kind: 'secret' | 'sbom' | 'vuln', binding: ArchiveBinding, directory: string, signal: AbortSignal) => {
      if (kind === 'sbom' && mode === 'checkpoint-cancel') {
        ready.resolve(); await release.promise; throw new Error('Controlled cancelled sibling');
      }
      check(kind === 'secret', 'secrets-only-native');
      const raw = await runArchiveProcess(kind, binding.archivePath, directory, signal) as NativeSecretReport;
      nativeCalls++;
      validateArchiveJson(raw, binding);
      const secrets = (raw.Results ?? []).flatMap((result) => result.Secrets ?? []);
      check(secrets.length === 2 && secrets.every((item) => item.RuleID === 'github-pat'), 'actual-positive-built-in-rule');
      check(raw.Results.some((item) => item.Target.includes(source.marker)), 'actual-positive-target');
      const normalized = parseSecretFindings(raw, binding); safe(normalized, 'normalizer-redaction');
      equal(normalized.map(item => item.line).sort(), [1, 2], 'native-line-provenance');
      check(new Set(normalized.map(item => item.evidenceRef)).size === 2, 'distinct-safe-evidence-refs');
      const wrong: ArchiveBinding = { ...binding, receipt: { ...binding.receipt, configDigest: `sha256:${'f'.repeat(64)}` } };
      let rejected = false; try { parseSecretFindings(raw, wrong); } catch { rejected = true; }
      check(rejected, 'wrong-identity-rejected-without-projection');
      if (mode === 'positive' || mode === 'duplicate-derived') {
        // Explicit report derivative, never a claim that Trivy emitted duplicates.
        const derivative = structuredClone(raw);
        for (const item of derivative.Results) if (item.Secrets) item.Secrets.push(...structuredClone(item.Secrets));
        const repeated = parseSecretFindings(derivative, binding);
        originalRows = normalized.length; duplicateRows = repeated.length;
        duplicateInputRows = derivative.Results.flatMap((item) => item.Secrets ?? []).length;
        duplicateRawRowsMerge = isDeepStrictEqual(repeated, normalized);
        check(duplicateInputRows === 4 && duplicateRawRowsMerge, 'exact-native-row-duplicates-merge-with-first-ids');
        safe(repeated, 'derivative-redaction');
        if (mode === 'duplicate-derived') return derivative;
      }
      if (mode === 'buffered-cancel') { ready.resolve(); await release.promise; }
      return raw; // Original positive/cancel JSON is unchanged; derivative mode is labelled separately.
    },
    audit: auditArchiveScratch, verifiedDb: dbAbsent,
    deadlineSignal: AbortSignal.timeout(45_000),
  });
  const consume = (mode: string, ready?: ReturnType<typeof deferred>, release?: ReturnType<typeof deferred>) => {
    const ledger = app!.get(LedgerStore).ledger!;
    const injected = lifecycle(mode, ready, release);
    const noLegacy = async (): Promise<never> => { throw new Error('Legacy adapter forbidden'); };
    return consumeOne(ledger, { timeoutMs: 120_000, dbDir: '/unused', publicImagePolicy: true }, noLegacy,
      Date.now(), noLegacy, noLegacy, noLegacy,
      async (selected, options) => {
        const original = options.onCheckpoint;
        if (mode === 'positive') {
          const row = new Database('/tmp/qualification/ledger.sqlite', { readonly: true });
          try { firstJob = row.prepare<PublicationJob>('SELECT scan_id AS scanId, attempts, lease_token AS leaseToken FROM outbox WHERE delivered_at IS NULL').get(); }
          finally { row.close(); }
        }
        const report = await scanPublicImageArchive(selected, { ...options, onCheckpoint: (kind, completed) => {
          const accepted = original?.(kind, completed) ?? true;
          if (accepted) acceptedCheckpoints++;
          return accepted;
        } }, injected);
        safe(report, 'adapter-redaction');
        if (mode === 'positive') firstReport = report;
        return report;
      });
  };
  const persistence = async () => {
    const db = new Database('/tmp/qualification/ledger.sqlite', { readonly: true });
    try {
      for (const { name } of db.prepare<{ name: string }>("SELECT name FROM sqlite_master WHERE type='table'").all()) {
        check(/^[a-zA-Z0-9_]+$/.test(name), 'safe-table-name');
        safe(db.prepare(`SELECT * FROM "${name}"`).all(), 'all-ledger-tables-redacted');
      }
    } finally { db.close(); }
    for (const file of await readdir('/tmp/qualification')) {
      if (/^ledger\.sqlite(?:-wal|-shm)?$/.test(file)) safe(await readFile(`/tmp/qualification/${file}`), 'sqlite-main-wal-shm-redacted');
    }
  };
  try {
    stage = 'http-admission'; await openApi();
    const owner = await register('qualification-owner'), other = await register('qualification-other');
    const path = '/browser/scans';
    const made = await call<{ scanId: string }>(path, owner.cookie, 'POST', admission('qualification-positive'), 202);
    const id = made.json.scanId;
    equal((await call<{ scanId: string }>(path, owner.cookie, 'POST', admission('qualification-positive'), 202)).json.scanId, id, 'idempotent-admission');
    stage = 'native-positive';
    check(await consume('positive'), 'public-consumer-executed');
    const ledger = app!.get(LedgerStore).ledger!;
    check(firstReport?.secret?.outcome === 'checked', 'adapter-checked-positive');
    equal(ledger.archiveResult(id, owner.id)?.secret, firstReport.secret, 'consumer-ledger-exact-findings');
    check(ledger.finishArchive(id, firstJob!.attempts, firstReport, undefined, firstJob!.leaseToken) === false, 'duplicate-terminal-publication-fenced');
    const snapshot = async (scanId: string): Promise<QualificationSnapshot> => {
      const status = (await call<QualificationSnapshot['status']>(`${path}/${scanId}`, owner.cookie)).json;
      const results = (await call<QualificationSnapshot['results']>(`${path}/${scanId}/results`, owner.cookie)).json;
      const hasResult = !!status.perCheck?.secret;
            const report = (await call<QualificationSnapshot['report']>(`${path}/${scanId}/results?view=report-v1&limit=25&sort=ruleId%3Aasc`, owner.cookie,
              'GET', undefined, hasResult ? 200 : 404)).json;
      const events = (await call(`${path}/${scanId}/events`, owner.cookie)).text;
      for (const suffix of ['', '/results', '/results?view=report-v1', '/events']) {
        await call(`${path}/${scanId}${suffix}`, other.cookie, 'GET', undefined, 404);
        await call(`${path}/${scanId}${suffix}`, undefined, 'GET', undefined, 401);
      }
      return { status, results, report, events };
    };
    stage = 'http-positive-sinks';
    const positive = await snapshot(id);
    check(positive.status.state === 'completed' && positive.status.profile === PUBLIC_IMAGE_PROFILE, 'http-completed-public-profile');
    check(positive.results.findings.length === 2 && positive.report.page!.totalCount === 2, 'http-positive-count');
    equal(positive.results.findings, firstReport.secret.findings, 'http-exact-provenance');
    check(['queued', 'running', 'completed'].every(state => positive.events.includes(`"state":"${state}"`)), 'sse-terminal-replay');
    const events = ledger.events(id, owner.id, null);
    check((await call(`${path}/${id}/events`, owner.cookie, 'GET', undefined, 200, { 'last-event-id': String(events!.at(-1)!.id) })).text.includes('event: scan') === false, 'sse-no-duplicate-after-terminal-cursor');
    await persistence();
    const cases: Record<string, QualificationSnapshot> = { positive };
    stage = 'duplicate-derived-sinks';
    const duplicateCreated = await call<{ scanId: string }>(path, owner.cookie, 'POST', admission('qualification-duplicate-derived'), 202);
    check(await consume('duplicate-derived'), 'duplicate-derived-public-consumer-executed');
    const duplicateCase = await snapshot(duplicateCreated.json.scanId);
    check(duplicateCase.status.state === 'completed' && duplicateCase.report.page!.totalCount === 2, 'duplicate-derived-sink-count');
    equal(duplicateCase.results.findings, positive.results.findings, 'duplicate-derived-sinks-keep-exact-original-ids-and-evidence');
    cases['duplicate-derived'] = duplicateCase;
    await persistence();
    for (const mode of ['buffered-cancel', 'checkpoint-cancel']) {
      stage = mode;
      const selected = mode === 'checkpoint-cancel' ? ['secret', 'sbom'] : ['secret'];
      const created = await call<{ scanId: string }>(path, owner.cookie, 'POST', admission(`qualification-${mode}`, selected), 202);
      const scanId = created.json.scanId;
      const ready = deferred(), release = deferred();
      const work = consume(mode, ready, release);
      try {
        await bounded(ready.promise);
        await call(`${path}/${scanId}/cancel`, other.cookie, 'POST', {}, 404);
        await call(`${path}/${scanId}/cancel`, owner.cookie, 'POST', {});
        await bounded(work);
      } finally { release.resolve(); }
      // The consumer may finish before the deliberately uncooperative adapter.
      for (let attempt = 0; attempt < 100 && (await readdir('/tmp/trivy/jobs')).length; attempt++) await new Promise(resolve => setTimeout(resolve, 20));
      check((await readdir('/tmp/trivy/jobs')).length === 0, `${mode}-scratch-clean`);
      const cancelled = await snapshot(scanId);
      check(cancelled.status.state === 'cancelled', `${mode}-terminal-cancel`);
      check(!cancelled.events.includes('"state":"completed"'), `${mode}-no-late-terminal`);
      if (mode === 'buffered-cancel') check(cancelled.results.findings.length === 0, 'buffered-no-positive-publication');
      else equal(cancelled.results.findings, firstReport.secret.findings, 'checkpoint-positive-preserved');
      cases[mode] = cancelled;
      await persistence();
    }
    check(ledger.pending().length === 0, 'outbox-delivery-fenced');
    stage = 'reopen';
    await app!.close(); app = undefined;
    await openApi();
    for (const [name, saved] of Object.entries(cases)) equal(await snapshot(saved.status.scanId), saved, `${name}-reopen-exact`);
    await persistence();
    stage = 'retention';
    const writer = new Database('/tmp/qualification/ledger.sqlite');
    try { writer.prepare("UPDATE scans SET terminal_at=datetime('now','-31 days') WHERE id=?").run(id); }
    finally { writer.close(); }
    check(app!.get(LedgerStore).ledger!.prune(30) === 1, 'retention-only-aged-terminal');
    for (const suffix of ['', '/results', '/events']) await call(`${path}/${id}${suffix}`, owner.cookie, 'GET', undefined, 404);
    const observer = new Database('/tmp/qualification/ledger.sqlite', { readonly: true });
    try {
      for (const { name } of observer.prepare<{ name: string }>("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all()) {
        const columns = observer.prepare<{ name: string }>(`PRAGMA table_info("${name}")`).all();
        if (columns.some((column) => column.name === 'scan_id')) {
                  const count = observer.prepare<{ n: number }>(`SELECT count(*) AS n FROM "${name}" WHERE scan_id=?`).get(id)!.n;
                  if (name === 'scan_audit') retainedFreshAuditRows = count;
                  else check(count === 0, 'retention-dependent-report-rows-gone');
                }
      }
    } finally { observer.close(); }
    await app!.close(); app = undefined; await openApi();
    await call(`${path}/${id}`, owner.cookie, 'GET', undefined, 404);
    for (const name of ['duplicate-derived', 'buffered-cancel', 'checkpoint-cancel']) equal(await snapshot(cases[name].status.scanId), cases[name], 'retention-preserves-young-scans');
    await persistence();
    check(nativeCalls === 4 && archiveCleanups === 4 && acceptedCheckpoints === 3, 'bounded-four-native-cohort');
    check((await readdir('/tmp/trivy/jobs')).length === 0, 'all-attempt-scratch-removed');
    const evidence = { version: 1, executedAt: new Date().toISOString(), checks,
      counts: { nativeInvocations: nativeCalls, nativeFindingsPerInvocation: originalRows, acceptedCheckpoints, archiveCleanups, duplicateDerivativeInputRows: duplicateInputRows, duplicateDerivativeRows: duplicateRows, retainedFreshAuditRows },
      provenance: { manifest: source.target.digest, config: source.target.configDigest, layer: sha(source.compressed), diffId: sha(source.layer),
        archive: firstReport.receipt.archiveSha256, scanner: '0.69.3' },
      boundaries: { syntheticTransport: true, readinessInjected: true, positiveAndCancelNativeJsonUnmodified: true,
              duplicateSinkUsesExplicitNativeDerivative: true, realPublicAdapterConsumerLedger: true,
        cancelBarriersSynthetic: true, semanticDuplicateRowsMerged: duplicateRawRowsMerge, cveQualification: false, liveQualification: false },
      cases };
    safe(evidence, 'evidence-redaction');
    await writeFile('/qualification-output/handoff.json', JSON.stringify(evidence), { mode: 0o600, flag: 'wx' });
  } finally {
    if (app) await app.close();
    await rm('/tmp/qualification', { recursive: true, force: true });
  }
}
main().then(() => process.stdout.write(JSON.stringify({ passed: true, checks: Object.keys(checks).length }) + '\n')).catch(async () => {
  // Only authored fixed labels; never exception strings, assertion operands, raw output or stacks.
  await writeFile('/qualification-output/failure.json', JSON.stringify({ passed: false, stage,
    failedCheck, checks }), { mode: 0o600 }).catch(() => {});
  process.stdout.write(JSON.stringify({ passed: false, checks: Object.keys(checks).length }) + '\n'); process.exitCode = 1;
});
