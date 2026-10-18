/* eslint-disable @typescript-eslint/no-explicit-any -- Disposable qualification harness traverses native scanner JSON and adversarial derivatives; production parsers remain the validation boundary. */
// Run from server/api: node --import tsx ../../scripts/task2-qualification-run.ts
// Native detection + explicitly separate identity-projected TEMP sink qualification.
import { createRequire } from 'node:module';
import { createHmac, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, mkdtempSync, readdirSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isDeepStrictEqual as same } from 'node:util';
import { fileURLToPath } from 'node:url';
import { check, fixture, nativeScan, publicField, sha256, IMAGE } from './task2-qualification-native.mjs';

const require = createRequire(new URL('../server/api/package.json', import.meta.url));
require('reflect-metadata');
const { NestFactory } = require('@nestjs/core');
const Database = require('better-sqlite3');
const root = fileURLToPath(new URL('..', import.meta.url)).replace(/\/$/, '');
const evidencePath = join(root, 'server/deploy/proof/task2-qualification-results.json');
const evidence: any = { schemaVersion: 1, startedAt: new Date().toISOString(), scannerImage: IMAGE,
  scope: 'native-local-inventory-detection; identity-projected-temporary-sinks; NOT remote admission or whole-task qualification',
  containers: [], checks: [], success: false };
let phase = 'initialization';
const pass = (name: string, detail: object = {}) => evidence.checks.push({ name, status: 'PASS', ...detail });
const sourcePaths = ['server/api/src/worker/secret-findings.ts', 'server/api/src/worker/vuln-findings.ts',
  'server/api/src/worker/vuln-advisory.ts', 'server/api/src/worker/cve-db-policy.mjs',
  'server/api/src/worker/vuln-db-bundle.ts', 'server/api/src/ledger/ledger.ts',
  'server/api/src/scans/scans.service.ts', 'scripts/task2-qualification-native.mjs', 'scripts/task2-qualification-run.ts'];
const sourceHashes = () => Object.fromEntries(sourcePaths.map(path => [path, sha256(readFileSync(join(root, path)))]));
evidence.sourcesBefore = sourceHashes();
let temporary: string | undefined;
let app: any;
try {
  phase = 'public-discovery';
  const release = publicField(['inspect', '--format', '{{range .Mounts}}{{if and (eq .Destination "/opt/release") (not .RW)}}{{.Source}}{{end}}{{end}}', 'dip-local-full-worker-1']);
  const dbMount = publicField(['inspect', '--format', '{{range .Mounts}}{{if and (eq .Destination "/tmp/trivy/db") (not .RW)}}{{.Source}}{{end}}{{end}}', 'dip-local-full-worker-1']);
  const publicKey = publicField(['inspect', '--format', '{{range .Mounts}}{{if and (eq .Destination "/opt/local-db-trust/public.pem") (not .RW)}}{{.Source}}{{end}}{{end}}', 'dip-local-full-worker-1']);
  check(new RegExp('^' + root.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '/.local-stand/db-releases/[a-f0-9]{64}$').test(release), 'public-release-location');
  check(dbMount === join(release, 'db') && publicKey === join(root, '.local-stand/trust/db-signing-key.pub.pem'), 'public-mounts');
  check(publicField(['image', 'inspect', IMAGE, '--format', '{{.Id}}']) === IMAGE, 'pinned-image-present');
  const descriptor = JSON.parse(readFileSync(join(release, 'descriptor.json'), 'utf8'));
  const { preflightVulnDbBundle } = await import('../server/api/src/worker/vuln-db-bundle.ts');
  const { CURRENT_DB_POLICY, evaluateDbPolicy, operatorUsableUntil } = await import('../server/api/src/worker/cve-db-policy.mjs');
  const options = { directory: release, trustedPublicKeyPem: readFileSync(publicKey, 'utf8'),
    expectedSigner: 'local-db-operator-v1', expectedSource: descriptor.source, expectedSchemaVersion: 2,
    expectedArtifactSha256: descriptor.artifactSha256, expectedManifestDigest: descriptor.manifestDigest, policy: CURRENT_DB_POLICY };
  phase = 'public-db-verification';
  const verified = await preflightVulnDbBundle(options);
  evidence.db = verified.identity;
  evidence.dbTrustScope = 'current LOCAL public key; not production trust or publisher attestation';
  pass('public-db-signature-artifact-metadata-extracted-bytes');
  const { parseSecretFindings } = await import('../server/api/src/worker/secret-findings.ts');
  const { parseVulnFindings } = await import('../server/api/src/worker/vuln-findings.ts');
  const f = fixture();
  phase = 'native-version';
  nativeScan(f, 'version', undefined, evidence.containers);
  pass('native-trivy-version-0-69-3');
  const forbidden = [...f.secrets, f.marker];
  const noLeaks = (value: unknown, label: string) => {
    const text = typeof value === 'string' ? value : JSON.stringify(value);
    check(forbidden.every(s => !text.includes(s)), label);
  };
  evidence.fixture = { kind: 'generated Docker archive; inventory only, no installed executable application',
    os: f.osVersion, package: 'lodash@4.17.20', archiveSha256: f.archiveSha256,
    configDigest: f.configDigest, diffId: f.diffId, syntheticCredentialCount: f.secrets.length };
  phase = 'native-secrets';
  const secretRun = nativeScan(f, 'secret', undefined, evidence.containers);
  check(secretRun.exitCode === 0, 'native-secret-exit');
  const secretFindings = parseSecretFindings(secretRun.report);
  check(secretFindings.length === 2 && secretFindings.every(x => /^rule-[a-f0-9]{16}$/.test(x.ruleId) && x.line !== null), 'native-secret-positive-count');
  const rawSecrets = secretRun.report.Results.flatMap((r: any) => r.Secrets ?? []);
  check(rawSecrets.every((s: any) => s.RuleID === 'github-pat'), 'native-built-in-rule');
  check(secretRun.report.Results.some((r: any) => r.Target.includes(f.marker)), 'native-secret-location');
  noLeaks(secretFindings, 'normalized-secret-redaction');
  evidence.secretFindings = secretFindings;
  pass('native-built-in-github-pat-positive-and-normalized-redaction', { count: secretFindings.length,
    rawContainsCompleteSyntheticToken: f.secrets.some(s => JSON.stringify(secretRun.report).includes(s)) });

  phase = 'native-npm';
  const vulnRun = nativeScan(f, 'vuln', dbMount, evidence.containers);
  check(vulnRun.exitCode === 0, 'native-vuln-exit');
  check(vulnRun.report.Metadata.OS.Family === 'alpine' && vulnRun.report.Metadata.OS.EOSL !== true, 'native-supported-os');
  const npmRows = vulnRun.report.Results.filter((r: any) => r.Type === 'node-pkg').flatMap((r: any) => r.Vulnerabilities ?? []);
  check(npmRows.some((v: any) => v.PkgName === 'lodash' && v.InstalledVersion === '4.17.20' && v.VulnerabilityID === 'CVE-2021-23337'), 'native-npm-positive');
  pass('native-offline-npm-positive', { count: npmRows.length, cveIds: [...new Set(npmRows.map((v: any) => v.VulnerabilityID))].sort() });

  // Explicitly NOT a remote image identity or accepted archive receipt. The unchanged
  // parser must reject raw local bytes. Only this test projection supplies its fixed
  // ordinary parser identity; finding payloads are unmodified native scanner data.
  const digest = ('sha256:' + f.archiveSha256) as `sha256:${string}`;
  const image = `registry-1.docker.io/library/alpine@${digest}`;
  let rawRejected = false;
  try { parseVulnFindings(vulnRun.report, image, 'linux/amd64'); } catch { rawRejected = true; }
  check(rawRejected, 'local-report-not-remote-qualified');
  const projected = structuredClone(vulnRun.report);
  projected.ArtifactName = image;
  projected.Metadata.RepoDigests = [image];
  const findings = parseVulnFindings(projected, image, 'linux/amd64');
  check(findings.some(x => x.ecosystem === 'npm' && x.cveId === 'CVE-2021-23337'), 'normalized-native-npm-positive');
  noLeaks(findings, 'normalized-vuln-redaction');
    const nativePositive = findings.find(x => x.ecosystem === 'npm' && x.cveId === 'CVE-2021-23337')!;
    check(['ghsa', 'nvd'].every(source => nativePositive.advisory?.assessments.some(a => a.source === source && a.cvss?.family === 'v3')), 'native-ghsa-nvd-assessments');
    pass('native-ghsa-and-nvd-cvss-assessments-retained');
  pass('raw-local-identity-rejected-identity-only-projection-normalizes', { findingCount: findings.length,
    changedFields: ['ArtifactName', 'Metadata.RepoDigests'], fakeArchiveReceipt: false });
  evidence.nativeNpm = findings.filter(x => x.ecosystem === 'npm').map(x => ({ findingId: x.findingId, cveId: x.cveId,
    packageName: x.packageName, installedVersion: x.installedVersion, severity: x.severity, severitySources: x.severitySources,
    assessments: x.advisory?.assessments.map(a => ({ source: a.source, severity: a.severity, cvss: a.cvss })), conflicts: x.advisory?.conflicts }));
  const duplicates = structuredClone(projected);
  for (const result of duplicates.Results) if (result.Vulnerabilities) result.Vulnerabilities.push(...structuredClone(result.Vulnerabilities));
  check(same(parseVulnFindings(duplicates, image, 'linux/amd64'), findings), 'native-duplicate-idempotence');
  pass('duplicated-native-rows-normalize-identically');

  // A separately labelled adversarial derivative, not new scanner evidence:
  // preserve a second source assessment at the same location with a conflicting severity.
  const derivative = structuredClone(projected);
  const npmResult = derivative.Results.find((r: any) => r.Type === 'node-pkg');
  const original = npmResult.Vulnerabilities.find((v: any) => v.VulnerabilityID === 'CVE-2021-23337');
  const second = { ...structuredClone(original), DataSource: { ID: 'nvd' }, SeveritySource: 'nvd',
    Severity: original.Severity === 'LOW' ? 'HIGH' : 'LOW',
    Title: `source two token=${f.secrets[0]}`, Description: `source two secret=${f.secrets[1]}` };
  npmResult.Vulnerabilities.push(second);
  const conflictFindings = parseVulnFindings(derivative, image, 'linux/amd64');
  const conflict = conflictFindings.find(x => x.ecosystem === 'npm' && x.cveId === 'CVE-2021-23337')!;
  check(conflict.advisory?.assessments.some(a => a.source === original.SeveritySource && a.severity === original.Severity) &&
    conflict.advisory.assessments.some(a => a.source === 'nvd' && a.severity === second.Severity) &&
    conflict.advisory.conflicts.includes('severity') && conflict.advisory.limitations.includes('redaction'), 'both-source-assessments');
  noLeaks(conflictFindings, 'derivative-source-redaction');
  pass('adversarial-derivative-both-source-assessments-conflict-redaction', { native: false });

  phase = 'native-unavailable-and-eol';
  const missing = nativeScan(f, 'vuln', undefined, evidence.containers);
  check(missing.exitCode !== 0 && missing.report === null, 'missing-db-not-clean');
  pass('native-missing-db-nonzero-no-checked-report');
  const eolFixture = fixture('3.14.10');
  const eol = nativeScan(eolFixture, 'vuln', dbMount, evidence.containers);
  check(eol.exitCode === 0 && eol.report.Metadata.OS.EOSL === true, 'native-eol-signal');
  pass('native-eol-exit-zero-is-not-supported-coverage', { os: '3.14.10', EOSL: true,
    productionOutcomeNotExercised: 'unsupported/OS_EOL archive publication requires an exact accepted receipt' });
  const after = await preflightVulnDbBundle(options);
  check(same(after.identity, verified.identity), 'public-db-unchanged');
  const checkedAt = Date.now();
  const dbEvidence = { db: verified.identity, checkedAt, dbPolicy: evaluateDbPolicy(verified.identity, CURRENT_DB_POLICY, checkedAt) };
  evidence.actualDbPolicy = dbEvidence.dbPolicy;
  const staleClock = Date.parse(verified.identity.updatedAt) + 3 * 86400_000;
  check(evaluateDbPolicy(verified.identity, CURRENT_DB_POLICY, staleClock)?.status === 'stale-but-usable', 'stale-policy');
  let expired = false;
  try { evaluateDbPolicy(verified.identity, CURRENT_DB_POLICY, Date.parse(operatorUsableUntil(verified.identity)) + 1); } catch { expired = true; }
  check(expired, 'expired-policy');
  pass('same-real-db-stale-and-expired-clock-derivatives', { fixedClockTests: true, dbBytesModified: false });

  phase = 'temporary-http-sqlite-sinks';
  temporary = mkdtempSync(join(tmpdir(), 'task2-qualification-sinks-'));
  const ledgerPath = join(temporary, 'ledger.sqlite');
  process.env.SCAN_LEDGER_PATH = ledgerPath;
  process.env.AUTH_DB_PATH = join(temporary, 'auth.sqlite');
  process.env.AUTH_ORIGIN = 'http://127.0.0.1:8080';
  process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'true';
  process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS = 'true';
  const jwtSecret = randomBytes(32).toString('hex');
  process.env.SCAN_JWT_SECRET = jwtSecret;
  process.env.SCAN_JWT_ISSUER = 'task2-qualification';
  process.env.SCAN_JWT_AUDIENCE = 'scan-api';
  const { AppModule } = await import('../server/api/src/app.module.ts');
  const { LedgerStore } = await import('../server/api/src/ledger/ledger-store.ts');
  const open = async () => {
    app = await NestFactory.create(AppModule, { logger: false });
    await app.listen(0, '127.0.0.1');
    return { ledger: app.get(LedgerStore).ledger!, base: `http://127.0.0.1:${app.getHttpServer().address().port}/api/v1` };
  };
  let { ledger, base } = await open();
  const token = (subject: string) => {
    const now = Math.floor(Date.now() / 1000);
    const payload = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url') + '.' +
      Buffer.from(JSON.stringify({ iss: 'task2-qualification', aud: 'scan-api', sub: subject, iat: now - 1, exp: now + 120, scope: 'scan:create' })).toString('base64url');
    return payload + '.' + createHmac('sha256', jwtSecret).update(payload).digest('base64url');
  };
  const get = (path: string, subject?: string) => fetch(base + path, { headers: subject ? { authorization: 'Bearer ' + token(subject) } : {}, signal: AbortSignal.timeout(5000) });
  const cases = [{ name: 'native-derived', values: findings }, { name: 'adversarial-derivative', values: conflictFindings }];
  const records: any[] = [];
  for (const c of cases) {
    const target = { subject: 'task2-owner', idempotencyKey: c.name, registry: 'registry-1.docker.io', repository: 'library/alpine',
      digest, platform: 'linux/amd64', checks: '["secret","vuln"]', scope: 'image', cvePolicy: CURRENT_DB_POLICY };
    const id = ledger.enqueue(target).scanId;
    const job = ledger.claim()!;
    check(job.scanId === id, 'temporary-job');
    const outcomes: any = [{ check: 'secret', outcome: 'checked', findings: secretFindings, scannerVersion: '0.69.3' },
      { check: 'vuln', outcome: 'checked', image, findings: c.values, scannerVersion: '0.69.3', dbEvidence }];
    check(ledger.finishCombined(id, job.attempts, outcomes, undefined, job.leaseToken), 'temporary-publication');
    check(!ledger.finishCombined(id, job.attempts, outcomes, undefined, job.leaseToken), 'duplicate-publication');
    check(ledger.enqueue(target).scanId === id && ledger.pending().length === 0, 'idempotent-replay');
    records.push({ id, values: c.values });
  }
  const readSinks = async (stage: string) => {
    for (const { id, values } of records) {
      for (const suffix of ['', '/results', '/vuln', '/results?view=report-v1&limit=5', '/vuln?view=report-v1&limit=5']) {
        const path = '/scans/' + id + suffix;
        check((await get(path)).status === 401, 'anonymous-denied');
        check((await get(path, 'task2-other')).status === 404, 'foreign-owner-denied');
        const response = await get(path, 'task2-owner');
        check(response.status === 200, 'owner-http-read');
        const body: any = await response.json();
        noLeaks(body, 'http-redaction');
        if (suffix === '/results') check(same(body.findings, secretFindings) && body.coverage.outcome === 'checked', 'http-secret-evidence');
        if (suffix === '/vuln') check(same(body.findings, values) && body.outcome === 'checked' && body.findingCount > 0, 'http-source-preservation');
        if (!suffix) check(body.state === 'completed' && body.perCheck.secret.findingCount === 2 && body.perCheck.vuln.findingCount === values.length, 'http-positive-status');
        if (suffix.includes('view=')) check(body.findings.length > 0 && body.findings.every((f: any) => (suffix.startsWith('/results') ? secretFindings : values).some((v: any) => same(v, f))), 'report-view-preserves-evidence');
      }
      const events = await get('/scans/' + id + '/events', 'task2-owner');
      check(events.status === 200, 'sse-http');
      const text = await events.text();
      noLeaks(text, 'sse-redaction');
      check(text.includes('completed'), 'sse-terminal');
      check(ledger.events(id, 'task2-other', null) === undefined, 'foreign-events-denied');
    }
    pass('http-status-results-vuln-report-view-sse-owner-redaction-' + stage);
  };
  await readSinks('before-reopen');
  await app.close(); app = undefined;
  ({ ledger, base } = await open());
  await readSinks('after-reopen');
  // Read all tables and raw main/WAL/SHM bytes of OUR disposable store only.
  const inspectStore = (stage: string) => {
    const raw = new Database(ledgerPath);
    try {
      const tables = raw.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
      for (const { name } of tables) {
        check(/^[a-zA-Z0-9_]+$/.test(name), 'temporary-table-name');
        noLeaks(raw.prepare(`SELECT * FROM "${name}"`).all(), 'sqlite-table-redaction');
      }
      check(raw.pragma('integrity_check', { simple: true }) === 'ok' && raw.pragma('foreign_key_check').length === 0, 'sqlite-integrity');
    } finally { raw.close(); }
    for (const name of readdirSync(temporary!).filter(n => /^ledger\.sqlite(?:-wal|-shm)?$/.test(n))) {
      const bytes = readFileSync(join(temporary!, name));
      check(forbidden.every(s => !bytes.includes(Buffer.from(s))), 'sqlite-byte-redaction');
    }
    pass('all-temp-sqlite-tables-main-wal-shm-redaction-' + stage);
  };
  inspectStore('before-retention');
  const raw = new Database(ledgerPath);
  raw.prepare("UPDATE scans SET terminal_at=datetime('now','-40 days')").run();
  raw.close();
  check(ledger.prune(30) === 2, 'temp-retention-count');
  for (const { id } of records) check((await get('/scans/' + id, 'task2-owner')).status === 404, 'retained-result-removed');
  const retained = new Database(ledgerPath);
  for (const table of ['scans', 'outbox', 'scan_results', 'scan_findings', 'scan_vuln_results', 'scan_vuln_findings', 'scan_events', 'scan_cve_evidence', 'scan_cve_policy'])
    check(retained.prepare(`SELECT count(*) AS n FROM ${table}`).get().n === 0, 'retention-related-rows');
  retained.close();
  inspectStore('after-retention');
  await app.close(); app = undefined;
  ({ ledger, base } = await open());
  for (const { id } of records) check((await get('/scans/' + id, 'task2-owner')).status === 404, 'retention-reopen');
  pass('temp-retention-deletes-results-evidence-events-and-reopen-stays-absent');
  evidence.checkedIsNotSafe = { asserted: true, basis: 'checked reports retain positive Secrets and CVEs; not a clean/safe verdict',
    legacyStatusBooleanAbsent: true };
  noLeaks(evidence, 'evidence-redaction');
  evidence.success = true;
} catch (error) {
  // Only our static hyphenated assertion labels may leave the process; no raw errors.
  const label = error instanceof Error && /^[a-z][a-z0-9-]{1,80}$/.test(error.message) ? error.message : 'unclassified-safe-failure';
  evidence.failure = { phase, label, message: 'Qualification stopped; inspect the bounded phase in source, never raw scanner output.' };
  process.exitCode = 1;
} finally {
  if (app) await app.close();
  if (temporary) { rmSync(temporary, { recursive: true }); evidence.tempStoreRemoved = !existsSync(temporary); }
  evidence.sourcesAfter = sourceHashes();
  evidence.sourceDriftDuringRun = !same(evidence.sourcesBefore, evidence.sourcesAfter);
  evidence.finishedAt = new Date().toISOString();
  writeFileSync(evidencePath, JSON.stringify(evidence, null, 2) + '\n', { mode: 0o644 });
  console.log(JSON.stringify({ success: evidence.success, phase: evidence.failure?.phase, checks: evidence.checks.length,
    cleanup: evidence.containers.every((c: any) => c.cleanup), artifact: 'server/deploy/proof/task2-qualification-results.json' }));
}
