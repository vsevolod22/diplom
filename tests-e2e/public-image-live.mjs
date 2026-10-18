// Native modes require the separately approved isolated public stand genuinely
// running on 127.0.0.1:8081 with its native worker/DB. No automatic native execution.
// No server/Docker lifecycle, existing credentials/env/state, fixtures or HTTP mocks.
// Creates one retained new random account and at most one retained native scan.
// Credentials/reports remain in memory; stdout is an allowlist-only receipt.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const ORIGIN = 'http://127.0.0.1:8081';
const NODE = Object.freeze({ name: 'node', reference: 'registry-1.docker.io/library/node:22.14.0-alpine3.21',
  pinned: /^registry-1\.docker\.io\/library\/node@sha256:[a-f0-9]{64}$/, expectedOS: 'alpine' });
const DEBIAN = Object.freeze({ name: 'debian', reference: 'registry-1.docker.io/library/debian:bookworm-slim',
  pinned: /^registry-1\.docker\.io\/library\/debian@sha256:[a-f0-9]{64}$/, expectedOS: 'debian' });
const CHECKS = Object.freeze(['secret', 'sbom', 'vuln', 'config']);
const SCANS = '/api/v1/browser/scans';
const PROFILE = 'public-hub-amd64-v1', RESOURCES = 'public-hub-resources-v1';
const ARCHIVE_CHECKS = 'trivy-0.69.3-public-archive-v1';
const WORKER_MS = 660_000; // Up to 600s native attempt plus bounded queue/transport allowance.
const GLOBAL_MS = 900_000;
const terminal = new Set(['completed', 'partial', 'failed', 'cancelled']);
const outcomes = new Set(['checked', 'failed', 'unsupported', 'skipped', 'not_authorized']);
const reasons = new Set(['SCAN_FAILED', 'SCAN_TIMEOUT', 'SCAN_UNAVAILABLE', 'SCANNER_UNAVAILABLE', 'DB_UNAVAILABLE', 'OS_EOL', 'OS_UNKNOWN',
  'NODE_INVENTORY_UNKNOWN', 'NODE_INVENTORY_ABSENT', 'CHECK_DISABLED', 'USER_NOT_RESOLVABLE', 'OCI_IDENTITY_REJECTED', 'CONFIG_LIMIT_EXCEEDED', 'INVALID_CONFIG', 'UNSUPPORTED_SCAN']);
const file = fileURLToPath(import.meta.url), root = resolve(dirname(file), '..');
const apiRequire = createRequire(join(root, 'server/api/package.json'));
const proofEnvironment = source => Object.fromEntries(['PATH', 'HOME', 'TMPDIR', 'LANG', 'TZ', 'SystemRoot']
  .filter(key => source[key] !== undefined).map(key => [key, source[key]]));

function mode(args, internal = false) {
  if (args.length === 0) return 'not-run';
  if (args.length !== 1) throw new Error('Fixed proof accepts no configuration');
  if (args[0] === '--self-test') return 'offline';
  if (args[0] === '--run-native') return 'native';
  if (args[0] === '--run-native-debian') return 'native-debian';
  if (args[0] === '--native-child' && internal) return 'child';
  if (args[0] === '--native-debian-child' && internal) return 'child-debian';
  throw new Error('Unsupported argument');
}
function targetForMode(selected) {
  if (selected === 'native' || selected === 'child') return NODE;
  if (selected === 'native-debian' || selected === 'child-debian') return DEBIAN;
  throw new Error('No native target for this mode');
}
function childArgument(selected) {
  if (selected === 'native') return '--native-child';
  if (selected === 'native-debian') return '--native-debian-child';
  throw new Error('No child for this mode');
}
function fixedUrl(input) {
  try {
    const url = new URL(input);
    return input.startsWith(`${ORIGIN}/`) && url.origin === ORIGIN && url.protocol === 'http:' &&
      url.hostname === '127.0.0.1' && url.port === '8081' && !url.username && !url.password && !url.hash;
  } catch { return false; }
}
const sameChecks = value => Array.isArray(value) && isDeepStrictEqual(value, CHECKS);
function eligibilityReady(value, target) {
  return !!value && value.imageReference === target.reference && value.eligible === true && value.reason === 'READY' &&
    value.eligibility === 'public-hub-profile' && Array.isArray(value.allowedCheckSets) && value.allowedCheckSets.some(sameChecks);
}
function validIntent(value, target) {
  return !!value && typeof value === 'object' && Object.keys(value).sort().join(',') === 'checks,idempotencyKey,imageReference,scope' &&
    value.imageReference === target.reference && value.scope === 'image' && sameChecks(value.checks) &&
    typeof value.idempotencyKey === 'string' && /^[A-Za-z0-9_-]{8,128}$/.test(value.idempotencyKey);
}
function identifierPartition(rows) {
  const counts = { cve: 0, debianTemp: 0 };
  for (const row of rows) {
    if (/^CVE-[0-9]{4}-[0-9]{4,12}$/.test(row.cveId)) counts.cve++;
    else if (row.ecosystem === 'deb' && /^TEMP-[0-9]{7}-[A-F0-9]{6}$/.test(row.cveId) && !row.advisory?.references?.length) counts.debianTemp++;
    else throw new Error('Invalid public advisory partition');
  }
  return counts;
}
function safeOutcomes(snapshot) {
  return Object.fromEntries(CHECKS.map(check => {
    const item = snapshot?.perCheck?.[check];
    return [check, { outcome: outcomes.has(item?.outcome) ? item.outcome : 'missing',
      ...(reasons.has(item?.reason) ? { reason: item.reason } : {}),
      ...(Number.isSafeInteger(item?.findingCount) && item.findingCount >= 0 && item.findingCount <= 1000 ? { findingCount: item.findingCount } : {}),
      ...(Number.isSafeInteger(item?.componentCount) && item.componentCount >= 0 && item.componentCount <= 1000 ? { componentCount: item.componentCount } : {}) }];
  }));
}
function offlineGuards() {
  assert.equal(mode([]), 'not-run'); assert.equal(mode(['--self-test']), 'offline');
  for (const [arg, selected, target] of [['--run-native', 'native', NODE], ['--run-native-debian', 'native-debian', DEBIAN]]) {
    assert.equal(mode([arg]), selected); assert.equal(targetForMode(selected), target);
    const child = childArgument(selected);
    assert.throws(() => mode([child]));
    assert.equal(targetForMode(mode([child], true)), target);
  }
  assert.equal(NODE.reference, 'registry-1.docker.io/library/node:22.14.0-alpine3.21');
  assert.equal(DEBIAN.reference, 'registry-1.docker.io/library/debian:bookworm-slim');
  assert.equal(NODE.expectedOS, 'alpine'); assert.equal(DEBIAN.expectedOS, 'debian');
  assert.throws(() => targetForMode('offline')); assert.throws(() => targetForMode('ubuntu'));
  assert.throws(() => childArgument('child-debian'));
  for (const args of [['--url', ORIGIN], ['--origin=http://127.0.0.1:8080'], ['--email=old'], ['--password=old'], ['--target=alpine'],
    ['--native-child'], ['--native-debian-child'], ['--run-native', '--self-test'], ['--run-native', '--run-native-debian'],
    ['--run-native-debian', '--target=alpine'], ['--run-native-debian=registry-1.docker.io/library/ubuntu:latest']]) assert.throws(() => mode(args));
  assert.equal(fixedUrl(`${ORIGIN}/scans/new`), true);
  for (const url of ['http://127.0.0.1:8080/scans', 'http://localhost:8081/scans', 'https://127.0.0.1:8081/scans',
    'http://127.0.0.1:8081@evil.test/scans', 'http://user:password@127.0.0.1:8081/scans', `${ORIGIN}/scans#fragment`, 'http://[::1]:8081/scans']) assert.equal(fixedUrl(url), false);
  for (const [target, other] of [[NODE, DEBIAN], [DEBIAN, NODE]]) {
    const ready = { imageReference: target.reference, eligible: true, reason: 'READY', eligibility: 'public-hub-profile', allowedCheckSets: [CHECKS] };
    assert.equal(eligibilityReady(ready, target), true);
    assert.equal(eligibilityReady(ready, other), false);
    for (const change of [{ eligible: false }, { reason: 'OS_EOL' }, { imageReference: 'registry-1.docker.io/library/alpine:latest' }, { allowedCheckSets: [['secret', 'sbom']] }]) assert.equal(eligibilityReady({ ...ready, ...change }, target), false);
    const intent = { imageReference: target.reference, scope: 'image', checks: CHECKS, idempotencyKey: 'offline-only-not-posted' };
    assert.equal(validIntent(intent, target), true); assert.equal(validIntent(intent, other), false);
    for (const change of [{ imageReference: 'registry-1.docker.io/library/node:latest' }, { checks: ['secret', 'sbom'] }, { scope: 'host' }, { public: true }]) assert.equal(validIntent({ ...intent, ...change }, target), false);
    const pinned = `${target.reference.split(':')[0]}@sha256:${'a'.repeat(64)}`;
    assert.equal(target.pinned.test(pinned), true); assert.equal(other.pinned.test(pinned), false);
    assert.equal(target.pinned.test(target.reference), false);
    assert.equal(target.pinned.test(pinned.replace('registry-1.docker.io', 'evil.example')), false);
  }
  const hostileEnvironment = { PATH: '/offline-only', AUTH_ORIGIN: 'http://127.0.0.1:8080', ORIGIN: 'https://evil.example',
    REFERENCE: 'registry-1.docker.io/library/ubuntu:latest', TARGET: 'ubuntu', PUBLIC_IMAGE_TARGET: 'ubuntu',
    NODE_OPTIONS: '--import=unapproved', NODE_PATH: '/unapproved', EMAIL: 'old', PASSWORD: 'old', AUTH_DB_PATH: '/old-state' };
  assert.deepEqual(proofEnvironment(hostileEnvironment), { PATH: '/offline-only' });
  assert.equal(targetForMode(mode(['--run-native-debian'])), DEBIAN);
  assert.equal(targetForMode(mode(['--run-native'])), NODE);
  const advisoryRows = Array.from({ length: 241 }, (_, i) => ({ cveId: i < 236 ? `CVE-2026-${1000 + i}` : `TEMP-${1000000 + i}-ABCDEF`, ecosystem: 'deb' }));
  assert.deepEqual(identifierPartition(advisoryRows), { cve: 236, debianTemp: 5 });
  assert.deepEqual(identifierPartition(advisoryRows.slice(0, 158)), { cve: 158, debianTemp: 0 });
  assert.throws(() => identifierPartition([{ cveId: 'TEMP-1234567-ABCDEF', ecosystem: 'npm' }]));
  assert.throws(() => identifierPartition([{ cveId: 'GHSA-abcd-1234-5678', ecosystem: 'deb' }]));
  assert.throws(() => identifierPartition([{ cveId: 'TEMP-1234567-ABCDEF', ecosystem: 'deb', advisory: { references: ['invented'] } }]));
  console.log(JSON.stringify({ status: 'OFFLINE_GUARDS_ONLY', nativeExecution: false, nativeQualification: 'NOT_RUN',
    origin: ORIGIN, fixedReferences: [NODE.reference, DEBIAN.reference], networkRequests: 0, accountsCreated: 0,
    guards: ['two closed native modes and internal children', 'fixed 8081 only', 'no credential/target/env overrides', 'cross-mode eligibility/intent/pinned refusal', 'exact four checks', 'READY required', 'no fallback intent', '241 vulnerabilities = 236 CVE + 5 Debian TEMP; no invented links'] }));
}
async function bounded(operation, timeoutMs) {
  let timer;
  try { return await Promise.race([operation, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('bounded operation timeout')), timeoutMs); })]); }
  finally { clearTimeout(timer); }
}

async function nativeProof(target) {
  const REFERENCE = target.reference;
  // Only this explicit native branch imports Playwright or the read-only TS decoders.
  const { chromium, expect: baseExpect } = await import('@playwright/test');
  const expect = baseExpect.configure({ timeout: 15_000 });
  const source = path => pathToFileURL(join(root, path)).href;
  const decoder = await import(source('src/shared/api/scans/scanTransport.ts'));
  const { reportViewSearch } = await import(source('src/shared/api/scans/reportView.ts'));
  const { cveMetadataIdentity, validateCveMetadata } = await import(source('src/shared/api/scans/cveDbMetadata.ts'));
  const { z } = await import('zod');
  const imageProfile = z.strictObject({ version: z.literal(PROFILE), configDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
    resourcePolicyVersion: z.literal(RESOURCES), qualified: z.literal(false) });
  const account = { email: `public-native-${randomUUID()}@example.invalid`, password: randomBytes(40).toString('base64url') };
  const receipt = { status: 'NOT_QUALIFIED', scope: 'single fixed native image/API/UI proof only', wholeSystemQualification: false,
    nativeModeInvoked: true, nativeExecution: false, nativeWorkerEvidence: 'not-yet-verified', origin: ORIGIN, proofTarget: target.name, requestedReference: REFERENCE, requestedChecks: [...CHECKS],
    startedAt: new Date().toISOString(), scanLaunchRequests: 0, nativeAttemptMayExist: false, scanId: null,
    state: 'not-launched', outcomes: safeOutcomes(null), pageErrors: 0, blockedExternalRequests: 0, blockedMutations: 0,
    blockedUnrelatedEligibility: 0, accountMayExist: false,
    mockedHttp: false, injectedOciOrScanner: false, lifecycleOperations: 0, accountRetained: false, browserClosed: false };
  const contexts = [];
  let browser, phase = 'browser-launch', failureCode = 'GUARD_OR_BROWSER_FAILURE', ownerId, scanPath, pinned, profile, launchAt;
  let armed = false, armedSequence = 0, sequence = 0, pendingEligibility = Promise.resolve(false), pendingCreation = Promise.resolve(false), grant = null;
  let registrations = 0, logins = 0, stopped = false;
  let interrupt;
  const interrupted = new Promise((_, reject) => { interrupt = () => reject(new Error('native deadline or signal')); });
  const timer = setTimeout(() => { failureCode = 'GLOBAL_NATIVE_DEADLINE_NO_RELAUNCH'; interrupt(); }, GLOBAL_MS);
  const onSignal = () => { failureCode = 'INTERRUPTED_NO_STAND_LIFECYCLE'; interrupt(); };
  process.once('SIGTERM', onSignal); process.once('SIGINT', onSignal);
  const fail = code => { failureCode = code; throw new Error('native proof gate'); };
  const count = value => { assert.ok(Number.isSafeInteger(value) && value >= 0 && value <= 1000); return value; };
  const getPathAllowed = pathname => pathname === '/api/v1/auth/me' || pathname === SCANS ||
    (scanPath && [scanPath, `${scanPath}/events`, `${scanPath}/results`, `${scanPath}/sbom`, `${scanPath}/vuln`].includes(pathname));
  const newPage = async () => {
    const context = await browser.newContext({ viewport: { width: 1280, height: 1000 }, reducedMotion: 'reduce', serviceWorkers: 'block', acceptDownloads: false });
    contexts.push(context);
    await context.route('**/*', async route => {
      const request = route.request(), url = new URL(request.url()), method = request.method();
      if (stopped || !fixedUrl(request.url())) { receipt.blockedExternalRequests++; await route.abort(); return; }
      if (['GET', 'HEAD'].includes(method)) {
        if (!scanPath && receipt.scanLaunchRequests === 1 && url.pathname.startsWith(`${SCANS}/`)) await bounded(pendingCreation, 45_000).catch(() => false);
        if (!url.pathname.startsWith('/api/') || getPathAllowed(url.pathname)) { await route.continue(); return; }
        // Runtime/LLM/discovery are not part of this one-image proof; do not contact them.
        await route.abort(); return;
      }
      let body;
      try { body = request.postDataJSON(); } catch { /* Reject non-JSON mutations. */ }
      if (method === 'POST' && ['/api/v1/auth/register', '/api/v1/auth/login'].includes(url.pathname) &&
          body && Object.keys(body).sort().join(',') === 'email,password' && body.email === account.email && body.password === account.password) {
        if (url.pathname.endsWith('/register') && registrations++ === 0 || url.pathname.endsWith('/login') && logins++ === 0) {
          if (url.pathname.endsWith('/register')) receipt.accountMayExist = true;
          await route.continue(); return;
        }
      }
      if (method === 'POST' && url.pathname === `${SCANS}/images/eligibility` && body &&
          Object.keys(body).sort().join(',') === 'checks,imageReference' && body.imageReference === REFERENCE &&
          Array.isArray(body.checks) && body.checks.length > 0 && body.checks.every(check => CHECKS.includes(check))) {
        const requestSequence = ++sequence;
        grant = null;
        // Observe the genuine response after continuing the original request. No
        // fulfill(), response replacement, fetch patch or synthetic eligibility.
        pendingEligibility = (async () => {
          await route.continue();
          const response = await request.response();
          if (!response || response.status() !== 200) return false;
          const value = await response.json();
          if (!eligibilityReady(value, target) || !sameChecks(body.checks) || requestSequence !== sequence) return false;
          grant = { at: Date.now(), requestSequence }; return true;
        })().catch(() => false);
        await pendingEligibility; return;
      }
      if (method === 'POST' && url.pathname === `${SCANS}/images/eligibility`) {
        // The current create page may probe its saved nginx example. Block that
        // unrelated read instead of contacting another target or mocking a reply.
        receipt.blockedUnrelatedEligibility++; await route.abort(); return;
      }
      if (method === 'POST' && url.pathname === SCANS && armed && receipt.scanLaunchRequests === 0 && validIntent(body, target)) {
        await bounded(pendingEligibility, 35_000).catch(() => false);
        if (grant && grant.requestSequence > armedSequence && Date.now() - grant.at <= 30_000) {
          receipt.scanLaunchRequests++; receipt.nativeAttemptMayExist = true; armed = false;
          pendingCreation = (async () => {
            await route.continue();
            const response = await request.response();
            if (!response || response.status() !== 202) return false;
            const value = await response.json();
            if (typeof value.scanId !== 'string' || !/^[a-f0-9-]{36}$/.test(value.scanId)) return false;
            receipt.scanId = value.scanId; scanPath = `${SCANS}/${value.scanId}`; return true;
          })().catch(() => false);
          await pendingCreation; return;
        }
      }
      receipt.blockedMutations++; await route.abort();
    });
    await context.routeWebSocket('**/*', socket => { receipt.blockedExternalRequests++; socket.close(); });
    const page = await context.newPage();
    page.setDefaultTimeout(15_000); page.setDefaultNavigationTimeout(20_000);
    page.on('pageerror', () => { receipt.pageErrors++; });
    return { context, page };
  };
  const http = async (page, path, body) => {
    assert.ok(path.startsWith('/api/v1/') && fixedUrl(`${ORIGIN}${path}`));
    return page.evaluate(async ({ path, body }) => {
      const response = await fetch(path, { method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        signal: AbortSignal.timeout(body === undefined ? 15_000 : 35_000),
        ...(body === undefined ? {} : { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }) });
      const reader = response.body?.getReader(); const chunks = []; let bytes = 0;
      if (reader) while (true) { const part = await reader.read(); if (part.done) break; bytes += part.value.length;
        if (bytes > 2 * 1024 * 1024) { await reader.cancel(); return { status: response.status, value: null }; } chunks.push(part.value); }
      const all = new Uint8Array(bytes); let offset = 0; for (const chunk of chunks) { all.set(chunk, offset); offset += chunk.length; }
      let value = null; try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(all)); } catch { /* No raw error body leaves the page. */ }
      return { status: response.status, value };
    }, { path, body });
  };
  const waitResponse = (page, path, method, timeout = 45_000) => page.waitForResponse(response => response.url() === `${ORIGIN}${path}` && response.request().method() === method,
    { timeout }).catch(() => null);
  const auth = async (page, action) => {
    await page.goto(`${ORIGIN}/${action}`);
    await page.getByLabel('Email', { exact: true }).fill(account.email);
    await page.getByLabel('Пароль', { exact: true }).fill(account.password);
    const response = waitResponse(page, `/api/v1/auth/${action}`, 'POST');
    await page.getByRole('button', { name: action === 'register' ? 'Создать аккаунт' : 'Войти', exact: true }).click();
    const reply = await response; assert.equal(reply?.status(), action === 'register' ? 201 : 200);
    if (action === 'register') receipt.accountRetained = true;
    await expect(page.getByRole('heading', { name: 'Вы вошли', exact: true })).toBeVisible();
    const me = await http(page, '/api/v1/auth/me'); assert.equal(me.status, 200); assert.ok(me.value?.email === account.email && typeof me.value?.id === 'string');
    if (ownerId) assert.ok(me.value.id === ownerId); else ownerId = me.value.id;
    const cookie = (await page.context().cookies(ORIGIN)).find(item => item.name === 'demo_session');
    assert.ok(cookie?.httpOnly && cookie.sameSite === 'Lax');
  };
  const status = async page => {
    const reply = await http(page, scanPath); assert.equal(reply.status, 200);
    receipt.outcomes = safeOutcomes(reply.value); receipt.state = terminal.has(reply.value?.state) || ['queued', 'running'].includes(reply.value?.state) ? reply.value.state : 'invalid';
    const value = decoder.parseCurrentStatus(reply.value);
    assert.equal(value.scanId, receipt.scanId); assert.ok(sameChecks(value.checks));
    assert.match(value.imageReference, target.pinned); assert.equal(value.platform, 'linux/amd64'); assert.match(value.digest, /^sha256:[a-f0-9]{64}$/);
    assert.ok(value.imageReference.endsWith(`@${value.digest}`)); assert.equal(reply.value.profile, PROFILE);
    const actual = { image: value.imageReference, digest: value.digest, platform: value.platform };
    if (pinned) assert.ok(isDeepStrictEqual(actual, pinned)); else { pinned = actual; receipt.target = actual; }
    if (profile) assert.ok(isDeepStrictEqual(imageProfile.parse(reply.value.imageProfile), profile));
    return { value, wire: reply.value };
  };
  const verifyReports = async (page, snapshot) => {
    const query = { secret: { view: 'report-v1', limit: 50, sort: 'ruleId:asc' }, sbom: { view: 'report-v1', limit: 50, sort: 'name:asc' }, vuln: { view: 'report-v1', limit: 50, sort: 'severity:desc' } };
    const paths = { secret: 'results', sbom: 'sbom', vuln: 'vuln' };
    const parse = { secret: decoder.parseCurrentResults, sbom: decoder.parseCurrentSbom, vuln: decoder.parseCurrentVuln };
    const all = {}, baselines = {};
    assert.ok(snapshot.identifierCounts);
    assert.equal(snapshot.identifierCounts.cve + snapshot.identifierCounts.debianTemp, snapshot.perCheck.vuln.findingCount);
    for (const kind of ['secret', 'sbom', 'vuln']) {
      const expected = count(kind === 'sbom' ? snapshot.perCheck.sbom.componentCount : snapshot.perCheck[kind].findingCount);
      if (kind === 'sbom') assert.ok(expected > 0);
      const rows = [], ids = new Set(), cursors = new Set(); let cursor;
      for (let pageNumber = 0; pageNumber < 20; pageNumber++) {
        const response = await http(page, `${scanPath}/${paths[kind]}?${reportViewSearch(kind, query[kind], cursor)}`); assert.equal(response.status, 200);
        const value = parse[kind](response.value, query[kind], cursor);
        assert.equal(value.page.totalCount, expected); assert.equal(value.page.matchedCount, expected); assert.equal(value.page.offset, rows.length);
        if (kind === 'secret') {
          assert.equal(response.value.coverage.outcome, 'checked'); assert.equal(response.value.coverage.findingCount, expected);
          assert.equal(response.value.coverage.scannerVersion, snapshot.perCheck.secret.scannerVersion);
          assert.equal(response.value.coverage.checkedAt, snapshot.perCheck.secret.checkedAt);
        } else {
          assert.equal(value.outcome, 'checked'); assert.equal(value.profile, PROFILE);
          assert.equal(value.image, pinned.image); assert.equal(value.platform, pinned.platform);
          assert.equal(value.scannerVersion, snapshot.perCheck[kind].scannerVersion); assert.equal(value.checkedAt, snapshot.perCheck[kind].checkedAt);
          if (kind === 'sbom') assert.equal(value.os?.name, target.expectedOS);
          if (kind === 'vuln') {
            assert.equal(value.resultContractVersion, 2); assert.equal(value.os?.outcome, 'checked');
            assert.deepEqual(value.identifierCounts, snapshot.identifierCounts);
            assert.ok(validateCveMetadata(value)); assert.ok(validateCveMetadata(snapshot.perCheck.vuln));
            assert.equal(cveMetadataIdentity(value), cveMetadataIdentity(snapshot.perCheck.vuln));
            assert.ok(value.workerCheckedAt >= launchAt - 300_000 && value.dbPolicy.evaluatedAt <= Date.now() + 300_000);
            assert.ok(Date.parse(value.usableUntil) > Date.now());
            assert.ok(value.node?.outcome === 'checked' || value.node?.outcome === 'unsupported');
            if (value.node.outcome === 'unsupported') assert.equal(value.node.reason, 'NODE_INVENTORY_UNKNOWN');
            assert.deepEqual(value.node, snapshot.perCheck.vuln.node);
            assert.deepEqual(value.os, snapshot.perCheck.vuln.os);
          }
        }
        const identity = kind === 'secret' ? response.value.coverage : { profile: value.profile, image: value.image, platform: value.platform,
          scannerVersion: value.scannerVersion, checkedAt: value.checkedAt,
          ...(kind === 'sbom' ? { os: value.os } : { dbMetadata: cveMetadataIdentity(value), identifierCounts: value.identifierCounts }) };
        if (baselines[kind]) assert.ok(isDeepStrictEqual(identity, baselines[kind])); else baselines[kind] = identity;
        const entries = kind === 'sbom' ? value.components : value.findings;
        for (const row of entries) { const id = kind === 'sbom' ? JSON.stringify([row.ecosystem, row.name, row.version]) : row.findingId;
          assert.equal(ids.has(id), false); ids.add(id); rows.push(row); }
        if (value.nextCursor === null) break;
        assert.ok(typeof value.nextCursor === 'string' && !cursors.has(value.nextCursor)); cursors.add(value.nextCursor); cursor = value.nextCursor;
        if (pageNumber === 19) throw new Error('bounded report pagination exhausted');
      }
      assert.equal(rows.length, expected); all[kind] = rows;
    }
    const sbom = page.getByRole('region', { name: 'Пакеты SBOM', exact: true });
    await expect(sbom.getByRole('alert')).toHaveCount(0);
    await expect(sbom.locator('ul.scan-report-inventory > li')).toHaveCount(Math.min(25, all.sbom.length));
    for (const row of all.sbom.slice(0, 3)) await expect(sbom).toContainText(row.name);
    const cve = page.getByRole('region', { name: 'Результаты Уязвимости', exact: true });
    await expect(cve.getByRole('alert')).toHaveCount(0);
    await expect(cve.locator('ul.scan-vuln-list > li')).toHaveCount(Math.min(25, all.vuln.length));
    const partition = identifierPartition(all.vuln);
    assert.deepEqual(partition, snapshot.identifierCounts);
    await expect(cve).toContainText(`Весь сохранённый отчёт (до фильтров): ${partition.cve} CVE, ${partition.debianTemp} Debian advisories`);
    if (all.vuln.length === 0) await expect(cve).toContainText('0 уязвимостей в выполненной проверенной области');
    const secrets = page.getByRole('region', { name: 'Результаты Secrets', exact: true });
    await expect(secrets.getByRole('alert')).toHaveCount(0);
    await expect(secrets.locator('ul.scan-report-inventory > li')).toHaveCount(Math.min(25, all.secret.length));
    await expect(page.getByRole('heading', { name: 'Image config · только метаданные образа', exact: true })).toBeVisible();
    const npm = all.sbom.filter(row => row.ecosystem === 'npm');
    if (npm.length) {
      const select = sbom.getByLabel('Экосистема · SBOM');
      const filteredReply = page.waitForResponse(response => {
        const url = new URL(response.url());
        return fixedUrl(response.url()) && url.pathname === `${scanPath}/sbom` && url.searchParams.get('view') === 'report-v1' && url.searchParams.get('ecosystem') === 'npm';
      }).catch(() => null);
      await select.selectOption('npm');
      const filtered = await filteredReply; assert.equal(filtered?.status(), 200);
      const npmPage = decoder.parseCurrentSbom(await filtered.json(), { view: 'report-v1', limit: 25, sort: 'name:asc', ecosystem: 'npm' });
      assert.equal(npmPage.profile, PROFILE); assert.equal(npmPage.image, pinned.image);
      assert.equal(npmPage.page.totalCount, all.sbom.length); assert.equal(npmPage.page.matchedCount, npm.length);
      await expect(sbom.locator('ul.scan-report-inventory > li')).toHaveCount(Math.min(25, npm.length));
      for (const row of npm.slice(0, 3)) await expect(sbom).toContainText(row.name);
      await select.selectOption(''); await expect(sbom.locator('ul.scan-report-inventory > li')).toHaveCount(Math.min(25, all.sbom.length));
    }
    receipt.inventory = { componentCount: all.sbom.length, os: baselines.sbom.os,
      npmComponentsReported: npm.length, npmEvidence: npm.length ? 'present-in-accepted-sbom' : 'not-reported-not-proof-of-absence',
            nodeCoverage: snapshot.perCheck.vuln.node };
    receipt.counts = { secrets: all.secret.length, sbom: all.sbom.length, vulnTotal: all.vuln.length,
          cve: partition.cve, debianTemp: partition.debianTemp, config: snapshot.config.findings.length };
    const db = snapshot.perCheck.vuln.db;
    receipt.db = { resultContractVersion: snapshot.perCheck.vuln.resultContractVersion, signer: db.signer, source: db.source, schemaVersion: db.schemaVersion,
      manifestDigest: db.manifestDigest, artifactSha256: db.artifactSha256, metadataSha256: db.metadataSha256, dbSha256: db.dbSha256,
      updatedAt: db.updatedAt, downloadedAt: db.downloadedAt, nextUpdate: db.nextUpdate,
      policy: snapshot.perCheck.vuln.dbPolicy, usableUntil: snapshot.perCheck.vuln.usableUntil, workerCheckedAt: snapshot.perCheck.vuln.workerCheckedAt,
      node: snapshot.perCheck.vuln.node };
    return { baselines, rows: all };
  };
  try {
    await Promise.race([interrupted, (async () => {
      browser = await chromium.launch({ headless: true, timeout: 20_000, args: ['--disable-background-networking', '--disable-component-update', '--disable-default-apps',
        '--no-first-run', '--no-proxy-server', '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1'] });
      phase = 'new-account-ui-registration'; failureCode = 'STAND_OR_UI_UNAVAILABLE_NO_FALLBACK';
      const first = await newPage(); await auth(first.page, 'register');
      failureCode = 'GUARD_OR_BROWSER_FAILURE'; phase = 'manual-fixed-reference-and-genuine-eligibility';
      await first.page.goto(`${ORIGIN}/scans/new`);
      await first.page.getByRole('textbox', { name: 'Canonical reference Docker Hub' }).fill(REFERENCE);
      const eligible = await http(first.page, `${SCANS}/images/eligibility`, { imageReference: REFERENCE, checks: CHECKS });
      if (eligible.status !== 200 || !eligibilityReady(eligible.value, target)) { receipt.eligibility = { httpStatus: eligible.status,
        ...(reasons.has(eligible.value?.reason) ? { reason: eligible.value.reason } : {}) }; fail('ELIGIBILITY_NOT_READY_NO_SCAN'); }
      for (const label of [/Secrets · проверка образа/, /SBOM · перечень пакетов/, /CVE · доступно только/, /Image config · OCI User metadata/])
        await first.page.getByRole('checkbox', { name: label }).check();
      assert.ok(sameChecks(await first.page.locator('input[name="checks"]:checked').evaluateAll(inputs => inputs.map(input => input.value))));
      const consent = first.page.getByRole('checkbox', { name: /Подтверждаю выбранную цель и область/ });
      const submit = first.page.getByRole('button', { name: 'Запустить скан', exact: true });
      await expect(consent).not.toBeChecked(); await expect(submit).toBeDisabled(); await consent.check(); await expect(submit).toBeEnabled();
      phase = 'fresh-ui-preflight-and-one-native-post'; armedSequence = sequence; armed = true; launchAt = Date.now();
      const created = waitResponse(first.page, SCANS, 'POST'); await submit.click(); const response = await created;
      if (!response || response.status() !== 202) fail('LAUNCH_UNCONFIRMED_NO_RETRY');
      const body = await response.json(); assert.match(body.scanId, /^[a-f0-9-]{36}$/); receipt.scanId = body.scanId; scanPath = `${SCANS}/${body.scanId}`;
      await expect(first.page).toHaveURL(`${ORIGIN}/scans/${body.scanId}`);
      phase = 'native-worker-terminal-status'; const deadline = Date.now() + WORKER_MS; let completed;
      do {
        completed = await status(first.page);
        if (terminal.has(completed.value.state)) break;
        await new Promise(resolvePause => setTimeout(resolvePause, Math.min(2000, Math.max(0, deadline - Date.now()))));
      } while (Date.now() < deadline);
      if (!terminal.has(completed.value.state)) fail('NATIVE_WORKER_TIMEOUT_NO_RELAUNCH');
      if (completed.value.state !== 'completed' || CHECKS.some(check => completed.value.perCheck?.[check]?.outcome !== 'checked')) fail('REQUIRED_CHECK_NOT_CHECKED_NO_QUALIFICATION');
      profile = imageProfile.parse(completed.wire.imageProfile); assert.equal(completed.wire.executedQualification, undefined);
      for (const check of ['secret', 'sbom', 'vuln']) { assert.equal(completed.value.perCheck[check].scannerVersion, '0.69.3'); assert.equal(completed.value.perCheck[check].checksVersion, ARCHIVE_CHECKS); }
      assert.equal(completed.value.perCheck.vuln.os?.outcome, 'checked');
      assert.equal(completed.value.config.config.outcome, 'checked'); assert.deepEqual(completed.value.config.completedRuleIds, ['IMGCFG_USER_ROOT']);
      for (const finding of completed.value.config.findings) { assert.equal(finding.manifestDigest, pinned.digest); assert.equal(finding.configDigest, profile.configDigest); }
      receipt.imageProfile = profile;
      phase = 'strict-native-report-db-count-and-ui-verification'; const initial = await verifyReports(first.page, completed.value);
      receipt.nativeExecution = true; receipt.nativeWorkerEvidence = 'checked-report-and-db-evidence-observed';
      phase = 'reload-durable-evidence'; await first.page.reload(); const reloaded = await status(first.page);
      assert.ok(isDeepStrictEqual(reloaded.value, completed.value));
      assert.ok(isDeepStrictEqual(await verifyReports(first.page, reloaded.value), initial));
      phase = 'fresh-context-anonymous-then-own-login'; await first.context.close(); const fresh = await newPage();
      await fresh.page.goto(`${ORIGIN}/login`); assert.equal((await http(fresh.page, scanPath)).status, 401);
      await auth(fresh.page, 'login'); await fresh.page.goto(`${ORIGIN}/scans/${receipt.scanId}`);
      const persisted = await status(fresh.page); assert.ok(isDeepStrictEqual(persisted.value, completed.value));
      assert.ok(isDeepStrictEqual(await verifyReports(fresh.page, persisted.value), initial));
      assert.equal(receipt.scanLaunchRequests, 1); assert.equal(receipt.pageErrors, 0); assert.equal(receipt.blockedExternalRequests, 0); assert.equal(receipt.blockedMutations, 0);
      receipt.status = 'PASS_SINGLE_NATIVE_TARGET'; // Never means whole-system/deployment qualification.
    })()]);
  } catch {
    receipt.status = 'NOT_QUALIFIED'; receipt.failure = { phase, code: failureCode };
  } finally {
    stopped = true; armed = false; clearTimeout(timer); process.removeListener('SIGTERM', onSignal); process.removeListener('SIGINT', onSignal);
    try {
      await bounded(Promise.allSettled(contexts.map(context => context.close())), 8000);
      if (browser) { await bounded(browser.close(), 8000); assert.equal(browser.isConnected(), false); }
      receipt.browserClosed = true;
    } catch { receipt.status = 'NOT_QUALIFIED'; receipt.failure = { phase: 'own-browser-cleanup', code: 'CLEANUP_FAILED' }; }
    if (receipt.pageErrors || receipt.blockedExternalRequests || receipt.blockedMutations) {
      receipt.status = 'NOT_QUALIFIED'; receipt.failure ??= { phase: 'browser-safety', code: 'BROWSER_SAFETY_GUARD' };
    }
    receipt.finishedAt = new Date().toISOString();
    console.log(JSON.stringify(receipt, null, 2));
  }
  return receipt.status === 'PASS_SINGLE_NATIVE_TARGET';
}

let selected;
try { selected = mode(process.argv.slice(2), typeof process.send === 'function' && process.connected); }
catch { console.error(JSON.stringify({ status: 'REFUSED_ARGUMENTS', nativeExecution: false, origin: ORIGIN, nativeQualification: 'NOT_RUN' })); process.exitCode = 2; }
if (selected === 'offline') offlineGuards();
else if (selected === 'not-run') {
  console.log(JSON.stringify({ status: 'NOT_RUN', nativeExecution: false, nativeQualification: 'NOT_RUN', origin: ORIGIN,
    nextCommandAfterApproved8081StandIsReady: 'node tests-e2e/public-image-live.mjs --run-native',
        additionalCompiledDebianCommand: 'node tests-e2e/public-image-live.mjs --run-native-debian',
    warning: 'Creates one new random account and at most one retained native scan; never starts or changes Docker/stand lifecycle.' }));
  process.exitCode = 2;
} else if (selected === 'child' || selected === 'child-debian') {
  try { process.exitCode = await nativeProof(targetForMode(selected)) ? 0 : 1; }
  catch { console.error(JSON.stringify({ status: 'NOT_QUALIFIED', nativeExecution: false, phase: 'native-bootstrap', rawDiagnosticsSuppressed: true, wholeSystemQualification: false })); process.exitCode = 1; }
  finally { if (process.connected) process.disconnect(); }
} else if (selected === 'native' || selected === 'native-debian') {
  // Minimal environment, isolated Playwright profile, and read-only TS decoders.
  // No old credentials/env files, server fixtures, Docker command or lifecycle helper.
  const child = spawn(process.execPath, ['--import', apiRequire.resolve('tsx/esm'), file, childArgument(selected)], {
    cwd: join(root, 'server/api'), env: proofEnvironment(process.env), stdio: ['ignore', 'inherit', 'inherit', 'ipc'], detached: true,
  });
  const killOwnedGroup = () => { if (child.pid) { try { process.kill(-child.pid, 'SIGKILL'); } catch { /* Only this proof's child group. */ } } };
  let hardStop;
  const terminate = () => { child.kill('SIGTERM'); hardStop ??= setTimeout(killOwnedGroup, 25_000); };
  const deadline = setTimeout(terminate, GLOBAL_MS + 30_000);
  process.once('SIGTERM', terminate); process.once('SIGINT', terminate);
  try { const [code] = await once(child, 'close'); process.exitCode = code ?? 1; if (code !== 0) killOwnedGroup(); }
  finally { clearTimeout(deadline); clearTimeout(hardStop); process.removeListener('SIGTERM', terminate); process.removeListener('SIGINT', terminate); }
}
