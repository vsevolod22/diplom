import 'reflect-metadata';
import assert from 'node:assert/strict';
import { lstatSync, readSync } from 'node:fs';
import { NestFactory, ModulesContainer } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { AuthStore } from '../../auth/auth.store.js';
import { AuthController } from '../../auth/auth.controller.js';
import { ScansService } from '../../scans/scans.service.js';
import { ScansController } from '../../scans/scans.controller.js';
import { BrowserScansController } from '../../scans/browser-scans.controller.js';
import { NginxLocalModule } from '../../oci/nginx-local.module.js';
import { NginxLocalScansService } from '../../oci/nginx-local-profile.js';
import { configureParentIngress } from '../../parent-ingress.js';
import { RuntimeApiModule } from '../../runtime/runtime-api.module.js';
import { BrowserRuntimeController } from '../../runtime/browser-runtime.controller.js';
import { RuntimeApiService } from '../../runtime/runtime-api.service.js';
import { RuntimeIdentity } from '../../runtime/browser-runtime-identity.js';
import { LlmRuntime, LlmService } from '../llm.service.js';
import { LlmController } from '../llm.controller.js';
import { LlmQuotaRuntime } from '../quota-runtime.js';
import { fixtureEnvironment, quotaAbsent, qualify, replayPolicy, validateState, type FixtureState } from './history-wire-native.seed.js';

// Only finite public receipts leave stdout. Nest logging and raw exceptions are disabled.
function emit(value: object) {
  const line = JSON.stringify(value); assert(Buffer.byteLength(line) <= 4096); process.stdout.write(line + '\n');
}
function input() {
  const parts: Buffer[] = []; let size = 0;
  while (true) {
    const part = Buffer.alloc(4096), n = readSync(0, part, 0, part.length, null);
    if (!n) break; size += n; assert(size <= 65536); parts.push(part.subarray(0, n));
  }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(parts)));
}
let app: NestExpressApplication | undefined;
let providerLookups = 0, providerFault = false, stopping = false;
try {
  process.umask(0o077); assert.equal(process.argv.length, 3);
  const phase = process.argv[2]; assert(phase === 'disabled' || phase === 'replay');
  fixtureEnvironment();
  assert.equal(process.env.SCAN_JWT_SECRET, 'history-wire-public-fixture-jwt-not-production-v1');
  assert(Buffer.byteLength(process.env.SCAN_JWT_SECRET!) >= 32);
  assert.equal(process.env.SCAN_JWT_ISSUER, 'history-wire-fixture');
  assert.equal(process.env.SCAN_JWT_AUDIENCE, 'history-wire-fixture');
  assert.equal(process.env.SCAN_BIND_ADDRESS, '0.0.0.0'); assert.equal(process.env.PORT, '3001');
  const spec = input(); assert.deepEqual(Object.keys(spec).sort(), ['files', 'fixtures', 'state']);
  const state: FixtureState = spec.state; validateState(state); qualify(spec.files, spec.fixtures, true);
  assert.equal(process.env.SCAN_BROWSER_ALLOWED_USER_IDS, state.owner + ',' + state.foreign);
  app = await NestFactory.create<NestExpressApplication>(NginxLocalModule, { logger: false, bodyParser: false });
  const modules = app.get(ModulesContainer);
  const singleton = (token: unknown, controller = false) => {
    const matches = [...modules.values()].flatMap(m => [...(controller ? m.controllers : m.providers).values()])
      .filter(p => p.token === token && p.instance !== undefined);
    assert.equal(matches.length, 1); return matches[0].instance;
  };
  assert(singleton(AuthStore) instanceof AuthStore);
  assert(singleton(ScansService) instanceof NginxLocalScansService);
  const runtimeModule = [...modules.values()].filter(m => m.metatype === RuntimeApiModule); assert.equal(runtimeModule.length, 1);
  const selected = app.select(RuntimeApiModule);
  assert.equal(singleton(RuntimeIdentity), selected.get(RuntimeIdentity, { strict: true }));
  const runtimeApi = singleton(RuntimeApiService) as RuntimeApiService;
  assert.equal(runtimeApi, selected.get(RuntimeApiService, { strict: true }));
  assert.equal(runtimeApi.store, undefined); assert.equal(runtimeApi.live, undefined);
  for (const controller of [AuthController, ScansController, BrowserScansController, LlmController, BrowserRuntimeController]) singleton(controller, true);
  const runtime = singleton(LlmRuntime) as LlmRuntime;
  assert.equal(runtime.policy(), null);
  // This is an explicitly synthetic bootstrap seam, not process.env/operator activation.
  if (phase === 'replay') {
    const policy = replayPolicy(); Object.defineProperty(runtime, 'policy', { value: () => policy, writable: false });
  }
  Object.defineProperty(runtime, 'provider', { value: () => {
    providerLookups++; providerFault = true; throw new Error('fixture-provider-tripwire');
  }, writable: false });
  assert(singleton(LlmQuotaRuntime) instanceof LlmQuotaRuntime);
  configureParentIngress(app);
  assert.equal(runtimeApi.capabilities().rawIntake, 'authenticated-pre-json');
  const store = (singleton(LlmService) as LlmService).history().runtime.store();
  assert.equal(store.incarnation, state.incarnation);
  const historyFile = lstatSync('/auth/llm-history.sqlite');
  assert.equal(historyFile.ino, state.historyInode); assert.equal(historyFile.dev, state.historyDevice);
  assert.equal(historyFile.mode & 0o7777, 0o600); assert.equal(historyFile.gid, 65532);
  const head = store.snapshot(state.owner, state.scanId);
  assert.equal(head.epoch, state.epoch); assert.equal(head.revision, phase === 'disabled' ? 2 : 3);
  assert.equal(head.pending, null); assert.equal(head.turns.length, 1);
  // Read the actual writer connection's pragma, not a fresh readonly connection's default.
  assert.equal(Reflect.get(store, 'db').pragma('synchronous', { simple: true }), 2);
  quotaAbsent();
  const stop = async () => {
    if (stopping) return; stopping = true;
    try {
      await app!.close(); quotaAbsent(); assert.equal(providerLookups, 0); assert.equal(providerFault, false);
      emit({ kind: 'history-wire-api-final', phase, closed: true, providerLookups, providerFault, quotaAbsent: true });
      process.exitCode = 0;
    } catch {
      emit({ kind: 'history-wire-api-refusal', phase, passed: false }); process.exitCode = 1;
    }
  };
  process.once('SIGTERM', () => { void stop(); }); process.once('SIGINT', () => { void stop(); });
  await app.listen(3001, '0.0.0.0');
  emit({ kind: 'history-wire-api-ready', phase, localSingleton: true, authSingleton: true, runtimeSingleton: true,
    controllersUnique: true, runtimeStoreAbsent: true, runtimeLiveAbsent: true, rawIntakeConfigured: true,
    embeddedSourceQualified: true, mountedFixtureBytesQualified: true, fullSynchronous: true, providerLookups, providerFault, quotaAbsent: true,
    unchangedProductionMainExecuted: false, syntheticReplayPolicy: phase === 'replay' });
} catch {
  if (app) { try { await app.close(); } catch { /* Refusal remains primary. */ } }
  emit({ kind: 'history-wire-api-refusal', passed: false }); process.exitCode = 1;
}
