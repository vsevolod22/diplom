import 'reflect-metadata';
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { NestFactory } from '@nestjs/core';
import { NginxLocalModule } from './nginx-local.module.js';
import { ScansService } from '../scans/scans.service.js';
import { NginxLocalScansService } from './nginx-local-profile.js';
import { LedgerStore } from '../ledger/ledger-store.js';
import { NGINX_LOCAL_POLICY as p } from './nginx-local-policy.js';

const origin = 'http://127.0.0.1:8080';
const imageReference = `${p.registry}/${p.repository}@${p.digest}`;

// Disposable auth/ledger only. No LIVE state, worker, registry or CVE bundle.
test('TASK35 retry contract keeps fixed-window rollover, active accounting and browser headers', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'retry-http-'));
  const values = { AUTH_DB_PATH: join(directory, 'auth.sqlite'), SCAN_LEDGER_PATH: join(directory, 'ledger.sqlite'), AUTH_ORIGIN: origin,
    AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'false', SCAN_BROWSER_ALLOWED_USER_IDS: '' };
  const previous = Object.keys(values).map(key => process.env[key]); Object.assign(process.env, values);
  const app = await NestFactory.create(NginxLocalModule, { logger: false });
  try {
    const service = app.get(ScansService);
    let now = 100_000;
    let hold = false;
    const releases: Array<() => void> = [];
    Object.defineProperties(service, {
      eligibilityNow: { value: () => now },
      readiness: { value: async () => { if (hold) await new Promise<void>(resolve => releases.push(resolve)); return true; } },
      resolveTarget: { value: async () => p },
    });
    await app.listen(0, '127.0.0.1');
    const base = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}/api/v1`;
    const registered = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'retry@example.test', password: 'ordinary-long-password-123' }) });
    assert.equal(registered.status, 201);
    const cookie = registered.headers.get('set-cookie')!.split(';')[0];
    const { id } = await registered.json() as { id: string };
    process.env.SCAN_BROWSER_ALLOWED_USER_IDS = id;
    const identity = { subject: id, scope: ['scan:create'] };
    const body = { imageReference, checks: ['secret'] };
    const unsupported = { ...body, checks: ['config'] };
    const post = (data: unknown = body, suffix = '/images/eligibility', requestCookie = cookie, requestOrigin = origin) =>
      fetch(`${base}/browser/scans${suffix}`, { method: 'POST', headers: { cookie: requestCookie, origin: requestOrigin, 'content-type': 'application/json' }, body: JSON.stringify(data) });
    const unauthorized = await post(body, '/images/eligibility', '');
    assert.equal(unauthorized.status, 401); assert.equal((await unauthorized.json() as { errorCode: string }).errorCode, 'UNAUTHORIZED');
    assert.equal(unauthorized.headers.get('retry-after'), null);
    assert.equal((await post(body, '/images/eligibility', cookie, 'https://wrong.invalid')).status, 403);
    const check = async (response: Response, errorCode: string, limitReason: string | null, seconds: number) => {
      assert.equal(response.status, 429); assert.equal(response.headers.get('retry-after'), String(seconds));
      assert.equal(response.headers.get('cache-control'), 'no-store');
      assert.deepEqual(await response.json(), { errorCode, ...(limitReason ? { limitReason } : {}), retryAfterSeconds: seconds });
    };
    for (let count = 0; count < 30; count++) assert.equal((await post(unsupported)).status, 200);
    now += 59_001;
    await check(await post(unsupported), 'IMAGE_SEARCH_RATE_LIMITED', 'rate', 1);
    now = 160_000;
    assert.equal((await post(unsupported)).status, 200);
    hold = true;
    const first = service.eligibility(identity, body), second = service.eligibility(identity, body);
    assert.equal(releases.length, 2);
    await check(await post(), 'IMAGE_SEARCH_RATE_LIMITED', 'concurrency', 1);
    // Rollover during active work resets only count, never active counters.
    now += 60_000;
    await check(await post(), 'IMAGE_SEARCH_RATE_LIMITED', 'concurrency', 1);
    hold = false; releases.splice(0).forEach(release => release());
    await Promise.all([first, second]);
    assert.equal((await post()).status, 200);
    // Process-wide 8 remains intact, across distinct subjects.
    hold = true;
    const active = Array.from({ length: 8 }, (_, index) => service.eligibility({ ...identity, subject: `parallel-${index}` }, body));
    assert.equal(releases.length, 8);
    await check(await post(), 'IMAGE_SEARCH_RATE_LIMITED', 'concurrency', 1);
    hold = false; releases.splice(0).forEach(release => release()); await Promise.all(active);
    // Atomic scan admission and exact replay are unchanged; only the header is new.
    const intent = { ...body, scope: 'image', idempotencyKey: 'retry-admission-1' };
    assert.equal((await post(intent, '')).status, 202);
    assert.equal((await post({ ...intent, idempotencyKey: 'retry-admission-2' }, '')).status, 202);
    assert.equal((await post({ ...intent, idempotencyKey: 'retry-admission-3' }, '')).status, 202);
    await check(await post({ ...intent, idempotencyKey: 'retry-admission-4' }, ''), 'SCAN_CAPACITY', null, 60);
    assert.equal((await post(intent, '')).status, 202);
    // Fill the bounded subject map through public service calls, not weakened limits.
    for (let index = 0; index < 1015; index++) await service.eligibility({ ...identity, subject: `capacity-${index}` }, unsupported);
    assert.equal((await post()).status, 200);
    const another = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'capacity@example.test', password: 'ordinary-long-password-123' }) });
    assert.equal(another.status, 201);
    const anotherCookie = another.headers.get('set-cookie')!.split(';')[0];
    const anotherId = (await another.json() as { id: string }).id;
    process.env.SCAN_BROWSER_ALLOWED_USER_IDS += `,${anotherId}`;
    await check(await post(unsupported, '/images/eligibility', anotherCookie), 'IMAGE_SEARCH_CAPACITY', 'capacity', 60);
    now += 60_000;
    assert.equal((await post(unsupported, '/images/eligibility', anotherCookie)).status, 200);
  } finally {
    await app.close(); Object.keys(values).forEach((key, index) => { if (previous[index] === undefined) delete process.env[key]; else process.env[key] = previous[index]; });
    rmSync(directory, { recursive: true, force: true });
  }
});

test('real Nest cookie HTTP eligibility keeps auth/origin/media/readonly guards; policy before replay, current readiness, default closed', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'local-http-'));
  const values = { AUTH_DB_PATH: join(directory,'auth.sqlite'), SCAN_LEDGER_PATH: join(directory,'ledger.sqlite'), AUTH_ORIGIN: origin,
    AUTH_ALLOW_INSECURE_LOCAL_HTTP:'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS:'false', SCAN_BROWSER_ALLOWED_USER_IDS:'', SCAN_VULN_ENABLED:'true' };
  const previous = Object.keys(values).map(key => process.env[key]); Object.assign(process.env, values);
  const app = await NestFactory.create(NginxLocalModule, { logger:false });
  try {
    const service = app.get(ScansService), ledger = app.get(LedgerStore).ledger!;
    let ready = true, db = true, resolutions = 0;
    Object.defineProperties(service, { readiness:{ value:async()=>ready }, vulnDbReady:{ value:async()=>db }, resolveTarget:{ value:async()=>{resolutions++;return p;} } });
    assert.ok(service instanceof NginxLocalScansService);
    await app.listen(0,'127.0.0.1');
    const base = `http://127.0.0.1:${(app.getHttpServer().address() as {port:number}).port}/api/v1`;
    const register = async(email:string) => {
      const response = await fetch(`${base}/auth/register`, {method:'POST',headers:{origin,'content-type':'application/json'},body:JSON.stringify({email,password:'ordinary-long-password-123'})});
      assert.equal(response.status,201);
      return { cookie:response.headers.get('set-cookie')!.split(';')[0], id:(await response.json() as {id:string}).id };
    };
    const alice=await register('alice@example.test'), bob=await register('bob@example.test');
    process.env.SCAN_BROWSER_ALLOWED_USER_IDS=alice.id;
    const path=`${base}/browser/scans`;
    const body={imageReference,checks:['secret']};
    const post=(data:unknown=body, cookie=alice.cookie, requestOrigin=origin, media='application/json', suffix='/images/eligibility') => fetch(path+suffix,{method:'POST',headers:{cookie,origin:requestOrigin,'content-type':media},body:JSON.stringify(data)});
    assert.equal((await post(body,'')).status,401);
    assert.equal((await post(body,bob.cookie)).status,403);
    assert.equal((await post(body,alice.cookie,'https://wrong.invalid')).status,403);
    assert.equal((await post(body,alice.cookie,origin,'text/plain')).status,415);
    assert.equal((await post({...body,raw:'x'.repeat(1100)})).status,415);
    assert.equal((await post({...body,scannable:true})).status,400);
    const response=await post(); assert.equal(response.status,200); assert.equal(response.headers.get('cache-control'),'no-store');
    const eligible=await response.json() as {eligible:boolean;allowedCheckSets:unknown};
    assert.equal(eligible.eligible,true); assert.deepEqual(eligible.allowedCheckSets,p.allowedCheckSets);
    assert.equal(ledger.pending().length,0); assert.equal(resolutions,1);
    for(const image of [imageReference.replace('nginx','node'),imageReference.replace(p.digest,`sha256:${'a'.repeat(64)}`),'registry-1.docker.io/library/nginx:latest']) {
      const r=await post({...body,imageReference:image});assert.equal(r.status,200);assert.equal((await r.json() as {eligible:boolean}).eligible,false);
    }
    for(const checks of [['config'],['secret','sbom'],['sbom','vuln']]) {
      const r=await post({...body,checks});assert.equal(r.status,200);assert.equal((await r.json() as {eligible:boolean}).eligible,false);
    }
    assert.equal(resolutions,1); assert.equal(ledger.pending().length,0);
    const intent={...body,scope:'image',idempotencyKey:'local-http-intent'};
    const created=await post(intent,alice.cookie,origin,'application/json','');assert.equal(created.status,202);
    const receipt=await created.json() as {scanId:string};
    ready=false;db=false;
    const replay=await post(intent,alice.cookie,origin,'application/json','');assert.equal(replay.status,202);assert.deepEqual(await replay.json(),receipt);
    for(const checks of [['config'],['secret','sbom']]) assert.equal((await post({...intent,checks},alice.cookie,origin,'application/json','')).status,400);
    assert.equal((await post()).status,200);
    assert.equal((await (await post()).json() as {reason:string}).reason,'SCANNER_UNAVAILABLE');
    assert.equal((await post({...intent,idempotencyKey:'new-local-http'},alice.cookie,origin,'application/json','')).status,503);
    ready=true;
    assert.equal((await (await post({...body,checks:['vuln']})).json() as {reason:string}).reason,'DB_UNAVAILABLE');
    assert.equal((await (await post()).json() as {eligible:boolean}).eligible,true); // secret independent of DB
    process.env.SCAN_BROWSER_ALLOWED_USER_IDS=`${alice.id},${bob.id}`;
    assert.equal((await fetch(`${path}/${receipt.scanId}`,{headers:{cookie:bob.cookie}})).status,404);
    const defaultService=new ScansService(app.get(LedgerStore), {} as never);
    assert.equal((await defaultService.eligibility({subject:alice.id,scope:['scan:create']},body)).eligible,false);
    assert.equal(ledger.pending().length,1);
    await fetch(`${base}/auth/logout`,{method:'POST',headers:{cookie:alice.cookie,origin,'content-type':'application/json'},body:'{}'});
    assert.equal((await post()).status,401);
  } finally {
    await app.close(); Object.keys(values).forEach((key,index)=>{if(previous[index]===undefined)delete process.env[key];else process.env[key]=previous[index];});
    rmSync(directory,{recursive:true,force:true});
  }
});
