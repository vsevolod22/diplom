import 'reflect-metadata';
import { Module } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { AuthModule } from '../auth/auth.module.js';
import { AuthStore } from '../auth/auth.store.js';
import { LedgerModule } from '../ledger/ledger.module.js';
import { LedgerStore } from '../ledger/ledger-store.js';
import { OciModule } from './oci.module.js';
import { OciResolver } from './oci-resolver.js';
import { BrowserScansController } from '../scans/browser-scans.controller.js';
import { ScansService } from '../scans/scans.service.js';
import { NginxProofScansService } from './nginx-proof-profile.js';

// A separate composition, never selected by a flag in the production AppModule.
// The proof harness owns fresh auth/ledger volumes and its random JWT. Only its
// loopback ingress exposes this listener; production guards and controllers stay intact.
@Module({ imports: [AuthModule, LedgerModule, OciModule], controllers: [BrowserScansController],
  providers: [{ provide: ScansService, inject: [LedgerStore, OciResolver],
    useFactory: (ledger: LedgerStore, resolver: OciResolver) => new NginxProofScansService(ledger, resolver) }] })
class ProofModule {}

if (process.env.AUTH_ORIGIN !== 'http://127.0.0.1:18080' || process.env.AUTH_DB_PATH !== '/auth/auth.sqlite' ||
    process.env.SCAN_LEDGER_PATH !== '/data/ledger.sqlite' || process.env.SCAN_JWT_ISSUER !== 'dip-nginx-disposable-proof' ||
    process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS !== 'false') throw new Error('Isolated proof composition required');
const credentials = JSON.parse(await readFile('/proof/credentials.json', 'utf8')) as { email: string; password: string }[];
if (credentials.length !== 2 || credentials.some(user => !/^proof-[a-f0-9]+@qualification.invalid$/.test(user.email) || user.password.length < 32))
  throw new Error('Invalid proof accounts');
process.env.SCAN_JWT_SECRET = randomBytes(32).toString('hex');
const app = await NestFactory.create(ProofModule, { logger: false });
const auth = app.get(AuthStore);
const ids: string[] = [];
for (const user of credentials) {
  const created = await auth.register(user.email, user.password);
  if (!created) throw new Error('Fresh isolated auth volume required');
  ids.push(created.id);
}
process.env.SCAN_BROWSER_ALLOWED_USER_IDS = ids.join(',');
await app.listen(3001, '0.0.0.0');
const stop = async () => { await app.close(); process.exit(0); };
process.on('SIGTERM', () => { void stop(); });
process.on('SIGINT', () => { void stop(); });
// No readiness stub: admission uses the actual worker marker, gateway and direct-egress probe.
