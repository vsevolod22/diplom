import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module.js';
import { LedgerModule } from '../ledger/ledger.module.js';
import { LedgerStore } from '../ledger/ledger-store.js';
import { SecurityModule } from '../security/security.module.js';
import { OciModule } from './oci.module.js';
import { OciResolver } from './oci-resolver.js';
import { ScansController } from '../scans/scans.controller.js';
import { BrowserScansController } from '../scans/browser-scans.controller.js';
import { ScansService } from '../scans/scans.service.js';
import { NginxLocalScansService } from './nginx-local-profile.js';

@Module({ imports: [AuthModule, LedgerModule, SecurityModule, OciModule],
  controllers: [ScansController, BrowserScansController],
  providers: [{ provide: ScansService, inject: [LedgerStore, OciResolver],
    useFactory: (ledger: LedgerStore, resolver: OciResolver) => new NginxLocalScansService(ledger, resolver) }] })
export class NginxLocalModule {}
