import { Module } from '@nestjs/common';
import { SecurityModule } from '../security/security.module.js';
import { OciModule } from '../oci/oci.module.js';
import { LedgerModule } from '../ledger/ledger.module.js';
import { ScansController } from './scans.controller.js';
import { ScansService } from './scans.service.js';
import { BrowserScansController } from './browser-scans.controller.js';
import { AuthModule } from '../auth/auth.module.js';

@Module({ imports: [SecurityModule, OciModule, LedgerModule, AuthModule], controllers: [ScansController, BrowserScansController], providers: [ScansService], exports: [ScansService] })
export class ScansModule {}
