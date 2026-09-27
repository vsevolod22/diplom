import { Module } from '@nestjs/common';
import { SecurityModule } from '../security/security.module.js';
import { OciModule } from '../oci/oci.module.js';
import { LedgerModule } from '../ledger/ledger.module.js';
import { ScansController } from './scans.controller.js';
import { ScansService } from './scans.service.js';

@Module({ imports: [SecurityModule, OciModule, LedgerModule], controllers: [ScansController], providers: [ScansService] })
export class ScansModule {}
