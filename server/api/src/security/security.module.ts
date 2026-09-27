import { Module } from '@nestjs/common';
import { ScanAuthGuard } from './scan-auth.guard.js';
import { LedgerModule } from '../ledger/ledger.module.js';

@Module({ imports: [LedgerModule], providers: [ScanAuthGuard], exports: [ScanAuthGuard] })
export class SecurityModule {}
