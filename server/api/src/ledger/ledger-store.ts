import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { ScanLedger } from './ledger.js';

@Injectable()
export class LedgerStore implements OnModuleDestroy {
  private readonly handle: ScanLedger | undefined;

  constructor() {
    // A missing durable volume must never silently become an in-memory ledger.
    if (process.env.SCAN_LEDGER_PATH) this.handle = new ScanLedger(process.env.SCAN_LEDGER_PATH);
  }

  get ledger(): ScanLedger | undefined { return this.handle; }
  onModuleDestroy(): void { this.handle?.close(); }
}
