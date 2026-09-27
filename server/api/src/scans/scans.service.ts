import { BadRequestException, ConflictException, Inject, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { LedgerStore } from '../ledger/ledger-store.js';
import { OciResolver } from '../oci/oci-resolver.js';
import { parseScanRequest } from './scan-request.js';
import type { Identity } from '../security/identity.js';

@Injectable()
export class ScansService {
  constructor(
    @Inject(LedgerStore) private readonly ledgerStore: LedgerStore,
    @Inject(OciResolver) private readonly resolver: OciResolver,
  ) {}

  create(identity: Identity, body: unknown): never {
    // The production gateway and worker readiness are not proven. Even a duplicate
    // request must not be reported as accepted while the execution chain is absent.
    void this.resolver;
    void this.ledgerStore;
    void identity;
    void body;
    throw new ServiceUnavailableException({ errorCode: 'SCANNER_UNAVAILABLE' });
  }

  // Kept separate so tests can verify replay is subject-bound and checked before
  // any mutable tag lookup. Not used by the HTTP endpoint until readiness is proven.
  findReplay(identity: Identity, body: unknown, allowedRegistries: ReadonlySet<string>): string | undefined {
    let request;
    try { request = parseScanRequest(body, allowedRegistries); }
    catch { throw new BadRequestException({ errorCode: 'INVALID_SCAN_REQUEST' }); }
    const existing = this.ledgerStore.ledger?.findByKey(identity.subject, request.idempotencyKey);
    if (existing && existing.fingerprint !== request.fingerprint) {
      throw new ConflictException({ errorCode: 'IDEMPOTENCY_CONFLICT' });
    }
    return existing?.scanId;
  }
}
