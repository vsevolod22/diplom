import { Module, Injectable, Inject, OnModuleDestroy, type DynamicModule } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module.js';
import { LedgerModule } from '../ledger/ledger.module.js';
import { RuntimeStore } from './runtime-store.js';
import { RuntimeIdentity } from './browser-runtime-identity.js';
import { BrowserRuntimeController } from './browser-runtime.controller.js';
import { RuntimeApiService, RUNTIME_STORE, RUNTIME_LIVE } from './runtime-api.service.js';
import { RuntimeImageLinkAdapter } from './runtime-image-link.adapter.js';
import type { QualifiedCapturePort } from '../../../runtime/src/live-port.js';
@Injectable()
class RuntimeStoreLifetime implements OnModuleDestroy {
  constructor(@Inject(RUNTIME_STORE) private readonly store: RuntimeStore | undefined) {}
  onModuleDestroy(): void {
    this.store?.close();
  }
}
@Module({
  imports: [AuthModule, LedgerModule],
  controllers: [BrowserRuntimeController],
  providers: [
    {
      provide: RUNTIME_STORE,
      useFactory: () => {
        if (!process.env.RUNTIME_DB_PATH) return undefined;
        try {
          return new RuntimeStore(process.env.RUNTIME_DB_PATH, Date.now, [
            process.env.AUTH_DB_PATH ?? '',
            process.env.SCAN_LEDGER_PATH ?? '',
          ]);
        } catch {
          return undefined;
        }
      },
    },
    // Parent-qualified Linux application bootstrap may override this provider. Never env-enable Engine.
    { provide: RUNTIME_LIVE, useValue: undefined },
    RuntimeStoreLifetime,
    RuntimeIdentity,
    RuntimeImageLinkAdapter,
    RuntimeApiService,
  ],
  exports: [RuntimeApiService],
})
export class RuntimeApiModule {
  // Explicit reviewed application port injection, never a browser/env/socket admission toggle.
  static withQualifiedCapture(live: QualifiedCapturePort): DynamicModule {
    return { module: RuntimeApiModule, providers: [{ provide: RUNTIME_LIVE, useValue: live }] };
  }
}
