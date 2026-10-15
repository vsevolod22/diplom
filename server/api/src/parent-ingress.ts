import type { NestExpressApplication } from '@nestjs/platform-express';
import { registerHistoryIngress } from './llm/history-ingress.js';
import { RuntimeApiModule } from './runtime/runtime-api.module.js';
import { RuntimeApiService } from './runtime/runtime-api.service.js';
import { RuntimeIdentity } from './runtime/browser-runtime-identity.js';
import { createRuntimeIntake } from './runtime/runtime-intake.js';

// Call only after NestFactory.create(..., { bodyParser: false }), before init/listen.
export function configureParentIngress(app: NestExpressApplication): void {
  const runtime = app.select(RuntimeApiModule);
  const identity = runtime.get(RuntimeIdentity, { strict: true });
  const service = runtime.get(RuntimeApiService, { strict: true });
  app.use(createRuntimeIntake(req => identity.resolve(req, true)));
  registerHistoryIngress(app);
  // Preserve ordinary Nest/Express defaults; finished raw streams are not reparsed.
  app.useBodyParser('json');
  app.useBodyParser('urlencoded', { extended: true });
  service.configureRawIntake();
}
