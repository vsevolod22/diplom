import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { AppModule } from './app.module.js';
import { configureParentIngress } from './parent-ingress.js';

async function main(): Promise<void> {
  // Never expose a listener with unconfigured authentication.
  if (!process.env.SCAN_JWT_SECRET || Buffer.byteLength(process.env.SCAN_JWT_SECRET) < 32 ||
      !process.env.SCAN_JWT_ISSUER || !process.env.SCAN_JWT_AUDIENCE) {
    throw new Error('Dedicated JWT issuer, audience and signing secret are required');
  }
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { bodyParser: false });
  configureParentIngress(app);
  const bind = process.env.SCAN_BIND_ADDRESS ?? '127.0.0.1';
  if (bind !== '127.0.0.1' && bind !== '0.0.0.0') throw new Error('Invalid bind address');
  await app.listen(Number(process.env.PORT || 3001), bind);
}

void main();
