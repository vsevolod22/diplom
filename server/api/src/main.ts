import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module.js';

async function main(): Promise<void> {
  // Never expose a listener with unconfigured authentication.
  if (!process.env.SCAN_JWT_SECRET || Buffer.byteLength(process.env.SCAN_JWT_SECRET) < 32 ||
      !process.env.SCAN_JWT_ISSUER || !process.env.SCAN_JWT_AUDIENCE) {
    throw new Error('Dedicated JWT issuer, audience and signing secret are required');
  }
  const app = await NestFactory.create(AppModule);
  await app.listen(Number(process.env.PORT || 3001), '127.0.0.1');
}

void main();
