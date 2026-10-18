import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { PublicImageModule, configurePublicImageIngress } from './public-image.module.js';

if (!process.env.SCAN_JWT_SECRET || Buffer.byteLength(process.env.SCAN_JWT_SECRET) < 32 ||
    !process.env.SCAN_JWT_ISSUER || !process.env.SCAN_JWT_AUDIENCE) throw new Error('Dedicated JWT configuration required');
const bind = process.env.SCAN_BIND_ADDRESS ?? '127.0.0.1';
if (bind !== '127.0.0.1' && bind !== '0.0.0.0') throw new Error('Invalid bind address');
const app = await NestFactory.create<NestExpressApplication>(PublicImageModule, { logger: false, bodyParser: false });
configurePublicImageIngress(app);
await app.listen(Number(process.env.PORT || 3001), bind);
const stop = async () => { await app.close(); process.exit(0); };
process.on('SIGTERM', () => { void stop(); });
process.on('SIGINT', () => { void stop(); });
