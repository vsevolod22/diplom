import { Module } from '@nestjs/common';
import { ScansModule } from './scans/scans.module.js';
import { AuthModule } from './auth/auth.module.js';

@Module({ imports: [ScansModule, AuthModule] })
export class AppModule {}
