import { Module } from '@nestjs/common';
import { ScanAuthGuard } from './scan-auth.guard.js';

@Module({ providers: [ScanAuthGuard], exports: [ScanAuthGuard] })
export class SecurityModule {}
