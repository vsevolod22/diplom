import { Module } from '@nestjs/common';
import { ScansModule } from './scans/scans.module.js';

@Module({ imports: [ScansModule] })
export class AppModule {}
