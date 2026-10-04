import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller.js';
import { AuthStore } from './auth.store.js';

@Module({ controllers: [AuthController], providers: [AuthStore], exports: [AuthStore] })
export class AuthModule {}
