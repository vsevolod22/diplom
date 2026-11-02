import { Module, type DynamicModule } from '@nestjs/common';
import { AuthController } from './auth.controller.js';
import { AuthStore } from './auth.store.js';

import { PASSWORD_RESET_DELIVERY, PasswordResetService, type PasswordResetDelivery } from './password-reset.service.js';

@Module({ controllers: [AuthController], providers: [AuthStore, PasswordResetService], exports: [AuthStore] })
export class AuthModule {
  // Opt-in server composition; importing plain AuthModule keeps recovery disabled.
  // Use one descriptor throughout the composition to avoid duplicate AuthStore instances.
  static withPasswordReset(delivery: PasswordResetDelivery): DynamicModule {
    return { module: AuthModule, providers: [{ provide: PASSWORD_RESET_DELIVERY, useValue: delivery }] };
  }
}
