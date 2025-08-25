import { Module, Global } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { PermissionsGuard } from '../../common/guards/permissions.guard';
import { PermissionsModule } from '../permissions/permissions.module';

@Global()
@Module({
  imports: [PermissionsModule],
  exports: [PermissionsModule],
  providers: [
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: PermissionsGuard },
  ],
})
export class SecurityModule {}
