import { Module } from '@nestjs/common';
import { PermissionsService } from './permissions.service';
import { RolesModule } from '../roles/roles.module';

@Module({
  imports: [RolesModule],
  providers: [PermissionsService],
  exports: [PermissionsService],
})
export class PermissionsModule {}