import { Module, OnModuleInit } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { RolesService } from './roles.service';
import { RolesController } from './roles.controller';
import { Role, RoleSchema } from './schemas/role.schema';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Role.name, schema: RoleSchema }])
  ],
  controllers: [RolesController],
  providers: [RolesService],
  exports: [RolesService],
})
export class RolesModule implements OnModuleInit {
  constructor(private rolesService: RolesService) {}

  async onModuleInit(): Promise<void> {
    await this.rolesService.createDefaultRoles();
  }
}