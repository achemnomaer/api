import { Controller, Get, Post, Body, Patch, Param, Delete, ParseArrayPipe } from '@nestjs/common';
import { Permissions } from '../../common/decorators/permissions.decorator';
import { RolesService } from './roles.service';
import { CreateRoleDto } from './dto/create-role.dto';
import { UpdateRoleDto } from './dto/update-role.dto';
import { Role } from './schemas/role.schema';

@Controller('roles')
export class RolesController {
  constructor(private readonly rolesService: RolesService) {}

  @Post()
  @Permissions('roles:write')
  async create(@Body() dto: CreateRoleDto): Promise<Role> {
    return this.rolesService.create(dto);
  }

  @Get()
  @Permissions('roles:read')
  async findAll(): Promise<Role[]> {
    return this.rolesService.findAll();
  }

  @Get(':id')
  @Permissions('roles:read')
  async findOne(@Param('id') id: string): Promise<Role | null> {
    return this.rolesService.findById(id);
  }

  @Patch(':id')
  @Permissions('roles:write')
  async update(@Param('id') id: string, @Body() dto: UpdateRoleDto): Promise<Role> {
    return this.rolesService.update(id, dto);
  }

  @Patch(':id/permissions/add')
  @Permissions('roles:write')
  async addPermissions(
    @Param('id') id: string,
    @Body('permissions', new ParseArrayPipe({ items: String })) permissions: string[],
  ): Promise<Role> {
    return this.rolesService.addPermissions(id, permissions);
  }

  @Patch(':id/permissions/remove')
  @Permissions('roles:write')
  async removePermissions(
    @Param('id') id: string,
    @Body('permissions', new ParseArrayPipe({ items: String })) permissions: string[],
  ): Promise<Role> {
    return this.rolesService.removePermissions(id, permissions);
  }

  @Delete(':id')
  @Permissions('roles:delete')
  async remove(@Param('id') id: string): Promise<void> {
    return this.rolesService.remove(id);
  }
}
