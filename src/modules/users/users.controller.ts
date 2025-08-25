import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  ParseArrayPipe,
} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { PermissionsGuard } from '../../common/guards/permissions.guard';
import { Permissions } from '../../common/decorators/permissions.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './schemas/user.schema';

@Controller('users')
@UseGuards(JwtAuthGuard, PermissionsGuard)
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  @Permissions('users:write')
  async create(@Body() createUserDto: CreateUserDto): Promise<User> {
    return this.usersService.create(createUserDto);
  }

  @Get()
  @Permissions('users:read')
  async findAll(): Promise<User[]> {
    return this.usersService.findAll();
  }

  @Get('me')
  async getProfile(@CurrentUser() user: User): Promise<User> {
    return user;
  }

  @Get(':id')
  @Permissions('users:read')
  async findOne(@Param('id') id: string): Promise<User | null> {
    return this.usersService.findById(id);
  }

  @Patch('me')
  async updateProfile(
    @CurrentUser('id') userId: string,
    @Body() updateUserDto: UpdateUserDto,
  ): Promise<User> {
    return this.usersService.update(userId, updateUserDto);
  }

  @Patch(':id')
  @Permissions('users:write')
  async update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto): Promise<User> {
    return this.usersService.update(id, updateUserDto);
  }

  @Patch(':id/roles')
  @Permissions('users:write', 'roles:assign')
  async assignRoles(
    @Param('id') id: string,
    @Body('roleIds', new ParseArrayPipe({ items: String })) roleIds: string[],
  ): Promise<User> {
    return this.usersService.assignRoles(id, roleIds);
  }

  @Delete(':id')
  @Permissions('users:delete')
  async remove(@Param('id') id: string): Promise<void> {
    return this.usersService.remove(id);
  }
}
