import {
  Injectable,
  ConflictException,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { Role, RoleDocument } from './schemas/role.schema';
import { CreateRoleDto } from './dto/create-role.dto';
import { UpdateRoleDto } from './dto/update-role.dto';

@Injectable()
export class RolesService {
  constructor(@InjectModel(Role.name) private roleModel: Model<RoleDocument>) {}

  private toObjectId(id: string): Types.ObjectId {
    if (!Types.ObjectId.isValid(id)) throw new BadRequestException('Invalid role id');
    return new Types.ObjectId(id);
  }

  private normalizeName(name: string): string {
    return name.trim().toLowerCase();
  }

  private normalizePermissions(perms: string[]): string[] {
    // trim, toLower if you want, and de-duplicate
    const seen = new Set<string>();
    for (const p of perms ?? []) {
      const v = String(p).trim();
      if (v) seen.add(v);
    }
    return Array.from(seen);
  }

  async create(dto: CreateRoleDto): Promise<Role> {
    const name = this.normalizeName(dto.name);
    const exists = await this.roleModel.exists({ name });
    if (exists) throw new ConflictException('Role with this name already exists');

    const role = await this.roleModel.create({
      name,
      description: dto.description.trim(),
      permissions: this.normalizePermissions(dto.permissions ?? []),
      isActive: dto.isActive ?? true,
    });

    return role;
  }

  async findAll(): Promise<Role[]> {
    return this.roleModel.find({ isActive: true }).exec();
    // If you ever want lean + virtuals:
    // return this.roleModel.find({ isActive: true }).lean({ virtuals: true }).exec();
  }

  async findById(id: string): Promise<Role | null> {
    return this.roleModel.findById(this.toObjectId(id)).exec();
  }

  async findByName(name: string): Promise<Role | null> {
    return this.roleModel.findOne({ name: this.normalizeName(name), isActive: true }).exec();
  }

  async findByIds(ids: string[]): Promise<Role[]> {
    const objectIds = ids.map((id) => this.toObjectId(id));
    return this.roleModel.find({ _id: { $in: objectIds }, isActive: true }).exec();
  }

  async update(id: string, dto: UpdateRoleDto): Promise<Role> {
    const update: Partial<Role> = {};

    if (dto.name) {
      const name = this.normalizeName(dto.name);
      const exists = await this.roleModel
        .findOne({ name, _id: { $ne: this.toObjectId(id) } })
        .exec();
      if (exists) throw new ConflictException('Role with this name already exists');
      update.name = name;
    }
    if (dto.description !== undefined) update.description = dto.description.trim();
    if (dto.permissions !== undefined)
      update.permissions = this.normalizePermissions(dto.permissions);
    if (dto.isActive !== undefined) update.isActive = dto.isActive;

    const role = await this.roleModel
      .findByIdAndUpdate(this.toObjectId(id), { $set: update }, { new: true, runValidators: true })
      .exec();

    if (!role) throw new NotFoundException('Role not found');
    return role;
  }

  async remove(id: string): Promise<void> {
    const res = await this.roleModel
      .updateOne({ _id: this.toObjectId(id) }, { $set: { isActive: false } })
      .exec();

    if (res.matchedCount === 0) throw new NotFoundException('Role not found');
  }

  async addPermissions(id: string, permissions: string[]): Promise<Role> {
    const normalized = this.normalizePermissions(permissions);
    const role = await this.roleModel
      .findByIdAndUpdate(
        this.toObjectId(id),
        { $addToSet: { permissions: { $each: normalized } } },
        { new: true },
      )
      .exec();

    if (!role) throw new NotFoundException('Role not found');
    return role;
  }

  async removePermissions(id: string, permissions: string[]): Promise<Role> {
    const normalized = this.normalizePermissions(permissions);
    const role = await this.roleModel
      .findByIdAndUpdate(
        this.toObjectId(id),
        { $pull: { permissions: { $in: normalized } } },
        { new: true },
      )
      .exec();

    if (!role) throw new NotFoundException('Role not found');
    return role;
  }

  async createDefaultRoles(): Promise<void> {
    const defaults = [
      {
        name: 'super_admin',
        description: 'Super Administrator with all permissions',
        permissions: ['*'],
      },
      {
        name: 'admin',
        description: 'Administrator with most permissions',
        permissions: [
          'users:read',
          'users:write',
          'users:delete',
          'roles:read',
          'roles:write',
          'panel:access',
          'leads:*',
          'applications:*',
          'students:*',
        ],
      },
      {
        name: 'counsellor',
        description: 'Education counsellor',
        permissions: ['users:read', 'leads:*', 'applications:*', 'students:*'],
      },
      {
        name: 'support',
        description: 'Support staff',
        permissions: ['users:read', 'leads:read', 'applications:read', 'students:read'],
      },
    ];

    for (const r of defaults) {
      const name = this.normalizeName(r.name);
      const exists = await this.roleModel.findOne({ name }).exec();
      if (!exists) {
        await this.roleModel.create({
          name,
          description: r.description,
          permissions: this.normalizePermissions(r.permissions),
          isActive: true,
        });
      }
    }
  }
}
