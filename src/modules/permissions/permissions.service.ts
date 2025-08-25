import { Injectable } from '@nestjs/common';
import { User } from '../users/schemas/user.schema';
import { RolesService } from '../roles/roles.service';

@Injectable()
export class PermissionsService {
  constructor(private rolesService: RolesService) {}

  async hasPermissions(user: User, requiredPermissions: string[]): Promise<boolean> {
    if (!user.roles || user.roles.length === 0) {
      return false;
    }

    const roles = await this.rolesService.findByIds(
      user.roles.map(roleId => roleId.toString())
    );

    const userPermissions = roles.reduce((permissions, role) => {
      return [...permissions, ...role.permissions];
    }, [] as string[]);

    // Check for super admin (*) permission
    if (userPermissions.includes('*')) {
      return true;
    }

    // Check each required permission
    return requiredPermissions.every(requiredPermission => {
      return userPermissions.some(userPermission => {
        // Exact match
        if (userPermission === requiredPermission) {
          return true;
        }

        // Wildcard match (e.g., users:* matches users:read, users:write, etc.)
        if (userPermission.endsWith(':*')) {
          const resource = userPermission.split(':')[0];
          const requiredResource = requiredPermission.split(':')[0];
          return resource === requiredResource;
        }

        return false;
      });
    });
  }

  async getUserPermissions(user: User): Promise<string[]> {
    if (!user.roles || user.roles.length === 0) {
      return [];
    }

    const roles = await this.rolesService.findByIds(
      user.roles.map(roleId => roleId.toString())
    );

    const permissions = roles.reduce((permissions, role) => {
      return [...permissions, ...role.permissions];
    }, [] as string[]);

    // Remove duplicates
    return [...new Set(permissions)];
  }

  getAvailablePermissions(): string[] {
    return [
      // User permissions
      'users:read',
      'users:write',
      'users:delete',
      
      // Role permissions
      'roles:read',
      'roles:write',
      'roles:delete',
      'roles:assign',
      
      // Admin panel access
      'panel:access',
      
      // Business permissions
      'leads:read',
      'leads:write',
      'leads:delete',
      'leads:*',
      
      'applications:read',
      'applications:write',
      'applications:delete',
      'applications:*',
      
      'students:read',
      'students:write',
      'students:delete',
      'students:*',
      
      // System permissions
      'system:health',
      'system:audit',
      'system:queue',
      
      // Super admin
      '*',
    ];
  }
}