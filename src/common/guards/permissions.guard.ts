import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PERMISSIONS_KEY } from '../decorators/permissions.decorator';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { SKIP_PERMISSIONS_KEY } from '../decorators/skip-permissions.decorator';
import { PermissionsService } from '../../modules/permissions/permissions.service';

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly permissionsService: PermissionsService,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    // Public routes bypass everything
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      ctx.getHandler(),
      ctx.getClass(),
    ]);
    if (isPublic) return true;

    // Explicitly skip RBAC but keep JWT (route/class marked @SkipPermissions)
    const skip = this.reflector.getAllAndOverride<boolean>(SKIP_PERMISSIONS_KEY, [
      ctx.getHandler(),
      ctx.getClass(),
    ]);
    if (skip) return true;

    // Read required permissions (route/class marked @Permissions(...))
    const required = this.reflector.getAllAndOverride<string[]>(PERMISSIONS_KEY, [
      ctx.getHandler(),
      ctx.getClass(),
    ]);

    // If no permissions are required, allow (JWT already enforced globally)
    if (!required || required.length === 0) return true;

    // Must be authenticated by JwtAuthGuard already
    const req = ctx.switchToHttp().getRequest();
    const user = req.user;
    if (!user) return false;

    // Delegate to your service
    return this.permissionsService.hasPermissions(user, required);
  }
}
