import { SetMetadata } from '@nestjs/common';

export const PERMISSIONS_KEY = 'permissions';
export const Permissions = (...permissions: string[]): any =>
  SetMetadata(PERMISSIONS_KEY, permissions);
