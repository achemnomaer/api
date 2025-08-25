import { SetMetadata } from '@nestjs/common';

export const SKIP_PERMISSIONS_KEY = 'skipPermissions';
export const SkipPermissions = () => SetMetadata(SKIP_PERMISSIONS_KEY, true);
