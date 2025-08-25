import { Module } from '@nestjs/common';
import { CacheCustomService } from './cache.service';

@Module({
  providers: [CacheCustomService],
  exports: [CacheCustomService],
})
export class CacheCustomModule {}