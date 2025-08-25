import { Module } from '@nestjs/common';
import { TerminusModule } from '@nestjs/terminus';
import { HealthController } from './health.controller';
import { CacheCustomModule } from '../cache/cache.module';
import { QueueModule } from '../queue/queue.module';

@Module({
  imports: [TerminusModule, CacheCustomModule, QueueModule],
  controllers: [HealthController],
})
export class HealthModule {}