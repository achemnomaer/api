import { Controller, Get } from '@nestjs/common';
import {
  HealthCheckService,
  HealthCheck,
  MongooseHealthIndicator,
  MemoryHealthIndicator,
} from '@nestjs/terminus';
import { ConfigService } from '@nestjs/config';
import { CacheCustomService } from '../cache/cache.service';
import { QueueService } from '../queue/queue.service';
import { Public } from '../../common/decorators/public.decorator';

@Public()
@Controller('health')
export class HealthController {
  constructor(
    private health: HealthCheckService,
    private mongoose: MongooseHealthIndicator,
    private memory: MemoryHealthIndicator,
    private configService: ConfigService,
    private cacheService: CacheCustomService,
    private queueService: QueueService,
  ) {}

  /** Safely extract an error message from unknown */
  private getErrorMessage(err: unknown): string {
    if (err instanceof Error) return err.message;
    try {
      return JSON.stringify(err);
    } catch {
      return String(err);
    }
  }

  @Get()
  @HealthCheck()
  check() {
    return this.health.check([
      // MongoDB
      () => this.mongoose.pingCheck('mongoose'),

      // Memory: heap <= 300MB
      () => this.memory.checkHeap('memory_heap', 300 * 1024 * 1024),

      // Memory: RSS <= 300MB
      () => this.memory.checkRSS('memory_rss', 300 * 1024 * 1024),

      // Redis
      async () => {
        try {
          await this.cacheService.ping();
          return { redis: { status: 'up' } };
        } catch (error: unknown) {
          return {
            redis: {
              status: 'down',
              message: this.getErrorMessage(error),
            },
          };
        }
      },

      // Queues
      async () => {
        try {
          const queueHealth = await this.queueService.getQueueHealth();
          return {
            queues: {
              status: queueHealth.isHealthy ? 'up' : 'down',
              details: queueHealth.queues,
            },
          };
        } catch (error: unknown) {
          return {
            queues: {
              status: 'down',
              message: this.getErrorMessage(error),
            },
          };
        }
      },
    ]);
  }

  @Get('liveness')
  liveness() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
    };
  }

  @Get('readiness')
  async readiness() {
    try {
      await Promise.all([
        this.cacheService.ping(),
        // add other critical checks here
      ]);

      return {
        status: 'ready',
        timestamp: new Date().toISOString(),
        checks: {
          redis: 'ok',
          // others...
        },
      };
    } catch (error: unknown) {
      return {
        status: 'not ready',
        timestamp: new Date().toISOString(),
        error: this.getErrorMessage(error),
      };
    }
  }

  @Get('info')
  info() {
    return {
      service: 'NestJS Auth System',
      version: process.env.npm_package_version || '1.0.0',
      environment: this.configService.get<string>('NODE_ENV'),
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      timestamp: new Date().toISOString(),
    };
  }
}
