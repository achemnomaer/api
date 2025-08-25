import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { CacheModule } from '@nestjs/cache-manager';
import { ScheduleModule } from '@nestjs/schedule';
import { TerminusModule } from '@nestjs/terminus';
import { LoggerModule } from 'nestjs-pino';
import { redisStore } from 'cache-manager-ioredis-yet';
import { BullModule } from '@nestjs/bull';
import { ThrottlerModule } from '@nestjs/throttler';
import { ThrottlerStorageRedisService } from '@nest-lab/throttler-storage-redis';
import Redis from 'ioredis';

import { configValidation } from './config/config.validation';
import { AuthModule } from './modules/auth/auth.module';
import { UsersModule } from './modules/users/users.module';
import { RolesModule } from './modules/roles/roles.module';
import { PermissionsModule } from './modules/permissions/permissions.module';
import { SessionsModule } from './modules/sessions/sessions.module';
import { OtpModule } from './modules/otp/otp.module';
import { MailModule } from './modules/mail/mail.module';
import { QueueModule } from './modules/queue/queue.module';
import { AuditModule } from './modules/audit/audit.module';
import { CacheCustomModule } from './modules/cache/cache.module';
import { HealthModule } from './modules/health/health.module';

import { SecurityModule } from './modules/core/security.module';

@Module({
  imports: [
    // Configuration
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: configValidation,
      validationOptions: {
        allowUnknown: false,
        abortEarly: true,
      },
    }),

    // Database
    MongooseModule.forRootAsync({
      useFactory: () => ({
        uri: process.env.MONGODB_URI,
        autoIndex: true,
        retryDelay: 500,
        retryAttempts: 3,
      }),
    }),

    // Cache with Redis
    CacheModule.registerAsync({
      isGlobal: true,
      useFactory: () => ({
        store: redisStore,
        host: process.env.REDIS_HOST || 'localhost',
        port: parseInt(process.env.REDIS_PORT || '6379'),
        password: process.env.REDIS_PASSWORD || undefined,
        db: parseInt(process.env.REDIS_DB || '0'),
        ttl: 60 * 60 * 1000, // 1 hour default TTL
      }),
    }),

    // Rate limiting
    ThrottlerModule.forRootAsync({
      useFactory: () => ({
        throttlers: [
          { name: 'short', ttl: 1_000, limit: 3 },
          { name: 'medium', ttl: 10_000, limit: 20 },
          { name: 'long', ttl: 60_000, limit: 100 },
        ],
        storage: new ThrottlerStorageRedisService(
          new Redis({
            host: process.env.REDIS_HOST || 'localhost',
            port: parseInt(process.env.REDIS_PORT || '6379', 10),
            password: process.env.REDIS_PASSWORD || undefined,
            db: parseInt(process.env.REDIS_THROTTLE_DB || '1', 10),
          }),
        ),
      }),
    }),

    // Queue system
    BullModule.forRootAsync({
      useFactory: () => ({
        redis: {
          host: process.env.REDIS_HOST || 'localhost',
          port: parseInt(process.env.REDIS_PORT || '6379'),
          password: process.env.REDIS_PASSWORD || undefined,
          db: parseInt(process.env.REDIS_QUEUE_DB || '2'),
        },
      }),
    }),

    // Scheduling
    ScheduleModule.forRoot(),

    // Logging
    LoggerModule.forRootAsync({
      useFactory: () => ({
        pinoHttp: {
          // Only enable pretty logs in dev
          transport:
            process.env.NODE_ENV === 'development'
              ? {
                  target: 'pino-pretty',
                  options: {
                    colorize: true,
                    singleLine: true,
                    translateTime: 'SYS:standard',
                    ignore: 'pid,hostname',
                  },
                }
              : undefined,
          redact: {
            paths: ['req.headers.authorization', 'req.headers.cookie'],
            censor: '[REDACTED]',
          },
        },
      }),
    }),

    // Health checks
    TerminusModule,

    // Feature modules
    AuthModule,
    UsersModule,
    RolesModule,
    //PermissionsModule, No need to use it, as we have done it in the security module
    SessionsModule,
    OtpModule,
    MailModule,
    QueueModule,
    AuditModule,
    CacheCustomModule,
    HealthModule,

    SecurityModule,
  ],
})
export class AppModule {}
