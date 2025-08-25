/* eslint-disable @typescript-eslint/no-unsafe-call */
import { NestFactory } from '@nestjs/core';
import { ValidationPipe, RequestMethod, VersioningType } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Logger } from 'nestjs-pino';
import helmet from 'helmet';
import * as hpp from 'hpp';
import * as cookieParser from 'cookie-parser';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';

function parseOrigins(origins?: string | string[]): string[] | boolean {
  if (Array.isArray(origins)) return origins;
  if (typeof origins === 'string' && origins.trim()) {
    return origins.split(',').map((s) => s.trim());
  }
  // default dev origin
  return ['http://localhost:3000'];
}

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule, {
    bufferLogs: true,
    logger: ['error', 'warn'],
  });

  const config = app.get(ConfigService);
  const logger = app.get(Logger);
  app.useLogger(logger);

  const isDev = config.get<string>('NODE_ENV', 'development') === 'development';

  // Security middleware
  app.use(helmet(isDev ? { contentSecurityPolicy: false } : undefined));
  app.use(hpp());
  app.use(cookieParser());

  // Global route prefix: /api (exclude GET /health if you have a public health probe)
  app.setGlobalPrefix('api', {});

  // API versioning => /api/v1/...
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  // CORS configuration
  app.enableCors({
    origin: parseOrigins(config.get<string | string[]>('CORS_ORIGINS')),
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  });

  // Global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: { enableImplicitConversion: true },
    }),
  );

  // Swagger at /api/docs
  const swaggerConfig = new DocumentBuilder()
    .setTitle('GEC API')
    .setDescription('Global Education Care API documentation')
    .setVersion('1.0')
    .addBearerAuth(
      { type: 'http', scheme: 'bearer', bearerFormat: 'JWT', in: 'header' },
      'JWT-auth',
    )
    .build();
  const swaggerDoc = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('api/docs', app, swaggerDoc);

  // Graceful shutdown hooks
  app.enableShutdownHooks();

  const port = config.get<number>('PORT', 3000);
  await app.listen(port);

  logger.log(`➡️  API:        http://localhost:${port}/api/v1`, 'Bootstrap');
  logger.log(`📚 Swagger:    http://localhost:${port}/api/docs`, 'Bootstrap');
}

bootstrap();
