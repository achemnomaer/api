import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from '../users/users.module';
import { SessionsModule } from '../sessions/sessions.module';
import { OtpModule } from '../otp/otp.module';
import { MailModule } from '../mail/mail.module';
import { AuditModule } from '../audit/audit.module';
import { LocalStrategy } from './strategies/local.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { GoogleStrategy } from './strategies/google.strategy';

@Module({
  imports: [
    PassportModule,
    JwtModule.register({}), // Configuration handled in service
    UsersModule,
    SessionsModule,
    OtpModule,
    MailModule,
    AuditModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, LocalStrategy, JwtStrategy, GoogleStrategy],
  exports: [AuthService],
})
export class AuthModule {}