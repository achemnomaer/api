import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../users/users.service';
import { SessionsService } from '../sessions/sessions.service';
import { OtpService } from '../otp/otp.service';
import { MailService } from '../mail/mail.service';
import { AuditService } from '../audit/audit.service';
import { User } from '../users/schemas/user.schema';
import { RegisterDto } from './dto/register.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { JwtPayload } from '../../common/interfaces/jwt-payload.interface';
import { UserStatus } from '../../common/enums/user-status.enum';
import { OtpType } from '../../common/enums/otp-type.enum';
import { AuditAction } from '../../common/enums/audit-action.enum';
import { AuthProvider, AuthAudience } from '../../common/enums/auth-provider.enum';
import { PermissionsService } from '../permissions/permissions.service';

interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  sessionId: string;
}

interface GoogleUser {
  email: string;
  firstName: string;
  lastName: string;
  avatar?: string;
  googleId: string;
}

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private sessionsService: SessionsService,
    private otpService: OtpService,
    private mailService: MailService,
    private auditService: AuditService,
    private permissionsService: PermissionsService,
  ) {}

  private isDupKeyError(err: unknown): boolean {
    return typeof err === 'object' && err !== null && (err as any).code === 11000;
  }

  async register(registerDto: RegisterDto, ip: string, userAgent: string): Promise<User> {
    try {
      const user = await this.usersService.create({
        ...registerDto,
        signupProvider: AuthProvider.EMAIL,
        linkedProviders: [AuthProvider.EMAIL],
      });

      const { otp } = await this.otpService.generateOtp(user.id!, OtpType.VERIFY_EMAIL);
      await this.mailService.sendEmailVerification(user, otp);

      await this.auditService.log({
        actorId: user.id!,
        action: AuditAction.CREATE,
        resource: 'user',
        resourceId: user.id!,
        meta: { ip, userAgent },
      });

      return user;
    } catch (error: unknown) {
      if (this.isDupKeyError(error)) {
        throw new ConflictException('Email already exists');
      }
      throw error;
    }
  }

  async validateUser(email: string, password: string): Promise<User | null> {
    // Validate credentials using the new usersService helper
    const validated = await this.usersService.validatePasswordByEmail(email, password);
    if (!validated) return null;

    // Fetch the canonical user (with roles populated if your usersService does that)
    const user = await this.usersService.findByEmail(email);
    if (!user) return null;

    if (user.status === UserStatus.SUSPENDED) {
      throw new UnauthorizedException('Account suspended');
    }
    return user;
  }

  async validateGoogleUser(googleUser: GoogleUser): Promise<User> {
    let user = await this.usersService.findByEmail(googleUser.email);

    if (!user) {
      user = await this.usersService.create({
        email: googleUser.email,
        firstName: googleUser.firstName,
        lastName: googleUser.lastName,
        googleId: googleUser.googleId,
        avatar: googleUser.avatar,
        status: UserStatus.ACTIVE,
        signupProvider: AuthProvider.GOOGLE,
        linkedProviders: [AuthProvider.GOOGLE],
      });

      await this.usersService.verifyEmail(user.id!);
    } else if (!user.googleId) {
      await this.usersService.update(user.id!, {
        googleId: googleUser.googleId,
        avatar: googleUser.avatar,
      });
      await this.usersService.linkProvider(user.id!, AuthProvider.GOOGLE);
    }

    if (user.status === UserStatus.SUSPENDED) {
      throw new UnauthorizedException('Account suspended');
    }

    return user;
  }

  async login(user: User, ip: string, userAgent: string, deviceName?: string): Promise<AuthTokens> {
    const tokens = await this.generateTokens(user, AuthAudience.WEB);

    const session = await this.sessionsService.createSession(
      user.id!,
      tokens.refreshToken,
      ip,
      userAgent,
      deviceName,
    );

    await this.usersService.updateLastLogin(user.id!, ip);

    await this.auditService.log({
      actorId: user.id!,
      action: AuditAction.LOGIN,
      resource: 'auth',
      resourceId: user.id!,
      meta: { ip, userAgent, deviceName, sessionId: session.id },
    });

    return {
      ...tokens,
      sessionId: session.id!,
    };
  }

  async adminLogin(user: User, ip: string, userAgent: string, deviceName?: string): Promise<AuthTokens> {
    // Check if user has admin panel access
    const hasAccess = await this.permissionsService.hasPermissions(user, ['panel:access']);
    if (!hasAccess) {
      throw new UnauthorizedException('Access denied: Admin panel access required');
    }

    const tokens = await this.generateTokens(user, AuthAudience.ADMIN);

    const session = await this.sessionsService.createSession(
      user.id!,
      tokens.refreshToken,
      ip,
      userAgent,
      deviceName,
    );

    await this.usersService.updateLastLogin(user.id!, ip);

    await this.auditService.log({
      actorId: user.id!,
      action: AuditAction.LOGIN,
      resource: 'admin_auth',
      resourceId: user.id!,
      meta: { ip, userAgent, deviceName, sessionId: session.id },
    });

    return {
      ...tokens,
      sessionId: session.id!,
    };
  }

  async refreshTokens(
    refreshToken: string,
    sessionId: string,
    ip: string,
    userAgent: string,
  ): Promise<AuthTokens | null> {
    const session = await this.sessionsService.validateRefreshToken(refreshToken, sessionId);
    if (!session) return null;

    const user = await this.usersService.findById(String(session.userId));
    if (!user || user.status === UserStatus.SUSPENDED) {
      await this.sessionsService.revokeSession(sessionId, 'User invalid or suspended');
      return null;
    }

    // Determine audience from existing session context
    // For now, we'll default to WEB, but you could store audience in session
    // or decode the old refresh token to get the audience
    const audience = AuthAudience.WEB; // Could be enhanced to detect from context
    
    const tokens = await this.generateTokens(user, audience);
    await this.sessionsService.rotateRefreshToken(sessionId, tokens.refreshToken);

    await this.auditService.log({
      actorId: user.id!,
      action: AuditAction.REFRESH_TOKEN,
      resource: 'auth',
      resourceId: user.id!,
      meta: { ip, userAgent, sessionId },
    });

    return { ...tokens, sessionId };
  }

  async logout(sessionId: string, userId: string): Promise<void> {
    await this.sessionsService.revokeSession(sessionId, 'User logout');

    await this.auditService.log({
      actorId: userId,
      action: AuditAction.LOGOUT,
      resource: 'auth',
      resourceId: userId,
      meta: { sessionId },
    });
  }

  async changePassword(
    userId: string,
    changePasswordDto: ChangePasswordDto,
    ip: string,
    userAgent: string,
  ): Promise<void> {
    const user = await this.usersService.findById(userId);
    if (!user) throw new UnauthorizedException('User not found');

    if (!user.passwordHash) {
      throw new BadRequestException('Password not set. Use Google login or reset password.');
    }

    // Validate current password using helper
    const ok = await this.usersService.validatePasswordByEmail(
      user.email,
      changePasswordDto.currentPassword,
    );
    if (!ok) throw new UnauthorizedException('Current password is incorrect');

    await this.usersService.updatePassword(userId, changePasswordDto.newPassword);
    await this.sessionsService.revokeAllUserSessions(userId, 'Password changed - security measure');

    await this.auditService.log({
      actorId: userId,
      action: AuditAction.PASSWORD_CHANGE,
      resource: 'auth',
      resourceId: userId,
      meta: { ip, userAgent },
    });

    await this.mailService.sendPasswordChangeNotification(user);
  }

  async requestPasswordReset(email: string): Promise<void> {
    const user = await this.usersService.findByEmail(email);
    if (!user) return; // do not reveal

    if (!user.passwordHash) {
      throw new BadRequestException(
        'This account uses Google login. Please use Google to sign in.',
      );
    }

    const { otp } = await this.otpService.generateOtp(user.id!, OtpType.RESET_PASSWORD);
    await this.mailService.sendPasswordReset(user, otp);
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto): Promise<void> {
    const user = await this.usersService.findByEmail(resetPasswordDto.email);
    if (!user) throw new BadRequestException('Invalid email or OTP');

    const isOtpValid = await this.otpService.verifyOtp(
      user.id!,
      OtpType.RESET_PASSWORD,
      resetPasswordDto.otp,
    );
    if (!isOtpValid) throw new BadRequestException('Invalid or expired OTP');

    await this.usersService.updatePassword(user.id!, resetPasswordDto.newPassword);

    await this.sessionsService.revokeAllUserSessions(user.id!, 'Password reset');
    await this.otpService.invalidateUserOtps(user.id!);

    await this.auditService.log({
      actorId: user.id!,
      action: AuditAction.PASSWORD_RESET,
      resource: 'auth',
      resourceId: user.id!,
      meta: {},
    });

    await this.mailService.sendPasswordResetConfirmation(user);
  }

  async verifyEmail(userId: string, otp: string): Promise<void> {
    const isOtpValid = await this.otpService.verifyOtp(userId, OtpType.VERIFY_EMAIL, otp);
    if (!isOtpValid) throw new BadRequestException('Invalid or expired OTP');

    const user = await this.usersService.verifyEmail(userId);

    await this.auditService.log({
      actorId: userId,
      action: AuditAction.EMAIL_VERIFY,
      resource: 'auth',
      resourceId: userId,
      meta: {},
    });

    await this.mailService.sendWelcome(user);
  }

  async setPassword(userId: string, password: string, ip: string, userAgent: string): Promise<void> {
    const user = await this.usersService.setPassword(userId, password);

    await this.auditService.log({
      actorId: userId,
      action: AuditAction.PASSWORD_CHANGE,
      resource: 'auth',
      resourceId: userId,
      meta: { ip, userAgent, action: 'set_password' },
    });

    await this.mailService.sendPasswordChangeNotification(user);
  }

  async linkProvider(userId: string, provider: AuthProvider): Promise<void> {
    await this.usersService.linkProvider(userId, provider);

    await this.auditService.log({
      actorId: userId,
      action: AuditAction.UPDATE,
      resource: 'user_provider',
      resourceId: userId,
      meta: { action: 'link_provider', provider },
    });
  }

  async unlinkProvider(userId: string, provider: AuthProvider): Promise<void> {
    await this.usersService.unlinkProvider(userId, provider);

    await this.auditService.log({
      actorId: userId,
      action: AuditAction.UPDATE,
      resource: 'user_provider',
      resourceId: userId,
      meta: { action: 'unlink_provider', provider },
    });
  }

  /** Convenience for controller – no need to reach into usersService from outside */
  async verifyEmailByEmail(email: string, otp: string): Promise<void> {
    const user = await this.usersService.findByEmail(email);
    if (!user) throw new BadRequestException('Invalid email or OTP');
    await this.verifyEmail(user.id!, otp);
  }

  async resendVerificationEmail(email: string): Promise<void> {
    const user = await this.usersService.findByEmail(email);
    if (!user) {
      // Don’t reveal whether the email exists
      return;
    }

    if (user.isEmailVerified) {
      throw new BadRequestException('Email is already verified');
    }

    const { otp } = await this.otpService.generateOtp(user.id!, OtpType.VERIFY_EMAIL);
    await this.mailService.sendEmailVerification(user, otp);
  }

  private async generateTokens(user: User, audience: AuthAudience): Promise<Omit<AuthTokens, 'sessionId'>> {
    const jti = `${user.id}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    const payload: JwtPayload = {
      sub: user.id!, // ⬅️ virtual id
      email: user.email,
      roles: (user.roles ?? []).map((r: any) => r.toString()),
      sessionId: '', // set by caller
      aud: audience,
      iss: 'education-consultancy-api',
      jti,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
        expiresIn: this.configService.get<string>('JWT_ACCESS_EXPIRY', '15m'),
      }),
      this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRY', '7d'),
      }),
    ]);

    return { accessToken, refreshToken };
  }
}
