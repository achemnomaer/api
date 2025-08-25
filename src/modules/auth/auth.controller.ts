import { Controller, Post, Body, UseGuards, Req, Res, Get, Ip, Headers } from '@nestjs/common';
import { Request, Response } from 'express';
import { Throttle } from '@nestjs/throttler';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ResetPasswordRequestDto, ResetPasswordDto } from './dto/reset-password.dto';
import { User } from '../users/schemas/user.schema';
import { Public } from 'src/common/decorators/public.decorator';

@Public()
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  @Throttle({ default: { limit: 5, ttl: 300000 } }) // 5 attempts / 5 min
  async register(
    @Body() registerDto: RegisterDto,
    @Ip() ip: string,
    @Headers('user-agent') userAgent: string = 'unknown',
  ): Promise<{ message: string; user: User }> {
    const user = await this.authService.register(registerDto, ip, userAgent);
    return {
      message: 'Registration successful. Please check your email for verification.',
      user,
    };
  }

  @Post('login')
  @UseGuards(LocalAuthGuard)
  @Throttle({ default: { limit: 10, ttl: 300000 } }) // 10 attempts / 5 min
  async login(
    @Body() _loginDto: LoginDto, // validated by LocalAuthGuard
    @CurrentUser() user: User,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Headers('user-agent') userAgent: string = 'unknown',
  ): Promise<{ message: string; user: User; accessToken: string }> {
    const ip = req.ip || (req.socket as any)?.remoteAddress || 'unknown';
    const tokens = await this.authService.login(user, ip, userAgent);

    // Set refresh token + session
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    res.cookie('sessionId', tokens.sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return { message: 'Login successful', user, accessToken: tokens.accessToken };
  }

  @Get('google')
  @UseGuards(GoogleAuthGuard)
  async googleAuth(): Promise<void> {
    // Redirect handled by guard
  }

  @Get('google/callback')
  @UseGuards(GoogleAuthGuard)
  async googleAuthCallback(
    @CurrentUser() user: User,
    @Req() req: Request,
    @Res() res: Response,
    @Headers('user-agent') userAgent: string = 'unknown',
  ): Promise<void> {
    const ip = req.ip || (req.socket as any)?.remoteAddress || 'unknown';
    const tokens = await this.authService.login(user, ip, userAgent, 'Google OAuth');

    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    res.cookie('sessionId', tokens.sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    const frontendUrl = process.env.FRONTEND_URL;
    res.redirect(`${frontendUrl}/auth/callback?token=${tokens.accessToken}`);
  }

  @Post('refresh')
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Headers('user-agent') userAgent: string = 'unknown',
  ): Promise<{ accessToken: string } | { message: string }> {
    const refreshToken = (req as any).cookies?.refreshToken;
    const sessionId = (req as any).cookies?.sessionId;

    if (!refreshToken || !sessionId) {
      res.clearCookie('refreshToken');
      res.clearCookie('sessionId');
      return { message: 'No refresh token found' };
    }

    const ip = req.ip || (req.socket as any)?.remoteAddress || 'unknown';
    const tokens = await this.authService.refreshTokens(refreshToken, sessionId, ip, userAgent);

    if (!tokens) {
      res.clearCookie('refreshToken');
      res.clearCookie('sessionId');
      return { message: 'Invalid refresh token' };
    }

    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return { accessToken: tokens.accessToken };
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  async logout(
    @CurrentUser('id') userId: string, // ⬅️ was '_id'
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<{ message: string }> {
    const sessionId = (req as any).cookies?.sessionId;

    if (sessionId) {
      await this.authService.logout(sessionId, userId);
    }

    res.clearCookie('refreshToken');
    res.clearCookie('sessionId');
    return { message: 'Logout successful' };
  }

  @Post('change-password')
  @UseGuards(JwtAuthGuard)
  async changePassword(
    @CurrentUser('id') userId: string, // ⬅️ was '_id'
    @Body() changePasswordDto: ChangePasswordDto,
    @Ip() ip: string,
    @Headers('user-agent') userAgent: string = 'unknown',
  ): Promise<{ message: string }> {
    await this.authService.changePassword(userId, changePasswordDto, ip, userAgent);
    return { message: 'Password changed successfully' };
  }

  @Post('request-password-reset')
  @Throttle({ default: { limit: 3, ttl: 300000 } })
  async requestPasswordReset(
    @Body() resetRequestDto: ResetPasswordRequestDto,
  ): Promise<{ message: string }> {
    await this.authService.requestPasswordReset(resetRequestDto.email);
    return {
      message: 'If the email exists, a password reset link has been sent.',
    };
  }

  @Post('reset-password')
  @Throttle({ default: { limit: 5, ttl: 300000 } })
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto): Promise<{ message: string }> {
    await this.authService.resetPassword(resetPasswordDto);
    return { message: 'Password reset successfully' };
  }

  @Post('verify-email')
  @Throttle({ default: { limit: 10, ttl: 300000 } })
  async verifyEmail(
    @Body('email') email: string,
    @Body('otp') otp: string,
  ): Promise<{ message: string }> {
    await this.authService.verifyEmailByEmail(email, otp); // ⬅️ no direct usersService reach
    return { message: 'Email verified successfully' };
  }

  @Post('resend-verification')
  @Throttle({ default: { limit: 3, ttl: 300000 } })
  async resendVerification(@Body('email') email: string): Promise<{ message: string }> {
    await this.authService.resendVerificationEmail(email);
    return {
      message: 'If the email exists and is not verified, a new verification code has been sent.',
    };
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  async getProfile(@CurrentUser() user: User): Promise<User> {
    return user;
  }
}
