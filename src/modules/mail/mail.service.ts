import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectQueue } from '@nestjs/bull';
import { Queue } from 'bull';
import { User } from '../users/schemas/user.schema';

export interface EmailJob {
  to: string;
  subject: string;
  template: string;
  context: Record<string, any>;
}

@Injectable()
export class MailService {
  constructor(
    @InjectQueue('email') private emailQueue: Queue<EmailJob>,
    private configService: ConfigService,
  ) {}

  async sendEmailVerification(user: User, otp: string): Promise<void> {
    const job: EmailJob = {
      to: user.email,
      subject: 'Verify Your Email Address',
      template: 'email-verification',
      context: {
        firstName: user.firstName,
        lastName: user.lastName,
        otp,
        frontendUrl: this.configService.get<string>('FRONTEND_URL'),
      },
    };

    await this.emailQueue.add('send-email', job, {
      attempts: 3,
      backoff: { type: 'exponential', delay: 2000 },
    });
  }

  async sendWelcome(user: User): Promise<void> {
    const job: EmailJob = {
      to: user.email,
      subject: 'Welcome to Our Platform!',
      template: 'welcome',
      context: {
        firstName: user.firstName,
        lastName: user.lastName,
        frontendUrl: this.configService.get<string>('FRONTEND_URL'),
      },
    };

    await this.emailQueue.add('send-email', job, {
      attempts: 3,
      backoff: { type: 'exponential', delay: 2000 },
    });
  }

  async sendPasswordReset(user: User, otp: string): Promise<void> {
    const job: EmailJob = {
      to: user.email,
      subject: 'Reset Your Password',
      template: 'password-reset',
      context: {
        firstName: user.firstName,
        lastName: user.lastName,
        otp,
        frontendUrl: this.configService.get<string>('FRONTEND_URL'),
      },
    };

    await this.emailQueue.add('send-email', job, {
      attempts: 3,
      backoff: { type: 'exponential', delay: 2000 },
    });
  }

  async sendPasswordResetConfirmation(user: User): Promise<void> {
    const job: EmailJob = {
      to: user.email,
      subject: 'Password Reset Successful',
      template: 'password-reset-confirmation',
      context: {
        firstName: user.firstName,
        lastName: user.lastName,
        frontendUrl: this.configService.get<string>('FRONTEND_URL'),
      },
    };

    await this.emailQueue.add('send-email', job, {
      attempts: 3,
      backoff: { type: 'exponential', delay: 2000 },
    });
  }

  async sendPasswordChangeNotification(user: User): Promise<void> {
    const job: EmailJob = {
      to: user.email,
      subject: 'Password Changed Successfully',
      template: 'password-change-notification',
      context: {
        firstName: user.firstName,
        lastName: user.lastName,
        timestamp: new Date().toLocaleString(),
        frontendUrl: this.configService.get<string>('FRONTEND_URL'),
      },
    };

    await this.emailQueue.add('send-email', job, {
      attempts: 3,
      backoff: { type: 'exponential', delay: 2000 },
    });
  }

  async sendSessionRevocationAlert(user: User, sessionsRevoked: number): Promise<void> {
    const job: EmailJob = {
      to: user.email,
      subject: 'Security Alert: Sessions Revoked',
      template: 'session-revocation-alert',
      context: {
        firstName: user.firstName,
        lastName: user.lastName,
        sessionsRevoked,
        timestamp: new Date().toLocaleString(),
        frontendUrl: this.configService.get<string>('FRONTEND_URL'),
      },
    };

    await this.emailQueue.add('send-email', job, {
      attempts: 3,
      backoff: { type: 'exponential', delay: 2000 },
    });
  }

  async sendRoleChangeNotification(
    user: User,
    oldRoles: string[],
    newRoles: string[],
  ): Promise<void> {
    const job: EmailJob = {
      to: user.email,
      subject: 'Account Permissions Updated',
      template: 'role-change-notification',
      context: {
        firstName: user.firstName,
        lastName: user.lastName,
        oldRoles: oldRoles.join(', '),
        newRoles: newRoles.join(', '),
        timestamp: new Date().toLocaleString(),
        frontendUrl: this.configService.get<string>('FRONTEND_URL'),
      },
    };

    await this.emailQueue.add('send-email', job, {
      attempts: 3,
      backoff: { type: 'exponential', delay: 2000 },
    });
  }
}
