import { Controller, Get, Delete, Param, UseGuards, Post } from '@nestjs/common';
import { Permissions } from '../../common/decorators/permissions.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { SessionsService } from './sessions.service';
import { Session } from './schemas/session.schema';

@Controller('sessions')
export class SessionsController {
  constructor(private readonly sessionsService: SessionsService) {}

  @Get('my')
  async getMySessions(@CurrentUser('id') userId: string): Promise<Session[]> {
    return this.sessionsService.getUserSessions(userId);
  }

  @Get('user/:userId')
  @Permissions('users:read')
  async getUserSessions(@Param('userId') userId: string): Promise<Session[]> {
    return this.sessionsService.getUserSessionsWithRevoked(userId);
  }

  @Delete('my/:sessionId')
  async revokeMySession(
    @CurrentUser('id') userId: string,
    @Param('sessionId') sessionId: string,
  ): Promise<void> {
    // Verify session belongs to user before revoking
    const sessions = await this.sessionsService.getUserSessions(userId);
    const sessionExists = sessions.some((session) => session.id === sessionId);

    if (sessionExists) {
      await this.sessionsService.revokeSession(sessionId, 'User revoked');
    }
  }

  @Delete('my/all')
  async revokeAllMySessions(@CurrentUser('id') userId: string): Promise<void> {
    await this.sessionsService.revokeAllUserSessions(userId, 'User revoked all');
  }

  @Delete('user/:userId/all')
  @Permissions('users:write')
  async revokeAllUserSessions(@Param('userId') userId: string): Promise<void> {
    await this.sessionsService.revokeAllUserSessions(userId, 'Admin revoked all');
  }

  @Get('stats')
  @Permissions('system:audit')
  async getStats(): Promise<{ total: number; active: number; revoked: number }> {
    return this.sessionsService.getSessionStats();
  }

  @Post('cleanup')
  @Permissions('system:audit')
  async cleanupSessions(): Promise<{ deletedCount: number }> {
    const deletedCount = await this.sessionsService.cleanupExpiredSessions();
    return { deletedCount };
  }
}
