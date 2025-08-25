import { Controller, Get, Query, Post, Delete, Param } from '@nestjs/common';
import { Permissions } from '../../common/decorators/permissions.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { AuditService, AuditLogQuery } from './audit.service';
import { AuditLog } from './schemas/audit-log.schema';
import { AuditAction } from '../../common/enums/audit-action.enum';

@Controller('audit')
export class AuditController {
  constructor(private readonly auditService: AuditService) {}

  @Get('logs')
  @Permissions('system:audit')
  async getLogs(
    @Query('actorId') actorId?: string,
    @Query('action') action?: AuditAction,
    @Query('resource') resource?: string,
    @Query('resourceId') resourceId?: string,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('page') page?: string,
    @Query('limit') limit?: string,
  ): Promise<{
    logs: AuditLog[];
    total: number;
    page: number;
    pages: number;
  }> {
    const query: AuditLogQuery = {};
    if (actorId) query.actorId = actorId;
    if (action) query.action = action;
    if (resource) query.resource = resource;
    if (resourceId) query.resourceId = resourceId;
    if (startDate) query.startDate = new Date(startDate);
    if (endDate) query.endDate = new Date(endDate);
    if (page) query.page = parseInt(page, 10);
    if (limit) query.limit = parseInt(limit, 10);

    return this.auditService.findLogs(query);
  }

  @Get('my-activity')
  async getMyActivity(
    @CurrentUser('id') userId: string, // ⬅️ was '_id'
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('limit') limit?: string,
  ): Promise<AuditLog[]> {
    return this.auditService.getUserActivity(
      userId,
      startDate ? new Date(startDate) : undefined,
      endDate ? new Date(endDate) : undefined,
      limit ? parseInt(limit, 10) : undefined,
    );
  }

  @Get('user-activity/:userId')
  @Permissions('system:audit')
  async getUserActivity(
    @Param('userId') userId: string, // ⬅️ was @Query
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('limit') limit?: string,
  ): Promise<AuditLog[]> {
    return this.auditService.getUserActivity(
      userId,
      startDate ? new Date(startDate) : undefined,
      endDate ? new Date(endDate) : undefined,
      limit ? parseInt(limit, 10) : undefined,
    );
  }

  @Get('resource-activity')
  @Permissions('system:audit')
  async getResourceActivity(
    @Query('resource') resource: string,
    @Query('resourceId') resourceId?: string,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('limit') limit?: string,
  ): Promise<AuditLog[]> {
    return this.auditService.getResourceActivity(
      resource,
      resourceId,
      startDate ? new Date(startDate) : undefined,
      endDate ? new Date(endDate) : undefined,
      limit ? parseInt(limit, 10) : undefined,
    );
  }

  @Get('stats')
  @Permissions('system:audit')
  async getStats(
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
  ): Promise<{
    totalLogs: number;
    actionBreakdown: { action: AuditAction; count: number }[];
    resourceBreakdown: { resource: string; count: number }[];
    topActors: { actor: any; count: number }[];
  }> {
    return this.auditService.getAuditStats(
      startDate ? new Date(startDate) : undefined,
      endDate ? new Date(endDate) : undefined,
    );
  }

  @Post('cleanup')
  @Permissions('system:audit')
  async cleanupLogs(
    @Query('olderThanDays') olderThanDays?: string,
  ): Promise<{ deletedCount: number }> {
    const days = olderThanDays ? parseInt(olderThanDays, 10) : 730;
    const deletedCount = await this.auditService.cleanupOldLogs(days);
    return { deletedCount };
  }
}
