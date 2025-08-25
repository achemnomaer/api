import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { AuditLog, AuditLogDocument } from './schemas/audit-log.schema';
import { AuditAction } from '../../common/enums/audit-action.enum';

export interface AuditLogData {
  actorId: string;
  action: AuditAction;
  resource: string;
  resourceId: string;
  meta?: Record<string, any>;
  changes?: {
    before?: Record<string, any>;
    after?: Record<string, any>;
  };
}

export interface AuditLogQuery {
  actorId?: string;
  action?: AuditAction;
  resource?: string;
  resourceId?: string;
  startDate?: Date;
  endDate?: Date;
  page?: number;
  limit?: number;
}

@Injectable()
export class AuditService {
  constructor(@InjectModel(AuditLog.name) private auditLogModel: Model<AuditLogDocument>) {}

  private toObjectId(id: string): Types.ObjectId {
    if (!Types.ObjectId.isValid(id)) throw new BadRequestException('Invalid id');
    return new Types.ObjectId(id);
  }

  async log(data: AuditLogData): Promise<AuditLog> {
    const auditLog = await this.auditLogModel.create({
      actorId: this.toObjectId(data.actorId),
      action: data.action,
      resource: data.resource,
      resourceId: data.resourceId,
      meta: data.meta ?? {},
      changes: data.changes,
      timestamp: new Date(),
    });
    return auditLog;
  }

  async findLogs(query: AuditLogQuery = {}): Promise<{
    logs: AuditLog[];
    total: number;
    page: number;
    pages: number;
  }> {
    const {
      actorId,
      action,
      resource,
      resourceId,
      startDate,
      endDate,
      page = 1,
      limit = 50,
    } = query;

    const filter: any = {};
    if (actorId) filter.actorId = this.toObjectId(actorId);
    if (action) filter.action = action;
    if (resource) filter.resource = resource;
    if (resourceId) filter.resourceId = resourceId;
    if (startDate || endDate) {
      filter.timestamp = {};
      if (startDate) filter.timestamp.$gte = startDate;
      if (endDate) filter.timestamp.$lte = endDate;
    }

    const skip = (page - 1) * limit;

    const [logs, total] = await Promise.all([
      this.auditLogModel
        .find(filter)
        .populate('actorId', 'firstName lastName email')
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(limit)
        .exec(),
      this.auditLogModel.countDocuments(filter).exec(),
    ]);

    return { logs, total, page, pages: Math.ceil(total / limit) };
  }

  async getUserActivity(
    userId: string,
    startDate?: Date,
    endDate?: Date,
    limit: number = 100,
  ): Promise<AuditLog[]> {
    const filter: any = { actorId: this.toObjectId(userId) };
    if (startDate || endDate) {
      filter.timestamp = {};
      if (startDate) filter.timestamp.$gte = startDate;
      if (endDate) filter.timestamp.$lte = endDate;
    }
    return this.auditLogModel.find(filter).sort({ timestamp: -1 }).limit(limit).exec();
  }

  async getResourceActivity(
    resource: string,
    resourceId?: string,
    startDate?: Date,
    endDate?: Date,
    limit: number = 100,
  ): Promise<AuditLog[]> {
    const filter: any = { resource };
    if (resourceId) filter.resourceId = resourceId;
    if (startDate || endDate) {
      filter.timestamp = {};
      if (startDate) filter.timestamp.$gte = startDate;
      if (endDate) filter.timestamp.$lte = endDate;
    }
    return this.auditLogModel
      .find(filter)
      .populate('actorId', 'firstName lastName email')
      .sort({ timestamp: -1 })
      .limit(limit)
      .exec();
  }

  async getAuditStats(
    startDate?: Date,
    endDate?: Date,
  ): Promise<{
    totalLogs: number;
    actionBreakdown: { action: AuditAction; count: number }[];
    resourceBreakdown: { resource: string; count: number }[];
    topActors: { actor: any; count: number }[];
  }> {
    const matchStage: any = {};
    if (startDate || endDate) {
      matchStage.timestamp = {};
      if (startDate) matchStage.timestamp.$gte = startDate;
      if (endDate) matchStage.timestamp.$lte = endDate;
    }

    const [actionBreakdown, resourceBreakdown, topActors, totalLogs] = await Promise.all([
      this.auditLogModel
        .aggregate([
          { $match: matchStage },
          { $group: { _id: '$action', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
          { $project: { action: '$_id', count: 1, _id: 0 } },
        ])
        .exec(),

      this.auditLogModel
        .aggregate([
          { $match: matchStage },
          { $group: { _id: '$resource', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
          { $project: { resource: '$_id', count: 1, _id: 0 } },
        ])
        .exec(),

      this.auditLogModel
        .aggregate([
          { $match: matchStage },
          { $group: { _id: '$actorId', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
          { $limit: 10 },
          {
            $lookup: {
              from: 'users',
              localField: '_id',
              foreignField: '_id',
              as: 'actor',
            },
          },
          { $unwind: '$actor' },
          {
            $project: {
              actor: {
                id: '$actor._id',
                firstName: '$actor.firstName',
                lastName: '$actor.lastName',
                email: '$actor.email',
              },
              count: 1,
              _id: 0,
            },
          },
        ])
        .exec(),

      this.auditLogModel.countDocuments(matchStage).exec(),
    ]);

    return { totalLogs, actionBreakdown, resourceBreakdown, topActors };
  }

  async cleanupOldLogs(olderThanDays: number = 730): Promise<number> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);

    const res = await this.auditLogModel.deleteMany({ timestamp: { $lt: cutoffDate } }).exec();

    return res.deletedCount ?? 0;
  }
}
