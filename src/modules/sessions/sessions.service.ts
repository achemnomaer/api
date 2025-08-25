import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import * as crypto from 'crypto';
import { Session, SessionDocument } from './schemas/session.schema';

@Injectable()
export class SessionsService {
  constructor(@InjectModel(Session.name) private sessionModel: Model<SessionDocument>) {}

  private toObjectId(id: string): Types.ObjectId {
    if (!Types.ObjectId.isValid(id)) {
      throw new BadRequestException('Invalid id');
    }
    return new Types.ObjectId(id);
  }

  async createSession(
    userId: string,
    refreshToken: string,
    ip: string,
    userAgent: string,
    deviceName?: string,
  ): Promise<Session> {
    const hashedRefreshToken = crypto.createHash('sha256').update(refreshToken).digest('hex');

    const session = await this.sessionModel.create({
      userId: this.toObjectId(userId),
      hashedRefreshToken,
      ip,
      userAgent,
      deviceName,
      lastSeen: new Date(),
    });

    return session;
  }

  async validateRefreshToken(refreshToken: string, sessionId: string): Promise<Session | null> {
    const hashedToken = crypto.createHash('sha256').update(refreshToken).digest('hex');

    const session = await this.sessionModel
      .findOne({
        _id: this.toObjectId(sessionId),
        hashedRefreshToken: hashedToken,
        revoked: false,
      })
      .populate('userId')
      .exec();

    if (!session) {
      // Potential token reuse - revoke all sessions for this user
      const suspicious = await this.sessionModel.findById(this.toObjectId(sessionId)).exec();
      if (suspicious) {
        await this.revokeAllUserSessions(
          String(suspicious.userId), 
          'Token reuse detected - security breach'
        );
        throw new UnauthorizedException('Token reuse detected. All sessions revoked.');
      }
      return null;
    }

    // Update last seen (timestamps will refresh updatedAt)
    session.lastSeen = new Date();
    await session.save();

    return session;
  }

  async rotateRefreshToken(sessionId: string, newRefreshToken: string): Promise<Session | null> {
    const hashedToken = crypto.createHash('sha256').update(newRefreshToken).digest('hex');

    const session = await this.sessionModel
      .findByIdAndUpdate(
        this.toObjectId(sessionId),
        { $set: { hashedRefreshToken: hashedToken, lastSeen: new Date() } },
        { new: true },
      )
      .exec();

    return session;
  }

  async revokeSession(sessionId: string, reason?: string): Promise<void> {
    await this.sessionModel
      .updateOne(
        { _id: this.toObjectId(sessionId) },
        { $set: { revoked: true, revokedAt: new Date(), revokedReason: reason } },
      )
      .exec();
  }

  async revokeAllUserSessions(userId: string, reason = 'User initiated'): Promise<void> {
    await this.sessionModel
      .updateMany(
        { userId: this.toObjectId(userId), revoked: false },
        { $set: { revoked: true, revokedAt: new Date(), revokedReason: reason } },
      )
      .exec();
  }

  async getUserSessions(userId: string): Promise<Session[]> {
    return this.sessionModel
      .find({ userId: this.toObjectId(userId), revoked: false })
      .sort({ lastSeen: -1 })
      .exec();
    // If you prefer lean:
    // .lean({ virtuals: true }).exec();
  }

  async getUserSessionsWithRevoked(userId: string): Promise<Session[]> {
    return this.sessionModel
      .find({ userId: this.toObjectId(userId) })
      .sort({ lastSeen: -1 })
      .exec();
    // Or lean({ virtuals: true })
  }

  async cleanupExpiredSessions(): Promise<number> {
    // This endpoint is optional since you also have a TTL on updatedAt.
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

    const res = await this.sessionModel
      .deleteMany({
        $or: [
          { updatedAt: { $lt: thirtyDaysAgo } },
          { revoked: true, revokedAt: { $lt: thirtyDaysAgo } },
        ],
      })
      .exec();

    return res.deletedCount ?? 0;
  }

  async getSessionStats(
    userId?: string,
  ): Promise<{ total: number; active: number; revoked: number }> {
    const query = userId ? { userId: this.toObjectId(userId) } : {};

    const [total, active, revoked] = await Promise.all([
      this.sessionModel.countDocuments(query),
      this.sessionModel.countDocuments({ ...query, revoked: false }),
      this.sessionModel.countDocuments({ ...query, revoked: true }),
    ]);

    return { total, active, revoked };
  }
}
