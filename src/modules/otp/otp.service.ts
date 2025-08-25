import { Injectable, BadRequestException, HttpException, HttpStatus } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import * as crypto from 'crypto';
import { Otp, OtpDocument } from './schemas/otp.schema';
import { OtpType } from '../../common/enums/otp-type.enum';

@Injectable()
export class OtpService {
  private readonly OTP_LENGTH = 6;
  private readonly OTP_EXPIRY_MINUTES = 15;
  private readonly MAX_ATTEMPTS = 3;
  private readonly RATE_LIMIT_MINUTES = 5;
  private readonly RATE_LIMIT_MAX_REQUESTS = 3;

  constructor(@InjectModel(Otp.name) private otpModel: Model<OtpDocument>) {}

  private toObjectId(id: string): Types.ObjectId {
    if (!Types.ObjectId.isValid(id)) {
      throw new BadRequestException('Invalid id');
    }
    return new Types.ObjectId(id);
  }

  async generateOtp(userId: string, type: OtpType): Promise<{ otp: string; id: string }> {
    // Rate limit
    await this.checkRateLimit(userId, type);

    // Invalidate any existing active OTPs of the same type
    await this.otpModel.updateMany(
      {
        userId: this.toObjectId(userId),
        type,
        used: false,
      },
      { $set: { used: true, usedAt: new Date() } },
    );

    // Generate & hash OTP
    const otp = this.generateRandomOtp();
    const codeHash = crypto.createHash('sha256').update(otp).digest('hex');

    const expiresAt = new Date(Date.now() + this.OTP_EXPIRY_MINUTES * 60 * 1000);

    const saved = await this.otpModel.create({
      userId: this.toObjectId(userId),
      type,
      codeHash,
      expiresAt,
      used: false,
      attempts: 0,
    });

    // HydratedDocument has _id typed; cast to string safely
    return { otp, id: String(saved._id) };
  }

  async verifyOtp(userId: string, type: OtpType, code: string): Promise<boolean> {
    const codeHash = crypto.createHash('sha256').update(code).digest('hex');

    const otpDoc = await this.otpModel.findOne({
      userId: this.toObjectId(userId),
      type,
      codeHash,
      used: false,
      expiresAt: { $gt: new Date() },
    });

    if (!otpDoc) {
      // Increment attempts for any still-active OTP of this type
      await this.otpModel.updateMany(
        {
          userId: this.toObjectId(userId),
          type,
          used: false,
          expiresAt: { $gt: new Date() },
        },
        { $inc: { attempts: 1 } },
      );

      // If any active OTP reached max attempts, invalidate them
      const exceeded = await this.otpModel.findOne({
        userId: this.toObjectId(userId),
        type,
        used: false,
        attempts: { $gte: this.MAX_ATTEMPTS },
      });

      if (exceeded) {
        await this.otpModel.updateMany(
          { userId: this.toObjectId(userId), type, used: false },
          { $set: { used: true, usedAt: new Date() } },
        );
        throw new BadRequestException('OTP invalid due to too many attempts');
      }

      return false;
    }

    // Mark as used
    otpDoc.used = true;
    otpDoc.usedAt = new Date();
    await otpDoc.save(); // timestamps will update updatedAt

    return true;
  }

  async invalidateUserOtps(userId: string, type?: OtpType): Promise<void> {
    const query: Record<string, any> = {
      userId: this.toObjectId(userId),
      used: false,
    };
    if (type) query.type = type;

    await this.otpModel.updateMany(query, { $set: { used: true, usedAt: new Date() } });
  }

  private generateRandomOtp(): string {
    // cryptographically stronger approach (optional)
    let otp = '';
    for (let i = 0; i < this.OTP_LENGTH; i++) {
      otp += Math.floor(Math.random() * 10).toString();
    }
    return otp;
  }

  private async checkRateLimit(userId: string, type: OtpType): Promise<void> {
    const since = new Date(Date.now() - this.RATE_LIMIT_MINUTES * 60 * 1000);

    const recentCount = await this.otpModel.countDocuments({
      userId: this.toObjectId(userId),
      type,
      createdAt: { $gte: since },
    });

    if (recentCount >= this.RATE_LIMIT_MAX_REQUESTS) {
      // Use HttpException 429 to support older Nest versions that lack TooManyRequestsException
      throw new HttpException(
        `Too many OTP requests. Please wait ${this.RATE_LIMIT_MINUTES} minutes.`,
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }

  async cleanupExpiredOtps(): Promise<number> {
    const res = await this.otpModel
      .deleteMany({
        $or: [
          { expiresAt: { $lt: new Date() } },
          { used: true, usedAt: { $lt: new Date(Date.now() - 24 * 60 * 60 * 1000) } },
        ],
      })
      .exec();

    return res.deletedCount ?? 0;
  }

  async getOtpStats(): Promise<{
    total: number;
    active: number;
    expired: number;
    used: number;
  }> {
    const now = new Date();
    const [total, active, expired, used] = await Promise.all([
      this.otpModel.countDocuments({}).exec(),
      this.otpModel.countDocuments({ used: false, expiresAt: { $gt: now } }).exec(),
      this.otpModel.countDocuments({ used: false, expiresAt: { $lte: now } }).exec(),
      this.otpModel.countDocuments({ used: true }).exec(),
    ]);

    return { total, active, expired, used };
  }
}
