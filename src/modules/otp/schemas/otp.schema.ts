import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Types } from 'mongoose';
import type { HydratedDocument } from 'mongoose';
import { OtpType } from '../../../common/enums/otp-type.enum';
import * as mongooseLeanVirtuals from 'mongoose-lean-virtuals';

export type OtpDocument = HydratedDocument<Otp>;

@Schema({
  timestamps: true,
  collection: 'otps',
  versionKey: false,
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
})
export class Otp {
  // type-only convenience (not part of schema)
  id?: string;
  createdAt?: Date;
  updatedAt?: Date;

  @Prop({ type: Types.ObjectId, ref: 'User', required: true, index: true })
  userId!: Types.ObjectId;

  @Prop({ type: String, enum: OtpType, required: true })
  type!: OtpType;

  // never exposed by default
  @Prop({ required: true, select: false })
  codeHash!: string;

  @Prop({ required: true })
  expiresAt!: Date;

  @Prop({ default: false })
  used!: boolean;

  @Prop()
  usedAt?: Date;

  @Prop({ default: 0 })
  attempts!: number;
}

export const OtpSchema = SchemaFactory.createForClass(Otp);

// Indexes
OtpSchema.index({ userId: 1, type: 1 });
OtpSchema.index({ used: 1 });
OtpSchema.index({ createdAt: -1 });

// TTL index for automatic removal at `expiresAt`
OtpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Keep virtuals when using .lean()
OtpSchema.plugin(mongooseLeanVirtuals.default ?? mongooseLeanVirtuals);
