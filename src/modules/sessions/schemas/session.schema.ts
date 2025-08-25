import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Types } from 'mongoose';
import type { HydratedDocument } from 'mongoose';
import * as mongooseLeanVirtuals from 'mongoose-lean-virtuals';

export type SessionDocument = HydratedDocument<Session>;

@Schema({
  timestamps: true,
  collection: 'sessions',
  versionKey: false,
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
})
export class Session {
  // Type-only fields so TS knows they exist; not part of schema definition
  id?: string;
  createdAt?: Date;
  updatedAt?: Date;

  @Prop({ type: Types.ObjectId, ref: 'User', required: true, index: true })
  userId!: Types.ObjectId;

  // never exposed by default
  @Prop({ required: true, select: false })
  hashedRefreshToken!: string;

  @Prop() ip?: string;
  @Prop() userAgent?: string;
  @Prop() deviceName?: string;

  @Prop({ default: Date.now })
  lastSeen?: Date;

  @Prop({ default: false })
  revoked!: boolean;

  @Prop() revokedAt?: Date;
  @Prop() revokedReason?: string;
}

export const SessionSchema = SchemaFactory.createForClass(Session);

// Helpful indexes
SessionSchema.index({ revoked: 1 });
SessionSchema.index({ createdAt: -1 });
SessionSchema.index({ lastSeen: -1 });

// TTL index for automatic cleanup of old sessions (30 days since last update)
SessionSchema.index({ updatedAt: 1 }, { expireAfterSeconds: 30 * 24 * 60 * 60 });

// Keep virtuals when using .lean()
SessionSchema.plugin(mongooseLeanVirtuals.default ?? mongooseLeanVirtuals);
