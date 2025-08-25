import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Types } from 'mongoose';
import type { HydratedDocument } from 'mongoose';
import { AuditAction } from '../../../common/enums/audit-action.enum';
import * as mongooseLeanVirtuals from 'mongoose-lean-virtuals';

export type AuditLogDocument = HydratedDocument<AuditLog>;

@Schema({
  timestamps: true, // adds createdAt/updatedAt
  collection: 'audit_logs',
  versionKey: false,
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
})
export class AuditLog {
  // type-only conveniences (not schema fields)
  id?: string;
  createdAt?: Date;
  updatedAt?: Date;

  @Prop({ type: Types.ObjectId, ref: 'User', required: true, index: true })
  actorId!: Types.ObjectId;

  @Prop({ type: String, enum: AuditAction, required: true, index: true })
  action!: AuditAction;

  @Prop({ required: true, index: true })
  resource!: string;

  @Prop({ required: true, index: true })
  resourceId!: string;

  @Prop({ type: Object, default: {} })
  meta!: Record<string, any>;

  @Prop({ type: Object })
  changes?: {
    before?: Record<string, any>;
    after?: Record<string, any>;
  };

  // event time (separate from createdAt). Optional at type-level since default exists.
  @Prop({ default: Date.now })
  timestamp?: Date;
}

export const AuditLogSchema = SchemaFactory.createForClass(AuditLog);

// Helpful indexes
AuditLogSchema.index({ actorId: 1, timestamp: -1 });
AuditLogSchema.index({ action: 1, timestamp: -1 });
AuditLogSchema.index({ resource: 1, resourceId: 1, timestamp: -1 });
AuditLogSchema.index({ timestamp: -1 });

// TTL (keep for 2 years)
AuditLogSchema.index({ timestamp: 1 }, { expireAfterSeconds: 2 * 365 * 24 * 60 * 60 });

// Keep virtuals with .lean()
AuditLogSchema.plugin(mongooseLeanVirtuals.default ?? mongooseLeanVirtuals);
