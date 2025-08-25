import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import type { HydratedDocument } from 'mongoose';
import * as mongooseLeanVirtuals from 'mongoose-lean-virtuals';

export type RoleDocument = HydratedDocument<Role>;

@Schema({
  timestamps: true,
  collection: 'roles',
  versionKey: false,
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
})
export class Role {
  // Type-only convenience (not part of schema)
  id?: string;
  createdAt?: Date;
  updatedAt?: Date;

  @Prop({ required: true, unique: true, trim: true, lowercase: true, index: true })
  name!: string;

  @Prop({ required: true, trim: true })
  description!: string;

  @Prop({ type: [String], default: [] })
  permissions!: string[];

  @Prop({ default: true })
  isActive!: boolean;
}

export const RoleSchema = SchemaFactory.createForClass(Role);

// Helpful indexes
RoleSchema.index({ isActive: 1 });

// Keep virtuals on .lean()
RoleSchema.plugin(mongooseLeanVirtuals.default ?? mongooseLeanVirtuals);
