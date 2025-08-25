import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Types } from 'mongoose';
import { UserStatus } from '../../../common/enums/user-status.enum';
import { AuthProvider } from '../../../common/enums/auth-provider.enum';
import * as mongooseLeanVirtuals from 'mongoose-lean-virtuals';
import type { HydratedDocument } from 'mongoose';

export type UserDocument = HydratedDocument<User>;

@Schema({
  timestamps: true,
  collection: 'users',
  versionKey: false,
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
})
export class User {
  // Type-only convenience fields (NOT part of the schema)
  id?: string;
  createdAt?: Date;
  updatedAt?: Date;

  @Prop({ required: true, unique: true, lowercase: true, trim: true, index: true })
  email!: string;

  // Never selected by default
  @Prop({ select: false })
  passwordHash?: string;

  @Prop({ required: true, trim: true })
  firstName!: string;

  @Prop({ required: true, trim: true })
  lastName!: string;

  @Prop({ type: [{ type: Types.ObjectId, ref: 'Role' }], default: [] })
  roles!: Types.ObjectId[];

  @Prop({ type: String, enum: UserStatus, default: UserStatus.PENDING })
  status!: UserStatus;

  @Prop({ default: false })
  isEmailVerified!: boolean;

  @Prop({ type: String, enum: AuthProvider })
  signupProvider?: AuthProvider;

  @Prop({ type: [String], enum: AuthProvider, default: [] })
  linkedProviders!: AuthProvider[];

  @Prop() googleId?: string;
  @Prop() avatar?: string;
  @Prop() phone?: string;

  @Prop() lastLoginAt?: Date;
  @Prop() lastLoginIp?: string;
}

export const UserSchema = SchemaFactory.createForClass(User);

// Nice-to-have virtual
UserSchema.virtual('fullName').get(function (this: any) {
  return `${this.firstName ?? ''} ${this.lastName ?? ''}`.trim();
});

// Keep virtuals when using .lean()
UserSchema.plugin(mongooseLeanVirtuals.default ?? mongooseLeanVirtuals);

// Helpful indexes (email already has index/unique)
UserSchema.index({ status: 1 });
UserSchema.index({ createdAt: -1 });
