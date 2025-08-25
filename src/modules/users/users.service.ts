import {
  Injectable,
  ConflictException,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import { ConfigService } from '@nestjs/config';
import { User, UserDocument } from './schemas/user.schema';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserStatus } from '../../common/enums/user-status.enum';
import { AuthProvider } from '../../common/enums/auth-provider.enum';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private config: ConfigService,
  ) {}

  private toObjectId(id: string): Types.ObjectId {
    if (!Types.ObjectId.isValid(id)) {
      throw new BadRequestException('Invalid user id');
    }
    return new Types.ObjectId(id);
  }

  async create(dto: CreateUserDto): Promise<User> {
    const email = dto.email.toLowerCase();

    const exists = await this.userModel.exists({ email });
    if (exists) throw new ConflictException('User with this email already exists');

    let passwordHash: string | undefined;
    if (dto.password) {
      const rounds = this.config.get<number>('BCRYPT_ROUNDS', 12);
      passwordHash = await bcrypt.hash(dto.password, rounds);
    }

    const user = await this.userModel.create({
      ...dto,
      email,
      passwordHash,
      status: dto.status ?? UserStatus.PENDING,
      signupProvider: dto.signupProvider,
      linkedProviders: dto.linkedProviders ?? [],
    });

    return user;
  }

  async findAll(): Promise<User[]> {
    // If you don't need populated docs everywhere, consider returning lean + virtuals for perf:
    // return this.userModel.find().lean({ virtuals: true }).exec();
    return this.userModel.find().populate('roles').exec();
  }

  async findById(id: string): Promise<User | null> {
    return this.userModel.findById(this.toObjectId(id)).populate('roles').exec();
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.userModel.findOne({ email: email.toLowerCase() }).populate('roles').exec();
  }

  async findByGoogleId(googleId: string): Promise<User | null> {
    return this.userModel.findOne({ googleId }).populate('roles').exec();
  }

  async update(id: string, dto: UpdateUserDto): Promise<User> {
    const user = await this.userModel
      .findByIdAndUpdate(this.toObjectId(id), { $set: dto }, { new: true, runValidators: true })
      .populate('roles')
      .exec();

    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  async updatePassword(id: string, newPassword: string): Promise<void> {
    const rounds = this.config.get<number>('BCRYPT_ROUNDS', 12);
    const passwordHash = await bcrypt.hash(newPassword, rounds);

    const res = await this.userModel
      .updateOne({ _id: this.toObjectId(id) }, { $set: { passwordHash } })
      .exec();

    if (res.matchedCount === 0) throw new NotFoundException('User not found');
  }

  async verifyEmail(id: string): Promise<User> {
    const user = await this.userModel
      .findByIdAndUpdate(
        this.toObjectId(id),
        { $set: { isEmailVerified: true, status: UserStatus.ACTIVE } },
        { new: true },
      )
      .populate('roles')
      .exec();

    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  async updateLastLogin(id: string, ip: string): Promise<void> {
    await this.userModel
      .updateOne(
        { _id: this.toObjectId(id) },
        { $set: { lastLoginAt: new Date(), lastLoginIp: ip } },
      )
      .exec();
  }

  async assignRoles(userId: string, roleIds: string[]): Promise<User> {
    const objectIds = roleIds.map((rid) => this.toObjectId(rid));
    const user = await this.userModel
      .findByIdAndUpdate(this.toObjectId(userId), { $set: { roles: objectIds } }, { new: true })
      .populate('roles')
      .exec();

    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  async remove(id: string): Promise<void> {
    const res = await this.userModel.deleteOne({ _id: this.toObjectId(id) }).exec();
    if (res.deletedCount === 0) throw new NotFoundException('User not found');
  }

  /**
   * Use this for login flows — passwordHash is excluded by default, so select it explicitly.
   */
  async validatePasswordByEmail(email: string, password: string): Promise<null | User> {
    const doc = await this.userModel
      .findOne({ email: email.toLowerCase() })
      .select('+passwordHash') // override select:false
      .populate('roles')
      .exec();

    if (!doc?.passwordHash) return null;

    const ok = await bcrypt.compare(password, doc.passwordHash);
    return ok ? (doc as unknown as User) : null;
  }

  async linkProvider(userId: string, provider: AuthProvider): Promise<User> {
    const user = await this.userModel
      .findByIdAndUpdate(
        this.toObjectId(userId),
        { $addToSet: { linkedProviders: provider } },
        { new: true }
      )
      .populate('roles')
      .exec();

    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  async unlinkProvider(userId: string, provider: AuthProvider): Promise<User> {
    const user = await this.userModel.findById(this.toObjectId(userId)).exec();
    if (!user) throw new NotFoundException('User not found');

    // Safety check: don't allow unlinking if it's the only way to login
    if (user.linkedProviders.length <= 1) {
      throw new BadRequestException('Cannot unlink the only authentication method');
    }

    // Additional safety: if unlinking email, must have password set
    if (provider === AuthProvider.EMAIL && !user.passwordHash) {
      throw new BadRequestException('Cannot unlink email without a password set');
    }

    // Additional safety: if unlinking Google, must have email verified
    if (provider === AuthProvider.GOOGLE && !user.isEmailVerified) {
      throw new BadRequestException('Cannot unlink Google without verified email');
    }

    const updatedUser = await this.userModel
      .findByIdAndUpdate(
        this.toObjectId(userId),
        { $pull: { linkedProviders: provider } },
        { new: true }
      )
      .populate('roles')
      .exec();

    return updatedUser!;
  }

  async setPassword(userId: string, password: string): Promise<User> {
    const rounds = this.config.get<number>('BCRYPT_ROUNDS', 12);
    const passwordHash = await bcrypt.hash(password, rounds);

    const user = await this.userModel
      .findByIdAndUpdate(
        this.toObjectId(userId),
        { 
          $set: { passwordHash },
          $addToSet: { linkedProviders: AuthProvider.EMAIL }
        },
        { new: true }
      )
      .populate('roles')
      .exec();

    if (!user) throw new NotFoundException('User not found');
    return user;
  }
}
