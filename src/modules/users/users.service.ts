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
      .exec();

    if (!doc?.passwordHash) return null;

    const ok = await bcrypt.compare(password, doc.passwordHash);
    return ok ? (doc as unknown as User) : null;
  }
}
