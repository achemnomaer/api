import { IsEmail, IsString, IsOptional, MinLength, IsEnum } from 'class-validator';
import { UserStatus } from '../../../common/enums/user-status.enum';

export class CreateUserDto {
  @IsEmail()
  email!: string;

  @IsString()
  @MinLength(8)
  @IsOptional()
  password?: string;

  @IsString()
  firstName!: string;

  @IsString()
  lastName!: string;

  @IsOptional()
  @IsEnum(UserStatus)
  status?: UserStatus;

  @IsOptional()
  @IsString()
  phone?: string;

  @IsOptional()
  @IsString()
  googleId?: string;

  @IsOptional()
  @IsString()
  avatar?: string;
}
