import { IsEmail, IsString, MinLength } from 'class-validator';

export class ResetPasswordRequestDto {
  @IsEmail()
  email!: string;
}

export class ResetPasswordDto {
  @IsEmail()
  email!: string;

  @IsString()
  otp!: string;

  @IsString()
  @MinLength(8)
  newPassword!: string;
}
