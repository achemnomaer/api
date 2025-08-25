import { IsString, IsArray, IsOptional, IsBoolean } from 'class-validator';

export class CreateRoleDto {
  @IsString()
  name!: string; // definite assignment

  @IsString()
  description!: string; // definite assignment

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  permissions?: string[];

  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}
