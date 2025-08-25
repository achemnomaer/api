import { IsEnum } from 'class-validator';
import { AuthProvider } from '../../../common/enums/auth-provider.enum';

export class LinkProviderDto {
  @IsEnum(AuthProvider)
  provider!: AuthProvider;
}