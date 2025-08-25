import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../../users/users.service';
import { JwtPayload } from '../../../common/interfaces/jwt-payload.interface';
import { User } from '../../users/schemas/user.schema';
import { AuthAudience } from '../../../common/enums/auth-provider.enum';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private usersService: UsersService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_ACCESS_SECRET'),
    });
  }

  async validate(payload: JwtPayload): Promise<User> {
    // Verify JWT claims
    if (!payload.aud || !payload.iss || !payload.jti) {
      throw new UnauthorizedException('Invalid token claims');
    }

    if (payload.iss !== 'education-consultancy-api') {
      throw new UnauthorizedException('Invalid token issuer');
    }

    if (!Object.values(AuthAudience).includes(payload.aud as AuthAudience)) {
      throw new UnauthorizedException('Invalid token audience');
    }

    const user = await this.usersService.findById(payload.sub);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Store audience in user object for later use
    (user as any).tokenAudience = payload.aud;
    
    return user;
  }
}