import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    config: ConfigService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: config.get('JWT_ACCESS_TOKEN_SECRET'),
    });
  }

  async validate(payload: any) {
    // console.log(payload)
    //if it decodes succesfully then we return user no database checking here
    //but if it fails nko, we then get refresh token from database and compare with the cookie one
    //if it matches we return use and update
    //console.log(payload)
    //return null

    return { userId: payload.sub, email: payload.email };
  }
}
