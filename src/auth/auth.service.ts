import {
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
  Req,
  Res,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { ITokenPayload } from './interfaces/ITokenPayload';
import { AuthProviderDto } from './dto/auth-provider.dto';

//const prisma = new PrismaClient()

const JWT_ACCESS_TOKEN_EXPIRATION_TIME = '5s';
const JWT_REFRESH_TOKEN_EXPIRATION_TIME = '1d';
const ACCESS_TOKEN_EXPIRY = 30 * 1000;
@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async signup(dto: AuthDto) {
    const password = await argon.hash(dto.password);
    try {
      const user = await this.prismaService.user.create({
        data: {
          email: dto.email,
          password,
        },
      });

   return  await this.handeleSigin(user)
   
    } catch (err) {
      if (err instanceof PrismaClientKnownRequestError) {
        if (err.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw err;
    }
  }

  async signIn(dto: AuthDto) {
    //find a user
    // await return this.handeleSigin(user)
    const user = await this.prismaService.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    //if the there is no user throw exception
    if (!user) {
      throw new ForbiddenException('Credentials incorrect');
    }

    if (user.password == null) {
      //this email didn't sign in using form
      //here i send a mail explaining the situation
      throw new ForbiddenException(
        'Credentilas incorrect or this email was gotten from a social account',
      );
    }
    // compare password
    const isMatch = await argon.verify(user.password, dto.password);

    if (!isMatch) {
      throw new ForbiddenException('Credentilas incorrect');
    }

    return await this.handeleSigin(user);
  }

  async handeleSigin(user: any) {
    const { refreshToken } = await this.getJwtRefreshToken(
      user.id,
      user?.email,
    );
    const { accessToken } = await this.getJwtAccessToken(user.id, user?.email);

    const hashed = await argon.hash(refreshToken);

    try {
      await this.prismaService.user.update({
        data: {
          currentHashedRefreshToken: hashed,
        },
        where: {
          id: user.id,
        },
      });
    } catch (error) {
      console.log(error);
    }

    return {
      accessToken,
      refreshToken,
      accessTokenExpires: Date.now() + ACCESS_TOKEN_EXPIRY,
      user: {
        id: user.id,
        email: user.email,
      },
    };
  }
  async signInWithOAuth(dto: AuthProviderDto) {
    
    const account = await this.prismaService.provider.findFirst({
      where: {
        provider_id: dto.id,
        provider_name: dto.provider,
      },
    });

    if (account) {
      const user = await this.prismaService.user.findFirst({
        where: {
          id: account.userId,
        },
      });
      return user;
    } else {
      let user: any = {};
      user = await this.prismaService.user.findFirst({
        where: {
          email: dto.email,
        },
      });
      if (!user) {
        //here i create a new user
        const user = await this.prismaService.user.create({
          data: {
            email: dto.email,
            lastName: dto.lastName,
            firstName: dto.firstName,
            provider: {
              create: {
                provider_id: dto.id,
                provider_name: dto.provider,
              },
            },
          },
        });
        return user;
      } else {
        await this.prismaService.provider.create({
          data: {
            provider_id: dto.id,
            provider_name: dto.provider,
            userId: user?.id,
          },
        });
        return user;
      }
    }
  }

  
  async getById(id: number) {
    const user = await this.prismaService.user.findFirst({
      where: {
        id,
      },
    });
    if (user) {
      return user;
    }
    throw new HttpException(
      'User with this id does not exist',
      HttpStatus.NOT_FOUND,
    );
  }

  async getByEmail(email: string) {
    const user = await this.prismaService.user.findFirst({
      where: {
        email,
      },
    });
    if (user) {
      return user;
    }
    throw new HttpException(
      'User with this id does not exist',
      HttpStatus.NOT_FOUND,
    );
  }

  async getUserIfRefreshTokenMatches(refreshToken: string, userId: number) {
    const user = await this.getById(userId);
    const isRefreshTokenMatching = await argon.verify(
      user.currentHashedRefreshToken,
      refreshToken,
    );

    if (isRefreshTokenMatching) {
      //then we issue a new accesstoken here
      const { accessToken } = await this.getJwtAccessToken(user.id, user.email);
      return {
        accessToken,
        refreshToken,
        accessTokenExpires: Date.now() + ACCESS_TOKEN_EXPIRY,
        user: {
          id: user.id,
          email: user.email,
        },
      };
    }
  }

  async getAuthenticatedUser(email: string, plainTextPassword: string) {
    try {
      const user = await this.prismaService.user.findFirst({
        where: {
          email,
        },
      });
      await this.verifyPassword(plainTextPassword, user.password);
      return user;
    } catch (error) {
      throw new HttpException(
        'Wrong credentials provided',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  async getCookieWithJwtAccessToken(
    sub: number,
    email: string,
    isSecondFactorAuthenticated = false,
  ) {
    const payload: ITokenPayload = { sub, email, isSecondFactorAuthenticated };

    const token = await this.jwtService.signAsync(payload, {
      secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
      expiresIn: JWT_ACCESS_TOKEN_EXPIRATION_TIME,
    });

    const cookie = `Authentication=${token}; HttpOnly; Path=/; Max-Age=${JWT_ACCESS_TOKEN_EXPIRATION_TIME}`;
    //todo only in middlewware
    return {
      token,
      cookie,
    };
  }

  public getCookieWithJwtRefreshToken(sub: number, email: string) {
    const payload: ITokenPayload = { sub, email };
    const token = this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
      expiresIn: JWT_REFRESH_TOKEN_EXPIRATION_TIME,
    });
    const cookie = `Refresh=${token}; HttpOnly; Path=/; Max-Age=${JWT_REFRESH_TOKEN_EXPIRATION_TIME}`;
    return {
      cookie,
      token,
    };
  }

  public async getJwtRefreshToken(sub: number, email: string) {
    const payload: ITokenPayload = { sub, email };
    const refreshToken = await this.jwtService.signAsync(payload, {
      secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
      expiresIn: JWT_REFRESH_TOKEN_EXPIRATION_TIME,
    });
    return {
      refreshToken,
    };
  }

  async getJwtAccessToken(
    sub: number,
    email?: string,
    isSecondFactorAuthenticated = false,
  ) {
    const payload: ITokenPayload = { sub, email, isSecondFactorAuthenticated };
    const accessToken = await this.jwtService.signAsync(payload, {
      secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
      expiresIn: JWT_ACCESS_TOKEN_EXPIRATION_TIME,
    });
    return {
      accessToken,
    };
  }

  private async verifyPassword(
    plainTextPassword: string,
    hashedPassword: string,
  ) {
    const isPasswordMatching = await argon.verify(
      plainTextPassword,
      hashedPassword,
    );
    if (!isPasswordMatching) {
      throw new HttpException(
        'Wrong credentials provided',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };

    const secret = this.configService.get('JWT_SECRETE');

    const token = await this.jwtService.signAsync(payload, {
      expiresIn: '15m',
      secret: secret,
    });

    return {
      access_token: token,
    };
  }
}
