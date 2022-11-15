import {
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { ITokenPayload } from './interfaces/ITokenPayload';
import { AuthProviderDto } from './dto/auth-provider.dto';

import * as dayjs from 'dayjs';

import { User } from '@prisma/client';
import { Request } from 'express';
import { UAParser } from 'ua-parser-js';

const JWT_ACCESS_TOKEN_EXPIRATION_TIME = '5s';
const JWT_REFRESH_TOKEN_EXPIRATION_TIME = '1d';
//const ACCESS_TOKEN_EXPIRY = 5;
//const REFRESH_TOKEN_EXPIRY = 1; //24 * 60 * 60 * 1000;

const getAccessExpiry = () => dayjs().add(5, 's').toDate();
const getRefreshExpiry = () => dayjs().add(1, 'd').toDate();

@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async handeleSigin(user: User, request: Request) {
    const userAgent: any = JSON.parse(request.header('x-user-agent'));
    //console.log(userAgent);
    const { refreshToken } = await this.getJwtRefreshToken(
      user.id,
      user?.email,
    );
    const { accessToken } = await this.getJwtAccessToken(user.id, user?.email);

    try {
      const hash = await argon.hash(refreshToken);
      const token = await this.prismaService.token.create({
        data: {
          expiresAt: getRefreshExpiry(),
          refreshToken: hash,
          device: userAgent.device,
          app: userAgent.appType,
          user: {
            connect: {
              id: user.id,
            },
          },
        },
      });

      return {
        accessToken,
        refreshToken,
        tokenId: token.id,
        accessTokenExpires: getAccessExpiry(),
        user: {
          id: user.id,
          email: user.email,
        },
      };
    } catch (error) {
      console.log(error);
    }
  }

  async signUp(dto: AuthDto, request: Request) {
    const password = await argon.hash(dto.password);
    try {
      const user = await this.prismaService.user.create({
        data: {
          email: dto.email,
          password,
        },
      });

      const userAgent = this.generateUserAgent(request.headers['user-agent']);
      request.headers['x-user-agent'] = JSON.stringify(userAgent);
      return await this.handeleSigin(user, request);
    } catch (err) {
      if (err instanceof PrismaClientKnownRequestError) {
        if (err.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw err;
    }
  }

  async signIn(dto: AuthDto, request: Request) {
    //find a user

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

    return await this.handeleSigin(user, request);
  }

  async signOut(tokenId: string) {
    try {
      await this.prismaService.token.delete({
        where: {
          id: tokenId,
        },
      });
    } catch (error) {
      throw new HttpException('Bad Request', HttpStatus.BAD_REQUEST);
    }
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
            providers: {
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

  /*  async getUserIfRefreshTokenMatches(refreshToken: string, userId: number) {
    const user = await this.getById(userId);

    const foundUser = await this.prismaService.user.findFirst({
      where: {
        refreshTokens: {
          has: refreshToken,
        },
      },
    });

    if (!foundUser) {
      //refresh token is valid but not in db
      //re-use detection possible!!! delete all refresh tokens
      try {
        const decoded = this.jwtService.verify(refreshToken, {
          secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
        });
        //Probably a resused token here, flag as a hacked user
        const compromisedUser = await this.prismaService.user.findUnique({
          where: {
            id: decoded.sub,
          },
        });
        await this.updateRefreshToken(compromisedUser.id, []);
      } catch (error) {
        // valid but expired or not decodeable
        console.log('', error);
        throw new HttpException(
          'Unauthorised valid but either expired or other reason ',
          HttpStatus.UNAUTHORIZED,
        );
      }

      throw new HttpException('Unauthorised', HttpStatus.FORBIDDEN);
    }

    //Token is valid and still in db , here we then remove from db and send new pairs of RF and AT

    //We then filter out the current RT
    const newRefreshTokens = foundUser.refreshTokens.filter(
      (rt) => rt !== refreshToken,
    );

    //check if token as expired
    try {
      const decoded = await this.jwtService.verifyAsync(refreshToken, {
        secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
      });

      //Here RT is still valid we can go ahead to send new pairs of Tokens
      const { accessToken } = await this.getJwtAccessToken(
        foundUser.id,
        foundUser.email,
      );
      const { refreshToken: newRefreshToken } = await this.getJwtRefreshToken(
        foundUser.id,
        foundUser?.email,
      );
      this.updateRefreshToken(foundUser.id, [
        ...newRefreshTokens,
        newRefreshToken,
      ]);

      return {
        accessToken,
        refreshToken: newRefreshToken,
        accessTokenExpires: ACCESS_TOKEN_EXPIRY,
        user: {
          id: foundUser.id,
          email: foundUser.email,
        },
      };
    } catch (error) {
      //expired RT, we can log out the user
      this.updateRefreshToken(foundUser.id, [...newRefreshTokens]);

      throw new HttpException('Unauthorised', HttpStatus.UNAUTHORIZED);
    }
  } */

  // async getUserIfRefreshTokenMatches0(refreshToken: string, userId: number) {
  //   //const user = await this.getById(userId);
  //   const foundUser = await this.prismaService.user.findFirst({
  //     where: {
  //       refreshTokens: {
  //         has: refreshToken,
  //       },
  //     },
  //   });

  //   if (!foundUser) {
  //     //refresh token is valid but not in db
  //     //re-use detection possible!!! delete all refresh tokens
  //     try {
  //       const decoded = this.jwtService.verify(refreshToken, {
  //         secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
  //       });

  //       const issuedAt = dayjs.unix(decoded.iat);

  //       const diff = dayjs().diff(issuedAt, 'seconds');

  //       if (diff < 30) {
  //         /*  const newRefreshTokens = foundUser.refreshTokens.filter(
  //           (rt) => rt !== refreshToken,
  //         ); */

  //         const { accessToken } = await this.getJwtAccessToken(
  //           decoded.id,
  //           decoded.email,
  //         );
  //         const {
  //           refreshToken: newRefreshToken,
  //         } = await this.getJwtRefreshToken(decoded.id, decoded.email);
  //         /*  this.updateRefreshToken(foundUser.id, [
  //           ...newRefreshTokens,
  //           newRefreshToken,
  //         ]); */

  //         this.prismaService.user.update({
  //           where: {
  //             id: decoded.sub,
  //           },
  //           data: {
  //             refreshTokens: {
  //               push: newRefreshToken,
  //             },
  //           },
  //         });

  //         return {
  //           accessToken,
  //           refreshToken: newRefreshToken,
  //           accessTokenExpires: ACCESS_TOKEN_EXPIRY,
  //           user: {
  //             id: decoded.id,
  //             email: decoded.email,
  //           },
  //         };
  //       }

  //       //Probably a resused token here, flag as a hacked user
  //       const compromisedUser = await this.prismaService.user.findUnique({
  //         where: {
  //           id: decoded.sub,
  //         },
  //       });
  //       await this.updateRefreshToken(compromisedUser.id, []);
  //     } catch (error) {
  //       // valid but expired or not decodeable
  //       console.log('', error);
  //       throw new HttpException(
  //         'Unauthorised valid but either expired or other reason ',
  //         HttpStatus.UNAUTHORIZED,
  //       );
  //     }

  //     throw new HttpException('Unauthorised', HttpStatus.FORBIDDEN);
  //   }

  //   //Token is valid and still in db , here we then remove from db and send new pairs of RF and AT

  //   //We then filter out the current RT
  //   const newRefreshTokens = foundUser.refreshTokens.filter(
  //     (rt) => rt !== refreshToken,
  //   );

  //   //check if token as expired
  //   try {
  //     const decoded = await this.jwtService.verifyAsync(refreshToken, {
  //       secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
  //     });

  //     //Here RT is still valid we can go ahead to send new pairs of Tokens
  //     const { accessToken } = await this.getJwtAccessToken(
  //       foundUser.id,
  //       foundUser.email,
  //     );
  //     const { refreshToken: newRefreshToken } = await this.getJwtRefreshToken(
  //       foundUser.id,
  //       foundUser?.email,
  //     );
  //     this.updateRefreshToken(foundUser.id, [
  //       ...newRefreshTokens,
  //       newRefreshToken,
  //     ]);

  //     return {
  //       accessToken,
  //       refreshToken: newRefreshToken,
  //       accessTokenExpires: ACCESS_TOKEN_EXPIRY,
  //       user: {
  //         id: foundUser.id,
  //         email: foundUser.email,
  //       },
  //     };
  //   } catch (error) {
  //     //expired RT, we can log out the user
  //     this.updateRefreshToken(foundUser.id, [...newRefreshTokens]);

  //     throw new HttpException('Unauthorised', HttpStatus.UNAUTHORIZED);
  //   }
  // }

  //with distribution lock
  /*   async getUserIfRefreshTokenMatches2(refreshToken: string, userId: number) {
    //const user = await this.getById(userId);
    const foundUser = await this.prismaService.user.findFirst({
      where: {
        refreshTokens: {
          has: refreshToken,
        },
      },
    });

    if (!foundUser) {
      //refresh token is valid but not in db
      //re-use detection possible!!! delete all refresh tokens
      try {
        const decoded = this.jwtService.verify(refreshToken, {
          secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
        });
        //Probably a resused token here, flag as a hacked user
        const compromisedUser = await this.prismaService.user.findUnique({
          where: {
            id: decoded.sub,
          },
        });
        await this.updateRefreshToken(compromisedUser.id, []);
      } catch (error) {
        // valid but expired or not decodeable
        console.log('', error);
        throw new HttpException(
          'Unauthorised valid but either expired or other reason ',
          HttpStatus.UNAUTHORIZED,
        );
      }

      throw new HttpException('Unauthorised', HttpStatus.FORBIDDEN);
    }

    //Token is valid and still in db , here we then remove from db and send new pairs of RF and AT

    //We then filter out the current RT
    const newRefreshTokens = foundUser.refreshTokens.filter(
      (rt) => rt !== refreshToken,
    );

    //check if token as expired
    try {
      const decoded = await this.jwtService.verifyAsync(refreshToken, {
        secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
      });

      //Here RT is still valid we can go ahead to send new pairs of Tokens
      const { accessToken } = await this.getJwtAccessToken(
        foundUser.id,
        foundUser.email,
      );
      const { refreshToken: newRefreshToken } = await this.getJwtRefreshToken(
        foundUser.id,
        foundUser?.email,
      );
      this.updateRefreshToken(foundUser.id, [
        ...newRefreshTokens,
        newRefreshToken,
      ]);

      return {
        accessToken,
        refreshToken: newRefreshToken,
        accessTokenExpires: ACCESS_TOKEN_EXPIRY,
        user: {
          id: foundUser.id,
          email: foundUser.email,
        },
      };
    } catch (error) {
      //expired RT, we can log out the user
      this.updateRefreshToken(foundUser.id, [...newRefreshTokens]);

      throw new HttpException('Unauthorised', HttpStatus.UNAUTHORIZED);
    }
  } */

  /*   async getUserIfRefreshTokenMatches3(
    refreshToken: string,
    tokenId: string,
    userId: number,
  ) {
    const user = await this.getById(userId);
    const foundToken = await this.prismaService.token.findUnique({
      where: {
        id: tokenId,
      },
    });

    const isMatch = await argon.verify(foundToken.refreshToken, refreshToken);

    if (!isMatch) {
      //refresh token is valid but not in db
      //re-use detection possible!!! delete all refresh tokens
      try {
        const decoded = this.jwtService.verify(refreshToken, {
          secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
        });

        //console.log('re use detected'); Re use detected or race condition

        const issuedAt = dayjs.unix(decoded.iat);
        const diff = dayjs().diff(issuedAt, 'seconds');

        console.log(diff);

        if (diff < 60 * 1 * 2) {
          //2 minute leeway allows refresh
          const { accessToken } = await this.getJwtAccessToken(
            user.id,
            user.email,
          );
          const {
            refreshToken: newRefreshToken,
          } = await this.getJwtRefreshToken(user.id, user?.email);

          const hash = await argon.hash(newRefreshToken);
          await this.prismaService.user.update({
            where: {
              id: user.id,
            },
            data: {
              tokens: {
                update: {
                  where: {
                    id: foundToken.id,
                  },
                  data: {
                    refreshToken: hash,
                  },
                },
              },
            },
          });

          return {
            accessToken,
            refreshToken: newRefreshToken,
            tokenId: foundToken.id,
            accessTokenExpires: getAccessExpiry(),
            user: {
              id: user.id,
              email: user.email,
            },
          };
        }

        //Probably a resused token here, flag as a hacked user and delete all session
        // You can decide to do anything aditional here maybe send a mail or something
        await this.prismaService.user.update({
          where: {
            id: decoded.sub,
          },
          data: {
            tokens: {
              deleteMany: {},
            },
          },
        });
      } catch (error) {
        // valid but expired or not decodeable
        console.log('', error);
        throw new HttpException(
          'Unauthorised valid but either expired or other reason ',
          HttpStatus.UNAUTHORIZED,
        );
      }

      throw new HttpException('Unauthorised ', HttpStatus.FORBIDDEN);
    }

    //console.log('not leeway');
    //Token is valid and still in db , here we then remove from db and send new pairs of RF and AT

    //We then filter out the current RT

    //check if token as expired
    try {
      const decoded = await this.jwtService.verifyAsync(refreshToken, {
        secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
      });

      //Here RT is still valid we can go ahead to send new pairs of Tokens
      const { accessToken } = await this.getJwtAccessToken(user.id, user.email);
      const { refreshToken: newRefreshToken } = await this.getJwtRefreshToken(
        user.id,
        user?.email,
      );

      const hash = await argon.hash(newRefreshToken);
      await this.prismaService.user.update({
        where: {
          id: user.id,
        },
        data: {
          tokens: {
            update: {
              where: {
                id: foundToken.id,
              },
              data: {
                refreshToken: hash,
              },
            },
          },
        },
      });

      return {
        accessToken,
        refreshToken: newRefreshToken,
        tokenId: foundToken.id,
        accessTokenExpires: getAccessExpiry(),
        user: {
          id: user.id,
          email: user.email,
        },
      };
    } catch (error) {
      //expired RT, we can log out the user
      //  this.updateRefreshToken(foundUser.id, [...newRefreshTokens]);

      throw new HttpException('Unauthorised', HttpStatus.UNAUTHORIZED);
    }
  } */

  async getUserIfRefreshTokenMatches(
    refreshToken: string,
    tokenId: string,
    payload: ITokenPayload,
  ) {
    const foundToken = await this.prismaService.token.findUnique({
      where: {
        id: tokenId,
      },
    });

    const isMatch = await argon.verify(foundToken.refreshToken, refreshToken);

    if (isMatch) {
      const issuedAt = dayjs.unix(payload.iat);
      const diff = dayjs().diff(issuedAt, 'seconds');

      if (diff < 60 * 1 * 1) {
        //less than 1 minute leeway allows refresh for network concurrency
        console.log('leeway');
        const { accessToken } = await this.getJwtAccessToken(
          payload.sub,
          payload.email,
        );

        const { refreshToken: newRefreshToken } = await this.getJwtRefreshToken(
          payload.sub,
          payload.email,
        );

        const hash = await argon.hash(newRefreshToken);

        await this.prismaService.token.update({
          where: {
            id: foundToken.id,
          },
          data: {
            refreshToken: hash,
          },
        });

        return {
          accessToken,
          refreshToken: newRefreshToken,
          tokenId: foundToken.id,
          accessTokenExpires: getAccessExpiry(),
          user: {
            id: payload.sub,
            email: payload.email,
          },
        };
      } else {
        await this.signOut(tokenId);
        throw new HttpException('Something went wrong', HttpStatus.BAD_REQUEST);
      }
    } else {
      //refresh token is valid but not in db
      //possible re-use!!! delete all refresh tokens belonging to the sub
      if (payload.sub !== foundToken.userId) {
        // log out all session of this payalod id, reFreshToken has been compromised
        await this.prismaService.token.deleteMany({
          where: {
            userId: payload.sub,
          },
        });
        throw new HttpException('Forbidden', HttpStatus.FORBIDDEN);
      }
      throw new HttpException('Unathorized', HttpStatus.UNAUTHORIZED);
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

  /*   public async updateRefreshToken(id: number, tokens: string[]) {
    //console.log(tokens)
    await this.prismaService.user.update({
      where: {
        id,
      },
      data: {
        refreshTokens: tokens,
      },
    });
  } */

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

  private generateUserAgent(userAgent: string) {
    const device: any = {};
    const parser = new UAParser(userAgent);
    if (parser.getDevice().model == undefined) {
      //web browser
      device.appType = parser.getBrowser().name;
      device.device = parser.getOS().name + ' ' + parser.getOS().version;
    } else {
      // a mobile web browser
      device.device = `${parser.getDevice().vendor}  ${
        parser.getDevice().model
      }`;
      device.appType = parser.getBrowser().name;
    }
    return device;
  }
}
