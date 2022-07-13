import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { IRequestWithUser } from './interfaces/IRequestWithUser';
import { PrismaService } from 'src/prisma/prisma.service';
import * as argon from 'argon2';
import { Response } from 'express';
import JwtRefreshGuard from './guard/jwt-refresh.guard';
import { AuthProviderDto } from './dto/auth-provider.dto';
import { JwtAuthGuard } from './guard/jwt.guard';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  //@UseGuards(LocalAuthenticationGuard)
  //@ApiBody({ type: LogInDto })
  @Get('v')
  async v() {
    return 'v'
  }

  @HttpCode(200)
  @Post('log-in')
  async logIn(
    @Body() dto: AuthDto,
    @Req() request: IRequestWithUser,
    @Res({ passthrough: true }) res: Response,
  ) {
    const user = await this.prismaService.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user) {
      throw new ForbiddenException('Credentials incorrect');
    }

    const isMatch = await argon.verify(user.password, dto.password);

    if (!isMatch) {
      throw new ForbiddenException('Credentilas incorrect');
    }

    const {
      cookie: accessTokenCookie,
      token: accesToken,
    } = await this.authService.getCookieWithJwtAccessToken(user.id, user.email);

    const {
      cookie: refreshTokenCookie,
      token: refreshToken,
    } = this.authService.getCookieWithJwtRefreshToken(user.id, user.email);

    //store refresh token to a store database
    const currentHashedRefreshToken = await argon.hash(refreshToken);
    await this.prismaService.user.update({
      where: {
        id: user.id,
      },
      data: {
        refreshTokens: {
          push: currentHashedRefreshToken,
        },
      },
    });
    request.res.setHeader('Set-Cookie', [
      accessTokenCookie,
      refreshTokenCookie,
    ]);

    res.cookie('test', accesToken);

    /*   if (user.isTwoFactorAuthenticationEnabled) {
      return;
    } */

    return { accesToken };
  }

  @Post('sign-up')
  signup(@Body() dto: AuthDto) {
    return this.authService.signUp(dto);
  }

  @Post('sign-in')
  async signIn(@Body() dto: AuthDto) {
    const tokens = await this.authService.signIn(dto);
    return tokens;
  }

  @Post('sign-in-with-oauth')
  async signInwithSocial(@Body() dto: AuthProviderDto) {
    const user = await this.authService.signInWithOAuth(dto);
    return await this.authService.handeleSigin(user);
  }

  @UseGuards(JwtAuthGuard)
  @Post('sign-out')
  @HttpCode(200)
  async logOut(@Req() request: IRequestWithUser, @Body() body) {
    //await this.authService.removeRefreshToken(request.user.id);
    const refreshToken = body.refreshToken;
    try {
      const decoded = await this.jwtService.verifyAsync(refreshToken, {
        secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
      });

      //console.log(decoded)
      const user = await this.authService.getById(decoded.sub);
      let refrestokenMatches = false;
      let index = 0;

      for (let i = 0; i < user.refreshTokens.length; i++) {
        refrestokenMatches = await argon.verify(
          user.refreshTokens[i],
          refreshToken,
        );

        if (refrestokenMatches == true) {
          index = i;
          break;
        }
      }
      const newRefreshTokens = user.refreshTokens.filter(
        (rt) => rt !== user.refreshTokens[index],
      );

      console.log(newRefreshTokens);
      this.authService.updateRefreshToken(user.id, [...newRefreshTokens]);

      // console.log(decoded);
    } catch (error) {
      console.log(error);
    }

    //request.res.setHeader('Set-Cookie', this.authenticationService.getCookiesForLogOut());
  }

  @UseGuards(JwtRefreshGuard)
  @Get('refresh')
  async refresh(@Req() request) {
    //console.log(request.user)
    //request.res.setHeader('Set-Cookie', accessToken); next-auth creates cookie no nned here
    return request.user;
  }
}
