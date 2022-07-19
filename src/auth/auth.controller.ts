import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  HttpException,
  HttpStatus,
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
import { Response, Request } from 'express';
import JwtRefreshGuard from './guard/jwt-refresh.guard';
import { AuthProviderDto } from './dto/auth-provider.dto';
import { JwtAuthGuard } from './guard/jwt.guard';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UAParser } from 'ua-parser-js';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly prismaService: PrismaService,
  ) {}

  //@UseGuards(LocalAuthenticationGuard)
  //@ApiBody({ type: LogInDto })
  @Get('v')
  async v() {
    return 'v';
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
  signup(@Body() dto: AuthDto, @Req() request: Request) {
    return this.authService.signUp(dto, request);
  }

  @Post('sign-in')
  async signIn(@Body() dto: AuthDto, @Req() request: Request) {
    const tokens = await this.authService.signIn(dto, request);
    return tokens;
  }

  @Post('sign-in-with-oauth')
  async signInwithSocial(
    @Body() dto: AuthProviderDto,
    @Req() request: Request,
  ) {
    const user = await this.authService.signInWithOAuth(dto);
    return await this.authService.handeleSigin(user, request);
  }

  @UseGuards(JwtAuthGuard)
  @Post('sign-out')
  @HttpCode(200)
  async signOut(@Req() request: IRequestWithUser) {
    const tokenId = request.header('Token-Id');
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

  @UseGuards(JwtRefreshGuard)
  @Get('refresh')
  async refresh(@Req() request: IRequestWithUser) {
    //console.log(request.user)
    //request.res.setHeader('Set-Cookie', accessToken); next-auth creates cookie no nned here
    return request.user;
  }
}
