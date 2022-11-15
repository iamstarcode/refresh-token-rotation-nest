import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpException,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { IRequestWithUser } from './interfaces/IRequestWithUser';
import { PrismaService } from 'src/prisma/prisma.service';
import { Request } from 'express';
import JwtRefreshGuard from './guard/jwt-refresh.guard';
import { AuthProviderDto } from './dto/auth-provider.dto';
import { JwtAuthGuard } from './guard/jwt.guard';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly prismaService: PrismaService,
  ) {}

  @Get('v')
  async v() {
    return 'v';
  }

  @Post('sign-up')
  signUp(@Body() dto: AuthDto, @Req() request: Request) {
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
    await this.authService.signOut(tokenId);
  }

  @UseGuards(JwtRefreshGuard)
  @Get('refresh')
  async refresh(@Req() request: IRequestWithUser) {
    //console.log(request.user)
    //request.res.setHeader('Set-Cookie', accessToken); next-auth creates cookie no nned here
    return request.user;
  }
}
