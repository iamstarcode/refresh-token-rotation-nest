import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { IRequestWithUser } from './interfaces/IRequestWithUser';
import JwtRefreshGuard from './guards/jwt-refresh.guard';
import { JwtAuthGuard } from './guards/jwt.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('sign-up')
  signUp(@Body() dto: AuthDto) {
    return this.authService.signUp(dto);
  }

  @Post('sign-in')
  async signIn(@Body() dto: AuthDto) {
    const tokens = await this.authService.signIn(dto);
    return tokens;
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
    //request.res.setHeader('Set-Cookie', accessToken); next-auth creates cookie no need here
    return request.user;
  }
}
