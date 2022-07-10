import { User } from '.prisma/client';
import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import JwtRefreshGuard from 'src/auth/guard/jwt-refresh.guard';
import { GetUser } from '../auth/decorator/get-user.decorator';
import { JwtAuthGuard } from '../auth/guard/jwt.guard';
import { UserService } from './user.service';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}
  
  @UseGuards(JwtAuthGuard)
  @Get('me')
  getMe(@GetUser() user: User) {
    console.log(user);
    return 'user me';
  }

  @Get('send-mail')
  refresh(@Req() request) {
    this.userService.example2()
  }
}
