import { User } from '.prisma/client';
import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import JwtRefreshGuard from 'src/auth/guard/jwt-refresh.guard';
import { GetUser } from './auth/decorator/get-user.decorator';
import { JwtAuthGuard } from './auth/guard/jwt.guard';
import { UserService } from './user/user.service';
import * as dayjs from 'dayjs'

@Controller('')
export class AppController {
  constructor(private readonly userService: UserService) {}
  
  //@UseGuards(JwtAuthGuard)
  @Get('me')
  getMe(@GetUser() user: User) {
    //console.log(dayjs( Date.now()).format('m:s'));
    return 'user me @ ' + dayjs( Date.now()).format('m:s');
  }

  @Get('send-mail')
  refresh(@Req() request) {
    this.userService.example2()
  }
}
