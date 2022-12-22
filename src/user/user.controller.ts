/* eslint-disable prettier/prettier */
import { Controller, Get, UseGuards } from '@nestjs/common';
import { GetUser } from '../auth/decorator/get-user.decorator';
import { JwtAuthGuard } from '../auth/guards/jwt.guard';
import * as dayjs from 'dayjs';

@Controller('user')
export class UserController {
  @UseGuards(JwtAuthGuard)
  @Get('me')
  getMe(@GetUser() user: any) {
    return (
      'User with Id: ' +
      user?.userId +
      ' requested @ ' +
      dayjs(Date.now()).format('hh:s a')
    );
  }
}
