import { User } from '.prisma/client';
import { Controller, Get, HttpStatus, Req, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { request, Request } from 'express';
import JwtRefreshGuard from 'src/auth/guard/jwt-refresh.guard';
import { GetUser } from '../auth/decorator/get-user.decorator';
import { JwtAuthGuard } from '../auth/guard/jwt.guard';
import { UserService } from './user.service';
import * as dayjs from 'dayjs';
import { PrismaService } from 'src/prisma/prisma.service';
import { IRequestWithUser } from 'src/auth/interfaces/IRequestWithUser';
import { UAParser } from 'ua-parser-js';

@Controller('user')
export class UserController {
  constructor(
    private readonly userService: UserService,
    private readonly prismaService: PrismaService,
  ) {}

  @UseGuards(JwtAuthGuard)
  @Get('me')
  getMe(@GetUser() user: User) {
    //console.log(dayjs( Date.now()).format('m:s'));
    return 'user me @ ' + dayjs(Date.now()).format('m:s');
  }

  @UseGuards(JwtAuthGuard)
  @Get('devices')
  async getDevices(@Req() request: IRequestWithUser) {
 /*    const parser = new UAParser(request.header('User-Agent'))
    console.log(parser.getDevice(), parser.getBrowser() , parser.getOS()) */
    return await this.prismaService.token.findMany({
      where:{
        userId:request.user.id
      },
      select:{
        browserInfo:true,
        createdAt:true,
      }
    })
  }

  @Get('send-mail')
  refresh(@Req() request) {
    this.userService.example2();
  }
}
