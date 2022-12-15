import { User } from '@prisma/client';
import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { GetUser } from '../auth/decorator/get-user.decorator';
import { JwtAuthGuard } from '../auth/guard/jwt.guard';
import * as dayjs from 'dayjs';
import { PrismaService } from 'src/prisma/prisma.service';
import { IRequestWithUser } from 'src/auth/interfaces/IRequestWithUser';

@Controller('user')
export class UserController {
  constructor(private readonly prismaService: PrismaService) {}

  @UseGuards(JwtAuthGuard)
  @Get('me')
  getMe(@GetUser() user: User) {
    return `User Id: ${user.id} @ ` + dayjs(Date.now()).format('m:s');
  }

  @UseGuards(JwtAuthGuard)
  @Get('devices')
  async getDevices(@Req() request: IRequestWithUser) {
    return await this.prismaService.token.findMany({
      where: {
        userId: request.user.id,
      },
      select: {
        device: true,
        app: true,
        createdAt: true,
      },
    });
  }
}
