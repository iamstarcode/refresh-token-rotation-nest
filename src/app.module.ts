import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { PrismaModule } from './prisma/prisma.module';
import { ConfigModule } from '@nestjs/config';
import { MailerModule } from '@nestjs-modules/mailer';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';

@Module({
  imports: [
    AuthModule,
    UserModule,
    PrismaModule,
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    MailerModule.forRoot({
      transport: {
        host: 'smtp.gmail.com',
        port: 587,
        secure: false, // upgrade later with STARTTLS
        auth: {
          type: 'OAuth2',
          user: 'iamstarcode@gmail.com',
          clientId: process.env.GOOGLE_CLIENT_ID,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET,
          refreshToken:
            '1//04EPaVxYS6ODSCgYIARAAGAQSNwF-L9IrB0Cq0soilOy-0w2EXIQCMeN_OIKTe6Oh5AqZpFg7Tj6B_mfgsvwGYwu-2k9J0SVex6k',
          accessToken:
            'ya29.A0ARrdaM_vERvjKmul9vJ5cE7UyKhNAjNZl44pcx1yDVqRdpQSEDKUfbGCmizoU7LWZn_2m9wugF8I9WzSIETFaxnfPwcLzDf-zM2gObP1ODgsw7Y9vWJT1Egm8hJ69kjex2lFK9WmkvGDI-t9NqIR6ip9J-npYUNnWUtBVEFTQVRBU0ZRRl91NjFWX1dxcEtTVHJxRGVjajRDdU9MdU01Zw0163',
          accessUrl: 'https://oauth2.googleapis.com/token',
        },
      },
      defaults: {
        from: '"nest-modules" <modules@nestjs.com>',
      },
      //preview: true,
      template: {
        dir: process.cwd() + '/templates/',
        adapter: new HandlebarsAdapter(), // or new PugAdapter()
        options: {
          strict: true,
        },
      },
    }),
  ],
})
export class AppModule {}
