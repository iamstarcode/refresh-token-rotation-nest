import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
//import * as csurf from 'csurf'; //deprecated
// eslint-disable-next-line @typescript-eslint/no-var-requires
const cookieParser = require('cookie-parser');

async function bootstrap() {
  const allowedOrigins = [
    'http://localhost:3000',
    'https://melodic-kitten-c0528c.netlify.app',
  ];

  const app = await NestFactory.create(AppModule);

  app.useGlobalPipes(new ValidationPipe({ whitelist: true }));

  //Cookie Parser
  app.use(cookieParser());

  //CORS
  app.enableCors({
    origin: (origin, callback) => {
      if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    optionsSuccessStatus: 200,
    credentials: true,
  });

  //CSRF Protection
  /*  app.use(csurf({cookie:true}));
  app.use('/csrf',(req,res)=>{
    return res.send(req.csrfToken())
  }) */

  await app.listen(process.env.PORT || 8000);
}

bootstrap();
