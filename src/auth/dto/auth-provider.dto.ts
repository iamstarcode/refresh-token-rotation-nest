import {
  IsEmail,
  IsNotEmpty,
  IsNumber,
  IsObject,
  IsOptional,
  IsString,
} from 'class-validator';

export class AuthProviderDto {

  @IsString()
  @IsNotEmpty()
  provider:string

  @IsString()
  @IsNotEmpty()
  id:string

  @IsString()
  @IsEmail()
  @IsOptional()
  email?:string
  
  @IsString()
  @IsOptional()
  firstName?:string

  @IsString()
  @IsOptional()
  lastName?:string

}
