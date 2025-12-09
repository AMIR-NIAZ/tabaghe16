import { IsString } from 'class-validator';

export class RefreshtokenDto {
  @IsString()
  refresh_token: string;
}
