import { IsEmail, IsString, Min, MinLength } from 'class-validator';

export class CreateUserDto {
    @IsString()
    name: string;
    
    @IsString()
    @MinLength(8, { message: 'رمز عبور باید حداقل ۸ کاراکتر باشد' })
    password: string;
}
