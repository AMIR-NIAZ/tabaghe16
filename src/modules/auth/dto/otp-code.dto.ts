import { IsEmail, IsNotEmpty, Matches } from 'class-validator';

export class OtpCodeDto {
    @IsEmail()
    email: string;

    @IsNotEmpty()
    @Matches(/^\d{5}$/, { message: 'کد باید دقیقا ۵ رقم باشد' })
    code: string;
}
