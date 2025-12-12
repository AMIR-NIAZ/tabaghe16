import { Body, Controller, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from '../services/auth.service';
import { HashPasswordPipe } from 'src/common/pipes/hash-password.pipe';
import { CreateUserDto } from '../dto/create-user.dto';
import { LoginUserDto } from '../dto/login-user.dto';
import { IsPublic } from 'src/common/decorators/public.decorator';
import { RefreshtokenDto } from '../dto/refresh-token.dto';
import { SendEmailDto } from '../dto/send-email.dto';
import { OtpService } from '../services/otp.service';
import { OtpCodeDto } from '../dto/otp-code.dto';
import { RgisterGuard } from 'src/common/guard/rgister.guard';

@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly otpService: OtpService
    ) { }

    @Post('send-otp')
    @IsPublic()
    async sendEmail(@Body() dto: SendEmailDto) {
        return this.otpService.sendEmail(dto)
    }

    @Post('verify-otp')
    @IsPublic()
    async verifyOtp(@Body() dto: OtpCodeDto) {
        return this.otpService.verifyOtp(dto)
    }

    @UseGuards(RgisterGuard)
    @Post('rgister')
    @IsPublic()
    async register(@Body(HashPasswordPipe) dto: CreateUserDto, @Req() req) {
        return await this.authService.register(dto, req.user.user_id);
    }

    @Post('login')
    @IsPublic()
    async login(@Body() dto: LoginUserDto) {
        return await this.authService.login(dto);
    }

    @Post('refresh-token')
    @IsPublic()
    async refreshToken(@Body() dto: RefreshtokenDto) {
        return await this.authService.refreshToken(dto);
    }
}
