import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './services/auth.service';
import { HashPasswordPipe } from 'src/common/pipes/hash-password.pipe';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { IsPublic } from 'src/common/decorators/public.decorator';
import { RefreshtokenDto } from './dto/refresh-token.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}
    
    @Post('rgister')
    @IsPublic()
    async register(@Body(HashPasswordPipe) dto: CreateUserDto) {
        return await this.authService.register(dto);
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
