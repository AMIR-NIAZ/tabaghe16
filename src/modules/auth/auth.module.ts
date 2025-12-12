import { Module } from '@nestjs/common';
import { AuthService } from './services/auth.service';
import { AuthController } from './controller/auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { JwtModule } from '@nestjs/jwt';
import { EmailService } from 'src/common/services/email.service';
import { CacheService } from 'src/common/services/cache.service';
import { OtpService } from './services/otp.service';
import { ConfigService } from '@nestjs/config';

@Module({
    imports: [
        TypeOrmModule.forFeature([User]),
        JwtModule.registerAsync({
            inject: [ConfigService],
            useFactory: (config: ConfigService) => ({
                secret: config.get('JWT_SECRET'),
            })
        }),
    ],
    controllers: [AuthController],
    providers: [
        AuthService,
        OtpService,
        EmailService,
        CacheService
    ],
    exports: [JwtModule],
})
export class AuthModule { }
