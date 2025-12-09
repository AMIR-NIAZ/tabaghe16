import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { Repository } from 'typeorm';
import { User } from '../entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { CreateUserDto } from '../dto/create-user.dto';
import { JwtService } from '@nestjs/jwt';
import { hash, compare } from 'bcrypt';
import { LoginUserDto } from '../dto/login-user.dto';
import { RefreshtokenDto } from '../dto/refresh-token.dto';
import { PayloadAccess, PayloadRefresh } from 'src/common/@type/payload.type';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
        private readonly jwtService: JwtService
    ) { }

    async register(dto: CreateUserDto) {
        const { name, email, password } = dto;

        const existsUser = await this.userRepository.findOne({ where: { email } });
        if (existsUser) throw new BadRequestException('کاربری با این ایمیل وجود دارد');

        const newUser = this.userRepository.create({
            name,
            email,
            password
        })
        let userSaved = await this.userRepository.save(newUser)

        const { accessToken, refreshToken } = await this.generateTokens(userSaved)
        userSaved.refreshToken = await hash(refreshToken, 10);
        await this.userRepository.save(userSaved)

        return { message: "کاربر با موفقیت ساخته شد", data: { accessToken, refreshToken } };
    }

    async login(dto: LoginUserDto) {
        const { email, password } = dto;

        const user = await this.userRepository.findOneBy({ email });
        if (!user) throw new NotFoundException("یوزری با این ایمیل پیدا نشد!");

        const isPasswordValidation = await compare(password, user.password);
        if (!isPasswordValidation) throw new UnauthorizedException("پسوورد صحیح نمیباشد");

        const { accessToken, refreshToken } = await this.generateTokens(user)

        const hashedToken: string = await hash(refreshToken, 10);
        await this.userRepository.update(user.id, { refreshToken: hashedToken })

        return { message: "لاگین با موفقیت انجام شد", data: { accessToken, refreshToken } };
    }

    async refreshToken(dto: RefreshtokenDto) {
        const { refresh_token } = dto;
        try {
            const payLoad = this.jwtService.verify<PayloadRefresh>(refresh_token);

            const user = await this.userRepository.findOneBy({ id: payLoad.sub })
            if (!user) throw new UnauthorizedException("توکن معتبر نمیباشد");

            const isToken = await compare(refresh_token, user.refreshToken)
            if (!isToken) throw new UnauthorizedException("توکن معتبر نمیباشد");

            const {accessToken} =  await this.generateTokens(user) 
            
            return {message: "توکن با موفقیت تغیر یافت", data: {accessToken}}
        } catch (err) {
            throw new UnauthorizedException("توکن معتبر نمیباشد");
        }
    }

    async generateTokens(user: User) {
        const payloadAccess: PayloadAccess = {
            sub: user.id,
            role: user.role,
        };

        const payloadRefresh: PayloadRefresh = {
            sub: user.id,
        };

        const accessToken = this.jwtService.sign(payloadAccess, {
            expiresIn: "10m",
        })
        const refreshToken = this.jwtService.sign(payloadRefresh, {
            expiresIn: "25d",
        });

        return { accessToken, refreshToken };
    }
}
