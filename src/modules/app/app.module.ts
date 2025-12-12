import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from '../auth/auth.module';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { PayloadGuard } from '../../common/guard/payload.guard';
import { RoleGurd } from '../../common/guard/role.guard';
import { CacheModule } from '@nestjs/cache-manager';

@Module({
    imports: [
        TypeOrmModule.forRoot({
            type: 'mysql',
            host: 'localhost',
            port: 3306,
            username: 'root',
            password: '',
            database: 'tabaghe16',
            autoLoadEntities: true,
            synchronize: true,
        }),
        ConfigModule.forRoot({
            isGlobal: true,
        }),
        CacheModule.register({isGlobal: true}),
        AuthModule,
    ],
    providers: [
        {
            provide: APP_GUARD,
            useClass: PayloadGuard,
        },
        {
            provide: APP_GUARD,
            useClass: RoleGurd,
        },
    ],
})
export class AppModule { }
