import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { JwtService } from "@nestjs/jwt";
import { PUBLIC_KEY } from "../decorators/public.decorator";

@Injectable()
export class PayloadGuard implements CanActivate {
    constructor(
        private readonly reflector: Reflector,
        private readonly jwtService: JwtService
    ) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const publicMethod = this.reflector.get(PUBLIC_KEY, context.getHandler());
        if (publicMethod) return true;

        let request = context.switchToHttp().getRequest<Request>();
        const token = this.getToken(request);

        try {
            const payload = await this.jwtService.verifyAsync(token);
            request['user'] = payload;
        } catch (error) {
            throw new UnauthorizedException("توکن نا معتبر میباشد");
        }

        return true
    }

    private getToken(request: Request) {
        const authHeader = request.headers['authorization'];

        if (typeof authHeader !== "string" || !authHeader.startsWith("Bearer ")) {
            throw new UnauthorizedException("توکن نا معتبر میباشد");
        }
        const token = authHeader.split(" ")[1];

        return token
    }
}