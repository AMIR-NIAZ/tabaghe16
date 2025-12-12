import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";

@Injectable()
export class RgisterGuard implements CanActivate {
    constructor(
        private readonly jwtService: JwtService
    ) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {

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