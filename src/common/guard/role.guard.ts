import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { roleEnum } from "../enums/role.enum";
import { PUBLIC_KEY } from "../decorators/public.decorator";
import { ROLE_KEY } from "../decorators/role.decorator";

@Injectable()
export class RoleGurd implements CanActivate {
    constructor(
        private readonly reflector: Reflector,
    ) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const publicMethod = this.reflector.get(PUBLIC_KEY, context.getHandler());
        if (publicMethod) return true;
        
        const userRole: string = context.switchToHttp().getRequest().user?.role;
        const requiredRoles: string[] = this.reflector.get(ROLE_KEY, context.getHandler()) || [];
        
        if (userRole == roleEnum.OWNER) return true;
        if (requiredRoles.includes(roleEnum.ALL)) return true;

        return requiredRoles.includes(userRole);
    }
}// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMiIsImVtYWlsIjoiYWFld0BnbWFpbC5jb20iLCJyb2xlIjoidXNlciIsImlhdCI6MTc2NTA5OTI2MywiZXhwIjoxNzY1MDk5ODYzfQ.b13abUy8WohV6TYp96xnzz_q2osvRyP4V9kFPDfVaDc