import {
    ArgumentsHost,
    Catch,
    ExceptionFilter,
    HttpException,
    HttpStatus,
} from '@nestjs/common';
import { QueryFailedError } from 'typeorm';

@Catch()
export class HttpExceptionFilter<T> implements ExceptionFilter {
    catch(exception: T, host: ArgumentsHost) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse();
        let status = HttpStatus.INTERNAL_SERVER_ERROR;
        let message = 'Internal server error';

        if (exception instanceof HttpException) {
            status = exception.getStatus();
            let res = exception.getResponse();
            message =
                typeof res === 'string' ? res : (res as any).message || message;
        } else if (exception instanceof QueryFailedError) {
            status = HttpStatus.BAD_REQUEST;
            message = exception.message;
        } else if (exception instanceof Error) {
            message = exception.message;
        }
        if (status === 403) message = 'شما به این بخش دسترسی ندارید';
        const errorResponse = {
            success: false,
            statusCode: status,
            message,
        };
        return response.status(status).json(errorResponse);
    }
}
