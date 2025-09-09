import { error } from 'elysia';

class BaseMiddleware {
    error(code: number, message: string) {
        return error(code, {
            message: `${code}: ${message}`,
        });
    }
}

export default BaseMiddleware;