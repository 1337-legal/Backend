import HttpException from "../exceptions/HttpException";

class BaseMiddleware {
    error(code: number, message: string) {
        return new HttpException(code, message);
    }
}

export default BaseMiddleware;