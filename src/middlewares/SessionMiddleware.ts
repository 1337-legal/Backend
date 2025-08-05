import type { Context } from "elysia";
import BaseMiddleware from './BaseMiddleware';

class SessionMiddleware extends BaseMiddleware {
    async auth(context: Context & { user: UserType | null }) {
        if (!context.user) {
            return this.error(401, "You need to be logged in to access this feature.");
        }
    }

    async premium(context: Context & { user: UserType | null }) {
        if (context.user && !["admin", "user"].includes(context.user.role)) {
            return this.error(402, "You need to be a premium user to access this feature.");
        }
    }

    async admin(context: Context & { user: UserType | null }) {
        if (context.user && context.user.role !== "admin") {
            return this.error(402, "You need to be an admin to access this feature.");
        }
    }
}

export default new SessionMiddleware();