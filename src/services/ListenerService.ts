import Elysia from 'elysia';

import cors from '@elysiajs/cors';
import jwt from '@elysiajs/jwt';
import swagger from '@elysiajs/swagger';

export const app = new Elysia()
    .use(swagger())
    .use(
        jwt({
            name: "jwt",
            secret: Bun.env.JWT_SECRET as string,
        })
    )
    .use(
        cors({
            origin: "*",
            methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            maxAge: 3600,
            allowedHeaders: ["Content-Type", "Authorization"],
            credentials: true,
        })
    )
    .derive(async ({ headers, jwt }) => {
        const token = headers["authorization"];

        const payload = (await jwt.verify(token)) as UserType | false;
        if (!payload) {
            return { user: null };
        }

        return { user: payload };
    });

export type AppType = typeof app;