import Elysia, { ElysiaConfig } from 'elysia';
import authRouter from 'src/routes/auth';
import blindflareRouter from 'src/routes/blindflare';

import cors from '@elysiajs/cors';
import jwt from '@elysiajs/jwt';
import swagger from '@elysiajs/swagger';

import BaseService from './BaseService';

class ListenerService extends BaseService {
    app: ReturnType<typeof this.generateApp>;
    env: { [key: string]: string | undefined; };

    constructor(config?: ElysiaConfig<any>) {
        super();
        this.env = this.getEnvironmentVariables([
            "JWT_SECRET"
        ]);

        this.app = this.generateApp(config);

        this.setupRoutes([
            blindflareRouter,
            authRouter
        ]);
    }

    public generateApp(config?: ElysiaConfig<any>) {
        return new Elysia(config).use(swagger())
            .use(
                jwt({
                    name: "jwt",
                    secret: this.env.JWT_SECRET as string,
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
    }

    public setupRoutes(routers: (typeof this.app)[]) {
        this.app.group("/api/v1", (group) => {
            for (const router of routers) {
                group.use(router);
            }

            return group;
        });
    }

    public start(port: number) {
        this.app.listen(port);

        console.log(`🦊 Elegant Elysia is running at ${this.app.server?.hostname}:${this.app.server?.port}`);
    }
}

export default new ListenerService();