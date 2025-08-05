import Router, { t } from 'elysia';

import UserRepository from '@Repositories/UserRepository';
import { AppType } from '@Services/ListenerService';

const authRouter: AppType = new Router();

authRouter.post(
    "/auth/login",
    async ({ set, body, jwt, request }) => {
        const { username, password } = body;

        const user = await UserRepository.findUserByUsername(username);
        if (!user) {
            set.status = 401;
            return {
                message: "Invalid username or password",
            };
        }

        if (!(await Bun.password.verify(password, user.password))) {
            set.status = 401;
            return {
                message: "Invalid username or password",
            };
        }

        const token = await jwt.sign({
            username: user.username,
            role: user.role,
        });



        return {
            user: {
                username: user.username,
                role: user.role,
            },
            token,
        };
    },
    {
        body: t.Object({
            publicKey: t.String({
                description: "Public key for the user",
            }),
            signature: t.String({
                description: "SHA-512 signature of the user's private key",
            }),
        }),
    }
);

authRouter.post(
    "/auth/register",
    async ({ set, body, jwt, request }) => {
        const { username, password } = body;



        const newUser = await UserRepository.create({
            username: username,
            password: hashedPassword,
        });

        const token = await jwt.sign({
            username: newUser.username,
            role: newUser.role,
        });

        return {
            user: {
                username: newUser.username,
                role: newUser.role,
            },
            token,
        };
    },
    {
        body: t.Object({
            publicKey: t.String({
                description: "Public key for the user",
            }),
            signature: t.String({
                description: "SHA-512 signature of the user's private key",
            }),
        }),
    }
);

export default authRouter;