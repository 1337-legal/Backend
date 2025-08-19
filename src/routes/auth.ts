import Router, { t } from 'elysia';

import Fortress from '@blindflare/fortress';
import FortressMiddleware from '@Middlewares/FortressMiddleware';
import UserRepository from '@Repositories/UserRepository';
import ListenerService from '@Services/ListenerService';

const authRouter: typeof ListenerService.app = new Router();

authRouter.post(
    "/auth/login",
    async ({ set, body, jwt }) => {
        const { blindflare: { publicKey, signature } } = body;

        const user = await UserRepository.findUserByPublicKey(publicKey);
        if (!user) {
            set.status = 401;
            return {
                message: "Public key not found.",
            };
        }

        if (!Fortress.verifySignature("AUTH", signature, publicKey)) {
            set.status = 401;
            return {
                message: "Invalid signature.",
            };
        }

        const token = await jwt.sign({
            publicKey: user.publicKey,
            role: user.role,
        });

        return {
            user: {
                address: user.address,
                role: user.role,
            },
            token,
        };
    },
    {
        afterHandle: [FortressMiddleware.handleResponse],
        body: t.Object({
            blindflare: t.Object({
                type: t.Literal("AUTH"),
                publicKey: t.String({
                    description: "Public key for the user.",
                }),
                signature: t.String({
                    description: "SHA-512 signature of the user's private key.",
                }),
                version: t.String({
                    description: "Version of the Blindflare protocol.",
                }),
            }),
        }),
    }
);

authRouter.post(
    "/auth/register",
    async ({ set, body, jwt }) => {
        const { address, blindflare: { publicKey, signature } } = body;

        if (!Fortress.verifySignature("AUTH", signature, publicKey)) {
            set.status = 401;
            return {
                message: "Invalid signature.",
            };
        }

        const user = await UserRepository.findUserByPublicKey(publicKey);
        if (user) {
            set.status = 409;
            return {
                message: "User already exists.",
            };
        }

        const newUser = await UserRepository.createUser({
            publicKey,
            address
        });

        if (!newUser) {
            set.status = 500;
            return {
                message: "Failed to create user.",
            };
        }

        const token = await jwt.sign({
            publicKey: publicKey,
            role: newUser.role
        });

        return {
            user: {
                address: newUser.address,
                role: newUser.role,
            },
            token
        };
    },
    {
        afterHandle: [FortressMiddleware.handleResponse],
        body: t.Object({
            address: t.String({
                description: "The address where the emails are going to be forwarded to.",
            }),
            blindflare: t.Object({
                type: t.Literal("AUTH"),
                publicKey: t.String({
                    description: "Public key for the user.",
                }),
                signature: t.String({
                    description: "SHA-512 signature of the user's private key.",
                }),
                version: t.String({
                    description: "Version of the Blindflare protocol.",
                }),
            }),
        }),
    }
);

export default authRouter;