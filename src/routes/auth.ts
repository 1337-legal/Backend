import Router, { t } from 'elysia';

import BlindflareMiddleware from '@Middlewares/BlindflareMiddleware';
import UserRepository from '@Repositories/UserRepository';
import BlindflareService from '@Services/BlindflareService';
import ListenerService from '@Services/ListenerService';

const authRouter: typeof ListenerService.app = new Router();

authRouter.post(
    "/auth/login",
    async ({ set, body, jwt }) => {
        const { publicKey, signature } = body;

        const user = await UserRepository.findUserByPublicKey(publicKey);
        if (!user) {
            set.status = 401;
            return {
                message: "Public key not found.",
            };
        }

        if (!BlindflareService.verifySignature("AUTH", signature, publicKey)) {
            set.status = 401;
            return {
                message: "Invalid signature.",
            };
        }

        const session = BlindflareService.generateSessionKey({
            user: user.publicKey,
            expirationMinutes: 120
        });

        const encryptedSessionKey = BlindflareService.encryptWithECC(session.key, publicKey);

        const token = await jwt.sign({
            publicKey: user.publicKey,
            encryptedSessionKey: JSON.stringify(encryptedSessionKey),
            role: user.role,
        });

        return {
            user: {
                address: user.address,
                role: user.role,
            },
            blindflare: {
                key: session.key,
                expiresAt: session.expiresAt
            },
            token,
        };
    },
    {
        afterHandle: [BlindflareMiddleware.handleResponse],
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
    async ({ set, body, jwt }) => {
        const { address, publicKey, signature } = body;

        if (!BlindflareService.verifySignature("AUTH", signature, publicKey)) {
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

        const session = BlindflareService.generateSessionKey({
            user: newUser.publicKey,
            expirationMinutes: 120
        });

        const encryptedSessionData = BlindflareService.encryptWithECC(session.key, publicKey);

        const token = await jwt.sign({
            publicKey: publicKey,
            encryptedSessionKey: JSON.stringify(encryptedSessionData),
            role: newUser.role
        });

        return {
            user: {
                address: newUser.address,
                role: newUser.role,
            },
            blindflare: {
                key: session.key,
                expiresAt: session.expiresAt
            },
            token
        };
    },
    {
        afterHandle: [BlindflareMiddleware.handleResponse],
        body: t.Object({
            address: t.String({
                description: "The address where the emails are going to be forwarded to.",
            }),
            publicKey: t.String({
                description: "Public key for the user.",
            }),
            signature: t.String({
                description: "SHA-512 signature of the user's private key.",
            }),
            blindflare: t.Object({
                type: t.Literal("AUTH"),
                version: t.String({
                    description: "Version of the Blindflare protocol.",
                }),
            }),
        }),
    }
);

export default authRouter;