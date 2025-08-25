import Router, { t } from 'elysia';

import Fortress from '@blindflare/fortress';
import FortressMiddleware from '@Middlewares/FortressMiddleware';
import UserRepository from '@Repositories/UserRepository';
import ListenerService from '@Services/ListenerService';
import VerificationService from '@Services/VerificationService';

const authRouter: typeof ListenerService.app = new Router();

authRouter.post(
    '/auth',
    async ({ set, body, jwt }) => {
        const { address, blindflare: { publicKey, signature } } = body as any;

        if (!Fortress.verifySignature('AUTH', signature, publicKey)) {
            set.status = 401;
            return { message: 'Invalid signature.' };
        }

        let user = await UserRepository.findUserByPublicKey(publicKey);

        if (!user) {
            if (!address) {
                set.status = 400;
                return { message: 'Address required for registration.' };
            }

            user = await UserRepository.createUser({ publicKey, address });
            if (!user) {
                set.status = 500;
                return { message: 'Failed to create user.' };
            }
        }

        const token = await jwt.sign({ publicKey: user.publicKey, role: user.role });

        return {
            user: { address: user.address, role: user.role },
            token
        };
    },
    {
        afterHandle: [FortressMiddleware.handleResponse],
        body: t.Object({
            address: t.Optional(t.String({
                description: 'Forwarding address required only when registering a new user.',
            })),
            blindflare: t.Object({
                type: t.Literal('AUTH'),
                publicKey: t.String({ description: 'Public key for the user.' }),
                signature: t.String({ description: "SHA-512 signature of the user's private key." }),
                version: t.String({ description: 'Version of the Blindflare protocol.' }),
            }),
        }),
    }
);

authRouter.post(
    '/auth/send-code',
    async ({ set, body }) => {
        const email = (body as any).email?.trim().toLowerCase();
        const pgp = ((body as any).pgp || '').trim();

        try {
            await VerificationService.sendCode(email, pgp);
            return { ok: true };
        } catch (e: any) {
            const status = typeof e?.status === 'number' ? e.status : 500;
            set.status = status;
            return { message: e?.message || 'Failed to send verification. Try again later.' };
        }
    },
    {
        beforeHandle: [FortressMiddleware.handleRequest],
        afterHandle: [FortressMiddleware.handleResponse],
    }
);

authRouter.post(
    '/auth/verify-code',
    async ({ set, body }) => {
        const email = (body as any).email?.trim().toLowerCase();
        const code = (((body as any).code || '') as string).trim();

        try {
            await VerificationService.verifyCode(email, code);
            return { ok: true };
        } catch (e: any) {
            const status = typeof e?.status === 'number' ? e.status : 400;
            set.status = status;
            return { message: e?.message || 'Verification failed' };
        }
    },
    {
        beforeHandle: [FortressMiddleware.handleRequest],
        afterHandle: [FortressMiddleware.handleResponse]
    }
);

export default authRouter;