import Router, { t } from 'elysia';

import Fortress from '@blindflare/fortress';
import FortressMiddleware from '@Middlewares/FortressMiddleware';
import UserRepository from '@Repositories/UserRepository';
import ListenerService from '@Services/ListenerService';

const authRouter: typeof ListenerService.app = new Router();

authRouter.post(
    '/auth',
    async ({ set, body, jwt }) => {
        const { address, blindflare: { publicKey, signature } } = body;

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

export default authRouter;