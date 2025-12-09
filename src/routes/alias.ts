import Router, {t} from 'elysia';
import {generateRandomWords} from 'src/lib/utils';

import FortressMiddleware from '@Middlewares/FortressMiddleware';
import SessionMiddleware from '@Middlewares/SessionMiddleware';
import AliasRepository from '@Repositories/AliasRepository';
import UserRepository from '@Repositories/UserRepository';
import ListenerService from '@Services/ListenerService';

const aliasRouter: typeof ListenerService.app = new Router();

aliasRouter.post(
    '/alias',
    async ({ user }) => {
        const address = generateRandomWords(3)
            .replace(/\s+/g, '-')
            .toLowerCase();

        const dbUser = await UserRepository.findUserByPublicKey(
            user?.publicKey!,
        );
        if (!dbUser) {
            throw new Error('User not found');
        }

        const alias = await AliasRepository.createAlias({
            address: address + '@1337.legal',
            userId: dbUser.id,
        });

        return {
            address: alias!.address,
        };
    },
    {
        beforeHandle: [
            SessionMiddleware.auth,
            FortressMiddleware.handleRequest,
        ],
        afterHandle: FortressMiddleware.handleResponse,
        detail: 'Create an alias',
        body: t.Object({
            blindflare: t.Object({
                type: t.Literal('TX'),
                version: t.String({
                    description: 'Version of the Blindflare protocol.',
                }),
            }),
        }),
    },
);

aliasRouter.patch(
    '/alias/:address',
    async ({ params }) => {
        const { address } = params;

        const alias = await AliasRepository.getAliasByAddress(address);
        if (!alias) {
            throw new Error('Alias not found');
        }

        return {
            address: alias.Alias?.address,
            createdAt: alias.Alias?.createdAt,
            updatedAt: alias.Alias?.updatedAt,
        };
    },
    {
        beforeHandle: [
            SessionMiddleware.auth,
            FortressMiddleware.handleRequest,
        ],
        afterHandle: [FortressMiddleware.handleResponse],
        detail: 'Change alias status. This can be used to enable or disable an alias.',
        body: t.Object({
            blindflare: t.Object({
                type: t.Literal('TX', {
                    description: 'Type of the Blindflare protocol.',
                }),
                payload: t.Object({
                    data: t.String({
                        description:
                            'Encrypted data containing the alias information.\n',
                    }),
                    iv: t.String({
                        description:
                            'Initialization vector for the encryption.',
                    }),
                    tag: t.String({
                        description: 'Authentication tag for the encryption.',
                    }),
                    ephemeralPublicKey: t.String({
                        description:
                            'Ephemeral public key used for the encryption.',
                    }),
                }),
                version: t.String({
                    description: 'Version of the Blindflare protocol.',
                }),
            }),
        }),
    },
);

aliasRouter.get(
    '/alias',
    async ({ user }) => {
        return await AliasRepository.getAllByUser(user.publicKey);
    },
    {
        beforeHandle: [
            SessionMiddleware.auth,
            FortressMiddleware.handleRequest,
        ],
        afterHandle: [FortressMiddleware.handleResponse],
    },
);

export default aliasRouter;
