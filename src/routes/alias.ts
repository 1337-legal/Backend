import Router, { t } from 'elysia';
import { generateRandomWords } from 'src/lib/utils';

import BlindflareMiddleware from '@Middlewares/FortressMiddleware';
import SessionMiddleware from '@Middlewares/SessionMiddleware';
import AliasRepository from '@Repositories/AliasRepository';
import ListenerService from '@Services/ListenerService';

const aliasRouter: typeof ListenerService.app = new Router();

aliasRouter.put(
    "/alias",
    async ({ user }) => {
        const address = generateRandomWords(3).replace(/\s+/g, '-').toLowerCase();

        const alias = await AliasRepository.createAlias({
            address: address + '@1337.legal',
            user: {
                connect: { publicKey: user?.publicKey }
            }
        });

        return {
            address: alias.address,
        };
    },
    {
        beforeHandle: [SessionMiddleware.auth, BlindflareMiddleware.handleRequest],
        afterHandle: [BlindflareMiddleware.handleResponse],
        detail: "Create an alias",
        body: t.Object({
            blindflare: t.Object({
                type: t.Literal("TX"),
                version: t.String({
                    description: "Version of the Blindflare protocol.",
                }),
            }),
        }),
    }
);

aliasRouter.patch(
    "/alias/:address",
    async ({ params }) => {
        const { address } = params;

        const alias = await AliasRepository.getAliasByAddress(address);
        if (!alias) {
            throw new Error("Alias not found");
        }

        return {
            address: alias.address,
            user: alias.user,
        };
    },
    {
        beforeHandle: [SessionMiddleware.auth, BlindflareMiddleware.handleRequest],
        afterHandle: [BlindflareMiddleware.handleResponse],
        detail: "Change alias status. This can be used to enable or disable an alias.",
        body: t.Object({
            blindflare: t.Object({
                type: t.Literal("TX", {
                    description: "Type of the Blindflare protocol.",
                }),
                payload: t.Object({
                    data: t.String({
                        description: "Encrypted data containing the alias information.\n",
                    }),
                    iv: t.String({
                        description: "Initialization vector for the encryption.",
                    }),
                    tag: t.String({
                        description: "Authentication tag for the encryption.",
                    }),
                    ephemeralPublicKey: t.String({
                        description: "Ephemeral public key used for the encryption.",
                    }),
                }),
                version: t.String({
                    description: "Version of the Blindflare protocol.",
                }),
            }),
        }),
    }
);

export default aliasRouter;