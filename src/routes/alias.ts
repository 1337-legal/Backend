import Router, { t } from 'elysia';

import BlindflareMiddleware from '@Middlewares/BlindflareMiddleware';
import SessionMiddleware from '@Middlewares/SessionMiddleware';
import AliasRepository from '@Repositories/AliasRepository';
import ListenerService from '@Services/ListenerService';

const authRouter: typeof ListenerService.app = new Router();

authRouter.put(
    "/alias",
    async ({ body, user }) => {
        const { domain } = body;

        const alias = await AliasRepository.createAlias({
            address: domain,
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
            domain: t.String({
                description: "The domain to create an alias for.",
            }),
            blindflare: t.Object({
                type: t.Literal("TRANSACTION"),
                version: t.String({
                    description: "Version of the Blindflare protocol.",
                }),
            }),
        }),
    }
);

// .patch (disable/enable alias) and .delete (remove alias) routes can be added similarly

authRouter.patch(
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
                type: t.Literal("TRANSACTION", {
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

export default authRouter;