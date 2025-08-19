import Router, { t } from 'elysia';

import Fortress from '@blindflare/fortress';
import ListenerService from '@Services/ListenerService';

const blindflareRouter: typeof ListenerService.app = new Router();

blindflareRouter.post(
    '/blindflare/hello',
    async ({ set, body }) => {
        const hello = body.blindflare

        const clientHello = {
            type: 'HELLO' as const,
            ver: '1' as const,
            clientPub: hello.publicKey,
            nonce: hello.nonce,
            ts: hello.ts,
            caps: hello.caps || { enc: ['aes-256-gcm'], ecc: ['secp256k1'], ser: ['json'] },
            sig: hello.signature,
        };

        if (!clientHello.clientPub || !clientHello.nonce || !clientHello.ts || !clientHello.sig) {
            set.status = 400;
            return { message: 'Invalid ClientHello' };
        }

        try {
            const serverHello = Fortress.createServerHello(clientHello);
            return { blindflare: serverHello };
        } catch (e) {

            console.log(e)
            set.status = 401;
            return { message: 'Handshake failed' };
        }
    },
    {
        body: t.Object({
            blindflare: t.Object({
                type: t.Literal('HELLO', {
                    description: 'ClientHello message type'
                }),
                ver: t.Literal('1'),
                publicKey: t.String({ description: 'Client public key for exchange (hex)' }),
                nonce: t.String({
                    description: 'Client nonce (hex)'
                }),
                ts: t.Number({
                    description: 'Client timestamp (ms)'
                }),
                caps: t.Object({
                    enc: t.Array(t.String({
                        description: 'Client capabilities: encryption algorithms'
                    })),
                    ecc: t.Array(t.String({
                        description: 'Client capabilities: ECC curves'
                    })),
                    ser: t.Array(t.String({
                        description: 'Client capabilities: serialization formats'
                    })),
                }),
                signature: t.String({
                    description: 'Client signature (hex)'
                }),
            }),
        }),
    }
);

export default blindflareRouter;
