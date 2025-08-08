import Router, { t } from 'elysia';

import Fortress from '@blindflare/fortress';
import ListenerService from '@Services/ListenerService';

const blindflareRouter: typeof ListenerService.app = new Router();

blindflareRouter.post(
    '/blindflare/hello',
    async ({ set, body }) => {
        const hello = (body?.blindflare || body) as {
            type: 'HELLO';
            ver: '1';
            publicKey: string;
            signature: string;
            nonce: string;
            ts: number;
            caps?: { enc: string[]; ecc: string[]; ser: string[] };
        };

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
            const serverHello = (Fortress as any).createServerHello(clientHello);
            return { blindflare: serverHello };
        } catch (e) {
            set.status = 401;
            return { message: 'Handshake failed' };
        }
    },
    {
        body: t.Object({
            blindflare: t.Object({
                type: t.Literal('HELLO'),
                ver: t.Literal('1'),
                publicKey: t.String({ description: 'Client public key (hex)' }),
                nonce: t.String(),
                ts: t.Number(),
                caps: t.Object({
                    enc: t.Array(t.String()),
                    ecc: t.Array(t.String()),
                    ser: t.Array(t.String()),
                }),
                signature: t.String(),
            }),
        }),
    }
);

export default blindflareRouter;
