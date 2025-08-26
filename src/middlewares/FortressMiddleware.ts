import type { Context } from "elysia";
import Fortress from '@blindflare/fortress';

import BaseMiddleware from './BaseMiddleware';

class FortressMiddleware extends BaseMiddleware {
    constructor() {
        super();

        this.handleRequest = this.handleRequest.bind(this);
    }

    public async handleResponse(context: Context & { response: unknown }) {
        const encryptedSessionKey = context.headers['bf-session-key'] ?? context.headers['BF-Session-Key'];
        if (typeof encryptedSessionKey !== 'string') return context.response;

        const sessionKey: string = await Fortress.unwrapSessionKey(encryptedSessionKey)

        try {
            const meta = { type: 'TX', version: '1.0.0' };
            return Fortress.encryptTransaction(context.response, sessionKey, meta);
        } catch {
            return this.error(500, 'Blindflare: Response encryption failed.');
        }
    }

    async handleRequest(context: Context & { body?: any }) {
        const encryptedSessionKey = context.headers?.['bf-session-key'] ?? (context as any).headers?.['BF-Session-Key'];
        const body = context.body as { blindflare?: { type?: string } };
        if (!body?.blindflare) return this.error(400, 'Blindflare: Missing metadata.');

        if (typeof encryptedSessionKey !== 'string') return this.error(401, 'Blindflare: Missing session key header.');
        let sessionKey: string;
        try {
            sessionKey = await Fortress.unwrapSessionKey(encryptedSessionKey);
        } catch {
            return this.error(401, 'Blindflare: Invalid session key header.');
        }

        try {
            const plain = await Fortress.decryptTransaction(context.body, sessionKey);
            context.body = plain.payload ?? plain;
        } catch {
            return this.error(400, 'Blindflare: Request decryption failed.');
        }
    }
}

export default new FortressMiddleware();