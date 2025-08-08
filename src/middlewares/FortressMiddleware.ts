import type { Context } from "elysia";

import Fortress from '@blindflare/fortress';

import BaseMiddleware from './BaseMiddleware';

interface UserType {
    publicKey: string;
    encryptedSessionKey: string; // stringified encrypted ECC data
    role: string;
}

class FortressMiddleware extends BaseMiddleware {
    constructor() {
        super();

        this.handleAuthResponse = this.handleAuthResponse.bind(this);
        this.handleResponse = this.handleResponse.bind(this);
        this.handleRequest = this.handleRequest.bind(this);
    }

    public async handleAuthResponse(context: Context & { response: unknown; user: UserType | null }) {
        const { publicKey } = context.body as { publicKey: string };
        try {
            const meta = { type: 'AUTH', version: '1.0.0' };
            return Fortress.encryptTransactionWithECC(context.response, publicKey, meta);
        } catch (error) {
            return this.error(401, "Invalid session data.");
        }
    }

    async handleResponse(context: Context & { response: unknown; user: UserType | null }) {
        const body = context.body as { blindflare?: { type?: string } };
        if (body.blindflare && body.blindflare.type === "AUTH") {
            return await this.handleAuthResponse(context);
        }

        if (!context.user) {
            return this.error(401, "You need to be logged in to access this feature.");
        }

        try {
            const encryptedSessionData = JSON.parse(context.user.encryptedSessionKey);
            const sessionKey = Fortress.decryptWithECC(encryptedSessionData); // uses fortress private key

            const meta = { type: 'TRANSACTION', version: '1.0.0' };
            return Fortress.encryptTransaction(context.response, sessionKey, meta);
        } catch (error) {
            return this.error(401, "Invalid session data.");
        }
    }

    async handleRequest(context: Context & { user: UserType | null; body?: any }) {
        if (!context.user) {
            return this.error(401, "You need to be logged in to access this feature.");
        }

        if (!context.body || !context.body.blindflare) {
            return this.error(400, "Blindflare: Invalid request body.");
        }

        try {
            const encryptedSessionData = JSON.parse(context.user.encryptedSessionKey);
            const sessionKey = Fortress.decryptWithECC(encryptedSessionData);

            // Decrypt incoming transaction into a plain object
            const obj = Fortress.decryptTransaction<any>(context.body, sessionKey);
            context.body = obj;
        } catch (error) {
            return this.error(500, "Blindflare: Decryption failed.");
        }
    }
}

export default new FortressMiddleware();