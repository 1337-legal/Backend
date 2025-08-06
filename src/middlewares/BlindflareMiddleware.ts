import type { Context } from "elysia";

import BlindflareService, { EncryptedData } from '@Services/BlindflareService';

import BaseMiddleware from './BaseMiddleware';

interface UserType {
    publicKey: string;
    encryptedSessionKey: string;
    role: string;
}

class BlindflareMiddleware extends BaseMiddleware {
    async handleAuthResponse(context: Context & { response: unknown; user: UserType | null }) {
        if (!context.user) {
            return this.error(401, "You need to be logged in to access this feature.");
        }

        try {
            context.response = BlindflareService.encryptWithECC(
                JSON.stringify(context.response),
                context.user.publicKey
            );

            return {
                data: context.response,
                blindflare: {
                    type: "AUTH",
                    version: "1.0.0"
                }
            };
        } catch (error) {
            return this.error(401, "Invalid session data.");
        }
    }

    async handleResponse(context: Context & { response: unknown; user: UserType | null }) {
        if (!context.user) {
            return this.error(401, "You need to be logged in to access this feature.");
        }

        const body = context.body as { blindflare?: { type?: string } };
        if (body.blindflare && body.blindflare.type === "AUTH") {
            return this.handleAuthResponse(context);
        }

        try {
            const encryptedSessionData = JSON.parse(context.user.encryptedSessionKey);
            const sessionKey = BlindflareService.decryptWithECC(encryptedSessionData);

            return {
                data: BlindflareService.encrypt(JSON.stringify(context.response), sessionKey),
                blindflare: {
                    type: "TRANSACTION",
                    version: "1.0.0"
                }
            };
        } catch (error) {
            return this.error(401, "Invalid session data.");
        }
    }

    async handleRequest(context: Context & { user: UserType | null; body?: { data?: EncryptedData; blindflare?: unknown } }) {
        if (!context.user) {
            return this.error(401, "You need to be logged in to access this feature.");
        }

        if (!context.body || !context.body.data || !context.body.blindflare) {
            return this.error(400, "Blindflare: Invalid request body.");
        }

        try {
            const encryptedSessionData = JSON.parse(context.user.encryptedSessionKey);
            const sessionKey = BlindflareService.decryptWithECC(encryptedSessionData);

            context.body = JSON.parse(BlindflareService.decrypt(context.body.data, sessionKey));
        } catch (error) {
            this.error(500, "Blindflare: Decryption failed.");
        }
    }
}

export default new BlindflareMiddleware();