import type { Context } from "elysia";

import BlindflareService, {
    BlindflareResponseBody, EncryptedData
} from '@Services/BlindflareService';

import BaseMiddleware from './BaseMiddleware';

interface UserType {
    publicKey: string;
    encryptedSessionKey: string;
    role: string;
}

class BlindflareMiddleware extends BaseMiddleware {
    constructor() {
        super();

        this.handleAuthResponse = this.handleAuthResponse.bind(this);
        this.handleResponse = this.handleResponse.bind(this);
        this.handleRequest = this.handleRequest.bind(this);
    }

    public async handleAuthResponse(context: Context & { response: unknown; user: UserType | null }) {
        //if (!context.user) {
        //    return this.error(401, "You need to be logged in to access this feature.");
        //}
        const { publicKey } = context.body as BlindflareResponseBody;

        try {
            context.response = BlindflareService.encryptWithECC(
                JSON.stringify(context.response),
                context.body.publicKey
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
        const body = context.body as { blindflare?: { type?: string } };
        console.log(body)
        if (body.blindflare && body.blindflare.type === "AUTH") {
            return await this.handleAuthResponse(context);
        }

        if (!context.user) {
            return this.error(401, "You need to be logged in to access this feature.");
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

    async handleRequest(context: Context & { user: UserType | null; body?: BlindflareResponseBody }) {
        if (!context.user) {
            return this.error(401, "You need to be logged in to access this feature.");
        }

        if (!context.body || !context.body.blindflare.payload || !context.body.blindflare) {
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