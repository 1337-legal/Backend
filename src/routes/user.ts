import Router from 'elysia';

import FortressMiddleware from '@Middlewares/FortressMiddleware';
import SessionMiddleware from '@Middlewares/SessionMiddleware';
import AliasRepository from '@Repositories/AliasRepository';
import UserRepository from '@Repositories/UserRepository';
import ListenerService from '@Services/ListenerService';

const userRouter: typeof ListenerService.app = new Router();

// Get current user profile
userRouter.get(
    '/user',
    async ({ user }) => {
        if (!user) throw new Error('Unauthorized');
        const dbUser = await UserRepository.findUserByPublicKey(user.publicKey);
        return {
            publicKey: user.publicKey,
            address: dbUser?.address || '',
            pgpPublicKey: dbUser?.pgpPublicKey ?? null,
            role: dbUser?.role || user.role,
        };
    },
    {
        beforeHandle: [
            SessionMiddleware.auth,
            FortressMiddleware.handleRequest,
        ],
        afterHandle: [FortressMiddleware.handleResponse],
    },
);

// Update current user profile (address and/or pgpPublicKey)
userRouter.patch(
    '/user',
    async ({ user, body }) => {
        if (!user) throw new Error('Unauthorized');
        const { address, pgpPublicKey } = (body || {}) as {
            address?: string;
            pgpPublicKey?: string | null;
        };

        const data: Record<string, any> = {};
        if (typeof address === 'string') data.address = address;
        if (typeof pgpPublicKey === 'string' || pgpPublicKey === null)
            data.pgpPublicKey = pgpPublicKey;

        const existing = await UserRepository.findUserByPublicKey(
            user.publicKey,
        );
        if (!existing) throw new Error('User not found');
        if (Object.keys(data).length === 0) {
            return {
                publicKey: existing.publicKey,
                address: existing.address,
                pgpPublicKey: existing.pgpPublicKey || null,
                role: existing.role,
            };
        }

        const updated = await UserRepository.updateUser(existing.id, data);
        if (!updated) {
            throw new Error('Failed to update user');
        }

        return {
            publicKey: updated.publicKey,
            address: updated.address,
            pgpPublicKey: updated.pgpPublicKey || null,
            role: updated.role,
        };
    },
    {
        beforeHandle: [
            SessionMiddleware.auth,
            FortressMiddleware.handleRequest,
        ],
        afterHandle: [FortressMiddleware.handleResponse],
    },
);

// Existing alias route
userRouter.get(
    '/alias',
    async ({ user }) => {
        if (!user) throw new Error('Unauthorized');

        const aliases = await AliasRepository.getAllByUser(user.publicKey);

        // Transform flattened Kysely results to nested structure
        return aliases.map((alias) => ({
            address: alias.aliasAddress,
            user: {
                id: alias.userId,
                address: alias.userAddress,
                publicKey: alias.publicKey,
                pgpPublicKey: alias.pgpPublicKey,
                role: alias.role,
                createdAt: alias.userCreatedAt,
                updatedAt: alias.userUpdatedAt,
            },
            createdAt: alias.aliasCreatedAt,
            updatedAt: alias.aliasUpdatedAt,
        }));
    },
    {
        beforeHandle: [
            SessionMiddleware.auth,
            FortressMiddleware.handleRequest,
        ],
        afterHandle: [FortressMiddleware.handleResponse],
    },
);

export default userRouter;
