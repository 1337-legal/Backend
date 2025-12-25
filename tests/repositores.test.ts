import {beforeEach, describe, expect, mock, test} from 'bun:test';
import {Kysely, Selectable} from 'kysely';
import type {Alias, DB, User} from '../src/types/database';

type UserRecord = Selectable<User>;
type AliasRecord = Selectable<Alias>;

interface AliasJsonResult {
    address: string;
    createdAt: string;
    id: number;
    status: 'active' | 'disabled';
    updatedAt: string;
    userId: number;
}

interface UserJsonResult {
    address: string;
    createdAt: string;
    id: number;
    pgpPublicKey: string | null;
    publicKey: string;
    role: 'guest' | 'user';
    updatedAt: string;
}

interface AliasWithUserResult {
    Alias: AliasJsonResult | null;
    User: UserJsonResult | null;
}

type GetAllByUserResult = Awaited<ReturnType<typeof AliasRepository.getAllByUser>>;

const mockExecuteTakeFirst = mock<() => Promise<UserRecord | AliasRecord | undefined>>(() =>
    Promise.resolve(undefined)
);
const mockExecute = mock<() => Promise<Array<unknown>>>(() => Promise.resolve([]));
const mockReturningAll = mock(() => ({
    executeTakeFirst: mockExecuteTakeFirst,
    execute: mockExecute,
}));

const mockSelectFrom = mock(() => ({
    selectAll: mock(() => ({
        where: mock(() => ({
            selectAll: mock(() => ({executeTakeFirst: mockExecuteTakeFirst})),
        })),
    })),
    where: mock(() => ({
        selectAll: mock(() => ({executeTakeFirst: mockExecuteTakeFirst})),
        returningAll: mockReturningAll,
        select: mock(() => ({executeTakeFirst: mockExecuteTakeFirst})),
    })),
    innerJoin: mock(() => ({
        where: mock(() => ({
            select: mock(() => ({execute: mockExecute})),
            selectAll: mock(() => ({execute: mockExecute})),
        })),
    })),
    select: mock(() => ({executeTakeFirst: mockExecuteTakeFirst})),
}));

const mockValues = mock(() => ({
    returningAll: mockReturningAll,
}));

const mockSet = mock(() => ({
    where: mock(() => ({
        returningAll: mockReturningAll,
    })),
}));

const mockDatabase = {
    selectFrom: mockSelectFrom,
    insertInto: mock(() => ({values: mockValues})),
    updateTable: mock(() => ({set: mockSet})),
    deleteFrom: mock(() => ({where: mock(() => ({returningAll: mockReturningAll}))})),
} as unknown as Kysely<DB>;

mock.module('../src/drivers/Database', () => ({
    default: mockDatabase,
}));

const UserRepository = (await import('../src/repositories/UserRepository')).default;
const AliasRepository = (await import('../src/repositories/AliasRepository')).default;

function createMockUser(overrides: Partial<UserRecord> = {}): UserRecord {
    return {
        id: 1,
        publicKey: 'test-public-key',
        address: 'test@example.com',
        role: 'user',
        pgpPublicKey: null,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        ...overrides,
    } as UserRecord;
}

function createMockAlias(overrides: Partial<AliasRecord> = {}): AliasRecord {
    return {
        id: 1,
        address: 'alias@example.com',
        userId: 1,
        status: 'active',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        ...overrides,
    } as AliasRecord;
}

describe('UserRepository', () => {
    beforeEach(() => {
        mockExecuteTakeFirst.mockReset();
        mockExecute.mockReset();
    });

    describe('findUserById', () => {
        test('should return user when found', async () => {
            const mockUser = createMockUser();
            mockExecuteTakeFirst.mockResolvedValueOnce(mockUser);

            const result = await UserRepository.findUserById(1);

            expect(mockDatabase.selectFrom).toHaveBeenCalledWith('User');
            expect(result).toEqual(mockUser);
        });

        test('should return undefined when user not found', async () => {
            mockExecuteTakeFirst.mockResolvedValueOnce(undefined);

            const result = await UserRepository.findUserById(999);

            expect(result).toBeUndefined();
        });
    });

    describe('findUserByPublicKey', () => {
        test('should return user when found by public key', async () => {
            const mockUser = createMockUser();
            mockExecuteTakeFirst.mockResolvedValueOnce(mockUser);

            const result = await UserRepository.findUserByPublicKey('test-public-key');

            expect(mockDatabase.selectFrom).toHaveBeenCalledWith('User');
            expect(result).toEqual(mockUser);
        });

        test('should return undefined when public key not found', async () => {
            mockExecuteTakeFirst.mockResolvedValueOnce(undefined);

            const result = await UserRepository.findUserByPublicKey('non-existent-key');

            expect(result).toBeUndefined();
        });
    });

    describe('createUser', () => {
        test('should create and return new user', async () => {
            const newUser = {
                publicKey: 'new-public-key',
                address: 'new@example.com',
            };
            const createdUser = createMockUser({
                id: 2,
                publicKey: newUser.publicKey,
                address: newUser.address,
                role: 'guest',
            });
            mockExecuteTakeFirst.mockResolvedValueOnce(createdUser);

            const result = await UserRepository.createUser(newUser);

            expect(mockDatabase.insertInto).toHaveBeenCalledWith('User');
            expect(result).toEqual(createdUser);
        });
    });

    describe('updateUser', () => {
        test('should update and return modified user', async () => {
            const updatedUser = createMockUser({address: 'updated@example.com'});
            mockExecuteTakeFirst.mockResolvedValueOnce(updatedUser);

            const result = await UserRepository.updateUser(1, {address: 'updated@example.com'});

            expect(mockDatabase.updateTable).toHaveBeenCalledWith('User');
            expect(result).toEqual(updatedUser);
        });
    });

    describe('deleteUser', () => {
        test('should delete user and return result', async () => {
            await UserRepository.deleteUser(1);

            expect(mockDatabase.deleteFrom).toHaveBeenCalledWith('User');
        });
    });
});

describe('AliasRepository', () => {
    beforeEach(() => {
        mockExecuteTakeFirst.mockReset();
        mockExecute.mockReset();
    });

    describe('createAlias', () => {
        test('should create and return new alias', async () => {
            const newAlias = {
                address: 'alias@example.com',
                userId: 1,
            };
            const createdAlias = createMockAlias(newAlias);
            mockExecuteTakeFirst.mockResolvedValueOnce(createdAlias);

            const result = await AliasRepository.createAlias(newAlias);

            expect(mockDatabase.insertInto).toHaveBeenCalledWith('Alias');
            expect(result).toEqual(createdAlias);
        });
    });

    describe('getAliasByAddress', () => {
        test('should return alias with user when found', async () => {
            const now = new Date().toISOString();
            const mockResult: AliasWithUserResult = {
                Alias: {id: 1, address: 'alias@example.com', userId: 1, status: 'active', createdAt: now, updatedAt: now},
                User: {
                    id: 1,
                    publicKey: 'test-key',
                    address: 'user@example.com',
                    role: 'user',
                    pgpPublicKey: null,
                    createdAt: now,
                    updatedAt: now
                },
            };
            mockExecuteTakeFirst.mockResolvedValueOnce(mockResult as unknown as UserRecord);

            const result = await AliasRepository.getAliasByAddress('alias@example.com');

            expect(mockDatabase.selectFrom).toHaveBeenCalledWith('Alias');
            expect(result).toEqual(mockResult as unknown as typeof result);
        });

        test('should return undefined when alias not found', async () => {
            mockExecuteTakeFirst.mockResolvedValueOnce(undefined);

            const result = await AliasRepository.getAliasByAddress('non-existent@example.com');

            expect(result).toBeUndefined();
        });
    });

    describe('getAllByUser', () => {
        test('should return all aliases for a user', async () => {
            const now = new Date().toISOString();
            const mockResults: AliasWithUserResult[] = [
                {
                    Alias: {id: 1, address: 'alias1@example.com', userId: 1, status: 'active', createdAt: now, updatedAt: now},
                    User: {
                        id: 1,
                        publicKey: 'test-key',
                        address: 'user@example.com',
                        role: 'user',
                        pgpPublicKey: null,
                        createdAt: now,
                        updatedAt: now
                    },
                },
                {
                    Alias: {id: 2, address: 'alias2@example.com', userId: 1, status: 'active', createdAt: now, updatedAt: now},
                    User: {
                        id: 1,
                        publicKey: 'test-key',
                        address: 'user@example.com',
                        role: 'user',
                        pgpPublicKey: null,
                        createdAt: now,
                        updatedAt: now
                    },
                },
            ];

            mockExecute.mockResolvedValueOnce(mockResults);

            const result = await AliasRepository.getAllByUser('test-key');

            expect(mockDatabase.selectFrom).toHaveBeenCalledWith('Alias');
            expect(result).toEqual(mockResults as unknown as GetAllByUserResult);
        });

        test('should return empty array when user has no aliases', async () => {
            mockExecute.mockResolvedValueOnce([]);

            const result = await AliasRepository.getAllByUser('no-aliases-key');

            expect(result).toEqual([]);
        });
    });
});

