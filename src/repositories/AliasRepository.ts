import { Prisma } from '@prisma/client';

import BaseRepository from './BaseRepository';

class AliasRepository extends BaseRepository {
    async createAlias(data: Prisma.AliasCreateInput) {
        return this.prisma.alias.create({
            data,
        });
    }

    async getAliasByAddress(address: string) {
        return this.prisma.alias.findUnique({
            where: { address },
            include: { user: true },
        });
    }
}

export default new AliasRepository();