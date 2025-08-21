FROM oven/bun:debian

WORKDIR /app

COPY package.json ./
COPY bun.lock ./
COPY .env ./
COPY prisma/ ./
COPY tsconfig.json ./
COPY src/ ./src/

RUN apt update && apt install -y curl
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs

RUN bun install

EXPOSE 3000

CMD ["bash", "-c", "bunx prisma generate && bun run start"]
