FROM oven/bun:alpine

WORKDIR /app

COPY package.json ./
COPY bun.lock ./
COPY tsconfig.json ./
COPY src/ ./src/

RUN bun install

EXPOSE 3000

CMD ["bun", "run", "start"]