# @blindflare/fortress

Advanced cryptographic service with AES-256-GCM, secp256k1 ECC (hex-only), digital signatures, and session/transaction utilities.

- AES-256-GCM symmetric encryption with AAD
- ECIES-like hybrid encryption on secp256k1 (hex keys only, no PEM)
- Session key generation, rotation, tokens
- ECDSA signatures (secp256k1, SHA-256)
- Hashing (PBKDF2-SHA512), secure token generation, memory wipe
- Transaction helpers: serialize, encrypt, and decrypt into typed objects

## Installation

```bash
npm install @blindflare/fortress
```

Node.js >= 16, Bun recommended.

## Quick start

```ts
import blindflare, { Fortress } from '@blindflare/fortress';

// Singleton usage
const key = blindflare.generateKey();
const encrypted = blindflare.encrypt('Hello, World!', key);
const decrypted = blindflare.decrypt(encrypted, key);

// Custom instance
const svc = new Fortress();
const session = svc.generateSessionKey({ user: 'alice', expirationMinutes: 60 });
```

## AES-GCM (symmetric)

```ts
const key = blindflare.generateKey(); // hex
const payload = { msg: 'secret' };

const enc = blindflare.encrypt(JSON.stringify(payload), key);
const dec = JSON.parse(blindflare.decrypt(enc, key));
```

## ECC hybrid (hex-only)

- Keys are hex strings (uncompressed SEC1 for public keys: 04 + X + Y)
- No PEM involved

```ts
const { publicKey, privateKey } = blindflare.generateKeyPair(); // hex

const encECC = blindflare.encryptWithECC('top secret', publicKey);
// encECC includes { data, iv, tag, ephemeralPublicKey }

const decECC = blindflare.decryptWithECC(encECC, privateKey);
```

## Digital signatures

```ts
const { publicKey, privateKey } = blindflare.generateKeyPair();
const signature = blindflare.signData('message', privateKey);
const ok = blindflare.verifySignature('message', signature, publicKey);
```

## Sessions and tokens

```ts
const sessionKey = blindflare.generateSessionKey({ user: 'alice', expirationMinutes: 120 });

const token = blindflare.createSessionToken(sessionKey, { role: 'admin' });
const claims = blindflare.verifySessionToken(token, sessionKey);
```

## Transactions (serialize, encrypt, decrypt)

```ts
import type { BlindflareMeta } from '@blindflare/fortress';

const meta: BlindflareMeta = { type: 'TRANSACTION', version: '1.0.0' };
const payload = { amount: 100, currency: 'USD' };

// Symmetric
const tx = blindflare.encryptTransaction(payload, key, meta);
const obj = blindflare.decryptTransaction<typeof payload>(tx, key);

// ECC (hex keys)
const { publicKey, privateKey } = blindflare.generateKeyPair();
const txECC = blindflare.encryptTransactionWithECC(payload, publicKey, meta);
const objECC = blindflare.decryptECCTransaction<typeof payload>(txECC, privateKey);
```

Note: serializeTransaction(payload, meta) creates a body with plaintext payload and metadata for debugging or custom pipelines; do not send plaintext in production.

## File encryption (symmetric)

```ts
const fileBuffer = Buffer.from('file contents');
const key = blindflare.generateKey();

const encFile = blindflare.encrypt(fileBuffer.toString('base64'), key);
const decFile = Buffer.from(blindflare.decrypt(encFile, key), 'base64');
```

## Types

```ts
interface EncryptedData {
  data: string; // hex ciphertext
  iv: string;   // hex IV
  tag?: string; // hex GCM tag
}

interface EncryptedECCData extends EncryptedData {
  ephemeralPublicKey: string; // hex (04 + X + Y)
}

interface SessionKey {
  id: string;
  key: string; // hex
  user?: string;
  sessionId: string;
  createdAt: Date;
  expiresAt: Date;
  isActive: boolean;
  lastUsed?: Date;
}
```

## Testing

```bash
bun test
```

## Security notes

- AES-GCM with 12-byte IV and AAD to bind context
- ECDSA on secp256k1 with SHA-256 message hashing
- PBKDF2-SHA512 for hashing and key derivation helpers
- Constant-time comparisons where applicable

## License

MIT

## Author

Sierra