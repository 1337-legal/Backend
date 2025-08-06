import crypto from 'crypto';

import BaseService from './BaseService';

interface BlindflareConfig {
    algorithm: string;
    keyLength: number;
    ivLength: number;
}

export interface EncryptedData {
    data: string;
    iv: string;
    tag?: string;
    ephemeralPublicKey?: string; // For ECC encryption
}

interface BlindflareKey {
    id: string;
    key: string;
    createdAt: Date;
    expiresAt?: Date;
}

interface SessionKey {
    id: string;
    key: string;
    user?: string;
    sessionId: string;
    createdAt: Date;
    expiresAt: Date;
    isActive: boolean;
    lastUsed?: Date;
}

interface SessionKeyOptions {
    user?: string;
    expirationMinutes?: number;
    keyLength?: number;
}

class BlindflareService extends BaseService {
    private config: BlindflareConfig = {
        algorithm: 'aes-256-gcm',
        keyLength: 32,
        ivLength: 16
    };

    private privateKey: string;
    public publicKey: string;

    constructor() {
        super()

        const keypair = this.generateKeyPair()
        this.privateKey = keypair.privateKey
        this.publicKey = keypair.publicKey
    }

    /**
     * Generate a new encryption key
     */
    generateKey(): string {
        return crypto.randomBytes(this.config.keyLength).toString('hex');
    }

    /**
     * Generate a new initialization vector
     */
    private generateIV(): Buffer {
        return crypto.randomBytes(this.config.ivLength);
    }

    /**
     * Encrypt data using AES-256-GCM
     */
    encrypt(data: string, key: string): EncryptedData {
        try {
            const iv = this.generateIV();
            const cipher = crypto.createCipheriv(this.config.algorithm, Buffer.from(key, 'hex'), iv) as any;
            cipher.setAAD(Buffer.from('blindflare'));

            let encrypted = cipher.update(data, 'utf8', 'hex');
            encrypted += cipher.final('hex');

            const tag = cipher.getAuthTag();

            return {
                data: encrypted,
                iv: iv.toString('hex'),
                tag: tag.toString('hex')
            };
        } catch (error) {
            throw new Error(`Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Decrypt data using AES-256-GCM
     */
    decrypt(encryptedData: EncryptedData, key: string): string {
        try {
            const decipher = crypto.createDecipheriv(this.config.algorithm, Buffer.from(key, 'hex'), Buffer.from(encryptedData.iv, 'hex')) as any;
            decipher.setAAD(Buffer.from('blindflare'));

            if (encryptedData.tag) {
                decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'));
            }

            let decrypted = decipher.update(encryptedData.data, 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            return decrypted;
        } catch (error) {
            throw new Error(`Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Create a new Blindflare key with metadata
     */
    createKey(expirationHours?: number): BlindflareKey {
        const key = this.generateKey();
        const now = new Date();
        const expiresAt = expirationHours ? new Date(now.getTime() + expirationHours * 60 * 60 * 1000) : undefined;

        return {
            id: crypto.randomUUID(),
            key,
            createdAt: now,
            expiresAt
        };
    }

    /**
     * Validate if a key is still valid
     */
    isKeyValid(blindflareKey: BlindflareKey): boolean {
        if (!blindflareKey.expiresAt) {
            return true; // No expiration set
        }
        return new Date() < blindflareKey.expiresAt;
    }

    /**
     * Hash sensitive data for secure storage
     */
    hashData(data: string, salt?: string): { hash: string; salt: string } {
        const actualSalt = salt || crypto.randomBytes(16).toString('hex');
        const hash = crypto.pbkdf2Sync(data, actualSalt, 10000, 64, 'sha512').toString('hex');

        return { hash, salt: actualSalt };
    }

    /**
     * Verify hashed data
     */
    verifyHash(data: string, hash: string, salt: string): boolean {
        const { hash: computedHash } = this.hashData(data, salt);
        return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(computedHash, 'hex'));
    }

    /**
     * Generate a secure token for authentication
     */
    generateSecureToken(length: number = 32): string {
        return crypto.randomBytes(length).toString('hex');
    }

    /**
     * Encrypt file content
     */
    encryptFile(fileBuffer: Buffer, key: string): EncryptedData {
        const base64Data = fileBuffer.toString('base64');
        return this.encrypt(base64Data, key);
    }

    /**
     * Decrypt file content
     */
    decryptFile(encryptedData: EncryptedData, key: string): Buffer {
        const decryptedBase64 = this.decrypt(encryptedData, key);
        return Buffer.from(decryptedBase64, 'base64');
    }

    /**
     * Generate a key derivation from password
     */
    deriveKeyFromPassword(password: string, salt: string): string {
        return crypto.pbkdf2Sync(password, salt, 100000, this.config.keyLength, 'sha256').toString('hex');
    }

    /**
     * Secure data wipe (overwrite sensitive data in memory)
     */
    secureWipe(data: string | Buffer): void {
        if (typeof data === 'string') {
            data = Buffer.from(data);
        }
        data.fill(0);
    }

    /**
     * Generate digital signature
     */
    signData(data: string, privateKey: string): string {
        const sign = crypto.createSign('SHA256');
        sign.update(data);
        return sign.sign(privateKey, 'hex');
    }

    /**
     * Verify digital signature
     */
    verifySignature(data: string, signature: string, publicKey: string): boolean {
        try {
            const verify = crypto.createVerify('SHA256');
            verify.update(data);
            return verify.verify(publicKey, signature, 'hex');
        } catch (error) {
            return false;
        }
    }

    /**
     * Generate secp256k1 keypair
     */
    generateKeyPair(): { publicKey: string; privateKey: string } {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
            namedCurve: 'secp256k1', // or 'prime256v1' for P-256
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        return { publicKey, privateKey };
    }

    /**
     * Generate a new session key with metadata
     */
    generateSessionKey(options: SessionKeyOptions = {}): SessionKey {
        const {
            user,
            expirationMinutes = 60 * 2, // Default 2 hours
            keyLength = 32
        } = options;

        const sessionKey = crypto.randomBytes(keyLength).toString('hex');
        const sessionId = crypto.randomUUID();
        const now = new Date();
        const expiresAt = new Date(now.getTime() + expirationMinutes * 60 * 1000);

        return {
            id: crypto.randomUUID(),
            key: sessionKey,
            user,
            sessionId,
            createdAt: now,
            expiresAt,
            isActive: true
        };
    }

    /**
     * Validate if a session key is still valid and active
     */
    isSessionKeyValid(sessionKey: SessionKey): boolean {
        const now = new Date();
        return sessionKey.isActive && now < sessionKey.expiresAt;
    }

    /**
     * Refresh a session key (extend expiration time)
     */
    refreshSessionKey(sessionKey: SessionKey, extensionMinutes: number = 60): SessionKey {
        const now = new Date();
        return {
            ...sessionKey,
            expiresAt: new Date(now.getTime() + extensionMinutes * 60 * 1000),
            lastUsed: now
        };
    }

    /**
     * Revoke a session key (mark as inactive)
     */
    revokeSessionKey(sessionKey: SessionKey): SessionKey {
        return {
            ...sessionKey,
            isActive: false,
            lastUsed: new Date()
        };
    }

    /**
     * Generate a temporary session key for short-lived operations
     */
    generateTempSessionKey(durationMinutes: number = 15): SessionKey {
        return this.generateSessionKey({
            expirationMinutes: durationMinutes,
            keyLength: 16 // Shorter key for temporary use
        });
    }

    /**
     * Create a secure session token that combines session key with additional data
     */
    createSessionToken(sessionKey: SessionKey, additionalData?: any): string {
        const tokenData = {
            sessionId: sessionKey.sessionId,
            user: sessionKey.user,
            timestamp: new Date().toISOString(),
            ...additionalData
        };

        const tokenString = JSON.stringify(tokenData);
        const encrypted = this.encrypt(tokenString, sessionKey.key);

        // Combine encrypted data into a single token
        return Buffer.from(JSON.stringify(encrypted)).toString('base64');
    }

    /**
     * Verify and decode a session token
     */
    verifySessionToken(token: string, sessionKey: SessionKey): any {
        try {
            if (!this.isSessionKeyValid(sessionKey)) {
                throw new Error('Session key is invalid or expired');
            }

            const encryptedData = JSON.parse(Buffer.from(token, 'base64').toString());
            const decryptedString = this.decrypt(encryptedData, sessionKey.key);

            return JSON.parse(decryptedString);
        } catch (error) {
            throw new Error(`Session token verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Generate a session key pair (encryption key + signing key)
     */
    generateSessionKeyPair(options: SessionKeyOptions = {}): {
        encryptionKey: SessionKey;
        signingKeys: { publicKey: string; privateKey: string };
    } {
        const encryptionKey = this.generateSessionKey(options);
        const signingKeys = this.generateKeyPair();

        return {
            encryptionKey,
            signingKeys
        };
    }

    /**
     * Create a rotating session key that changes periodically
     */
    createRotatingSessionKey(rotationIntervalMinutes: number = 30): {
        currentKey: SessionKey;
        nextKey: SessionKey;
        rotationTime: Date;
    } {
        const currentKey = this.generateSessionKey({
            expirationMinutes: rotationIntervalMinutes * 2 // Allow overlap
        });

        const nextKey = this.generateSessionKey({
            expirationMinutes: rotationIntervalMinutes * 2
        });

        const rotationTime = new Date(Date.now() + rotationIntervalMinutes * 60 * 1000);

        return {
            currentKey,
            nextKey,
            rotationTime
        };
    }

    /**
     * Encrypt data using ECC hybrid encryption (ECIES)
     * Uses ECC for key exchange and AES-256-GCM for data encryption
     */
    encryptWithECC(data: string, publicKey: string): EncryptedData {
        try {
            // Generate ephemeral key pair
            const ephemeralKeyPair = this.generateKeyPair();

            // Derive shared secret using ECDH
            const ecdh = crypto.createECDH('secp256k1');
            ecdh.setPrivateKey(crypto.createPrivateKey(ephemeralKeyPair.privateKey).export({
                type: 'sec1',
                format: 'der'
            }));

            const publicKeyObject = crypto.createPublicKey(publicKey);
            const sharedSecret = ecdh.computeSecret(publicKeyObject.export({
                type: 'spki',
                format: 'der'
            }));

            // Derive encryption key from shared secret
            const encryptionKey = crypto.pbkdf2Sync(sharedSecret, 'blindflare-ecc', 10000, 32, 'sha256');

            // Encrypt data with derived key
            const iv = this.generateIV();
            const cipher = crypto.createCipheriv(this.config.algorithm, encryptionKey, iv) as any;
            cipher.setAAD(Buffer.from('blindflare-ecc'));

            let encrypted = cipher.update(data, 'utf8', 'hex');
            encrypted += cipher.final('hex');

            const tag = cipher.getAuthTag();

            return {
                data: encrypted,
                iv: iv.toString('hex'),
                tag: tag.toString('hex'),
                ephemeralPublicKey: ephemeralKeyPair.publicKey
            };
        } catch (error) {
            throw new Error(`ECC encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Decrypt data using ECC hybrid decryption (ECIES)
     */
    decryptWithECC(encryptedData: EncryptedData & { ephemeralPublicKey: string }, privateKey: string = this.privateKey): string {
        try {
            // Create ECDH instance with our private key
            const ecdh = crypto.createECDH('secp256k1');
            const privateKeyObject = crypto.createPrivateKey(privateKey);
            ecdh.setPrivateKey(privateKeyObject.export({
                type: 'sec1',
                format: 'der'
            }));

            // Compute shared secret using ephemeral public key
            const ephemeralPublicKeyObject = crypto.createPublicKey(encryptedData.ephemeralPublicKey);
            const sharedSecret = ecdh.computeSecret(ephemeralPublicKeyObject.export({
                type: 'spki',
                format: 'der'
            }));

            // Derive decryption key from shared secret
            const decryptionKey = crypto.pbkdf2Sync(sharedSecret, 'blindflare-ecc', 10000, 32, 'sha256');

            // Decrypt data
            const decipher = crypto.createDecipheriv(
                this.config.algorithm,
                decryptionKey,
                Buffer.from(encryptedData.iv, 'hex')
            ) as any;
            decipher.setAAD(Buffer.from('blindflare-ecc'));

            if (encryptedData.tag) {
                decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'));
            }

            let decrypted = decipher.update(encryptedData.data, 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            return decrypted;
        } catch (error) {
            throw new Error(`ECC decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Encrypt file content using ECC
     */
    encryptFileWithECC(fileBuffer: Buffer, publicKey: string): EncryptedData & { ephemeralPublicKey: string } {
        const base64Data = fileBuffer.toString('base64');
        return this.encryptWithECC(base64Data, publicKey) as EncryptedData & { ephemeralPublicKey: string };
    }

    /**
     * Decrypt file content using ECC
     */
    decryptFileWithECC(encryptedData: EncryptedData & { ephemeralPublicKey: string }, privateKey: string): Buffer {
        const decryptedBase64 = this.decryptWithECC(encryptedData, privateKey);
        return Buffer.from(decryptedBase64, 'base64');
    }

    /**
     * Create a secure ECC session token
     */
    createECCSessionToken(sessionKey: SessionKey, recipientPublicKey: string, additionalData?: any): string {
        const tokenData = {
            sessionId: sessionKey.sessionId,
            user: sessionKey.user,
            timestamp: new Date().toISOString(),
            ...additionalData
        };

        const tokenString = JSON.stringify(tokenData);
        const encrypted = this.encryptWithECC(tokenString, recipientPublicKey);

        return Buffer.from(JSON.stringify(encrypted)).toString('base64');
    }

    /**
     * Verify and decode an ECC session token
     */
    verifyECCSessionToken(token: string, privateKey: string): any {
        try {
            const encryptedData = JSON.parse(Buffer.from(token, 'base64').toString());
            const decryptedString = this.decryptWithECC(encryptedData, privateKey);

            return JSON.parse(decryptedString);
        } catch (error) {
            throw new Error(`ECC session token verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
}

export default new BlindflareService();