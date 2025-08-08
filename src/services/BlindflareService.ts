import crypto from 'crypto';
import { ec as EC } from 'elliptic';

import BaseService from './BaseService';

// Initialize secp256k1 curve
const ec = new EC('secp256k1');

type BlindflareConfig = {
    algorithm: string;
    keyLength: number;
    ivLength: number;
}

export type EncryptedData = {
    data: string;
    iv: string;
    tag?: string;
    ephemeralPublicKey?: string; // For ECC encryption
}

export type BlindflareResponseBody = {
    blindflare: {
        payload?: EncryptedData;
        type: string;
        version: string;
    }
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
     * Generate digital signature using elliptic curve
     */
    signData(data: string, privateKey: string): string {
        try {
            // Convert PEM private key to elliptic private key
            const ellipticPrivateKey = this.pemToEllipticPrivateKey(privateKey);

            // Create SHA256 hash of the data
            const messageHash = crypto.createHash('sha256').update(data).digest();

            // Sign the hash
            const signature = ellipticPrivateKey.sign(messageHash);

            // Convert signature to DER format
            return signature.toDER('hex');
        } catch (error) {
            throw new Error(`Signing failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    /**
     * Verify digital signature using elliptic curve
     */
    verifySignature(data: string, signature: string, publicKey: string): boolean {
        try {
            const ellipticPublicKey = ec.keyFromPublic(publicKey, 'hex');

            // Create SHA256 hash of the data
            const messageHash = crypto.createHash('sha256').update(data).digest();

            // Verify signature using elliptic
            return ellipticPublicKey.verify(messageHash, signature);
        } catch (error) {
            console.error('Signature verification error:', error);
            return false;
        }
    }

    /**
     * Generate secp256k1 keypair using elliptic
     */
    generateKeyPair(): { publicKey: string; privateKey: string } {
        // Generate keypair using elliptic
        const keyPair = ec.genKeyPair();

        // Get private key as hex
        const privateKeyHex = keyPair.getPrivate('hex');

        // Get public key as hex (uncompressed)
        const publicKeyHex = keyPair.getPublic('hex');

        // Convert to PEM format for compatibility with crypto operations
        const privateKeyPEM = this.hexToPEMPrivate(privateKeyHex);
        const publicKeyPEM = this.hexToPEMPublic(publicKeyHex);

        return { publicKey: publicKeyPEM, privateKey: privateKeyPEM };
    }

    /**
     * Convert hex private key to PEM format
     */
    private hexToPEMPrivate(privateKeyHex: string): string {
        // Basic PEM wrapper for secp256k1 private key
        const header = '-----BEGIN EC PRIVATE KEY-----';
        const footer = '-----END EC PRIVATE KEY-----';

        // Simple DER encoding for secp256k1 private key
        const version = '01';
        const privateKeyOctet = '0420' + privateKeyHex;
        const parameters = 'A00706052B8104000A'; // secp256k1 curve parameters

        const derContent = '30' + // SEQUENCE
            '74' + // length
            '0201' + version + // INTEGER version
            privateKeyOctet + // OCTET STRING private key
            parameters; // curve parameters

        // Convert to base64
        const hexBytes = derContent.match(/.{2}/g) || [];
        const bytes = hexBytes.map(hex => String.fromCharCode(parseInt(hex, 16))).join('');
        const base64 = Buffer.from(bytes, 'binary').toString('base64');

        // Format with line breaks
        const formatted = base64.match(/.{1,64}/g)?.join('\n') || base64;

        return `${header}\n${formatted}\n${footer}`;
    }

    /**
     * Convert hex public key to PEM format
     */
    private hexToPEMPublic(publicKeyHex: string): string {
        const header = '-----BEGIN PUBLIC KEY-----';
        const footer = '-----END PUBLIC KEY-----';

        // DER encoding for secp256k1 public key
        const derPrefix = '3056301006072a8648ce3d020106052b8104000a034200';
        const derEncoded = derPrefix + publicKeyHex;

        // Convert to base64
        const hexBytes = derEncoded.match(/.{2}/g) || [];
        const bytes = hexBytes.map(hex => String.fromCharCode(parseInt(hex, 16))).join('');
        const base64 = Buffer.from(bytes, 'binary').toString('base64');

        // Format with line breaks
        const formatted = base64.match(/.{1,64}/g)?.join('\n') || base64;

        return `${header}\n${formatted}\n${footer}`;
    }

    /**
     * Convert PEM private key to elliptic private key
     */
    private pemToEllipticPrivateKey(pemKey: string): any {
        // Extract hex from PEM (simplified approach)
        const lines = pemKey.split('\n').filter(line =>
            !line.includes('BEGIN') && !line.includes('END') && line.trim()
        );
        const base64 = lines.join('');
        const der = Buffer.from(base64, 'base64');

        // For our simplified DER format, extract the private key hex
        // This is a basic extraction - in production, use proper ASN.1 parsing
        const derHex = der.toString('hex');
        const privateKeyMatch = derHex.match(/0420([a-f0-9]{64})/i);

        if (privateKeyMatch) {
            return ec.keyFromPrivate(privateKeyMatch[1], 'hex');
        }

        throw new Error('Could not extract private key from PEM');
    }

    /**
     * Convert PEM public key to elliptic public key
     */
    private pemToEllipticPublicKey(pemKey: string): any {
        // Extract hex from PEM
        const lines = pemKey.split('\n').filter(line =>
            !line.includes('BEGIN') && !line.includes('END') && line.trim()
        );
        const base64 = lines.join('');
        const der = Buffer.from(base64, 'base64');

        // Extract public key hex from DER
        const derHex = der.toString('hex');
        const publicKeyMatch = derHex.match(/034200([a-f0-9]+)$/i);

        if (publicKeyMatch) {
            return ec.keyFromPublic(publicKeyMatch[1], 'hex');
        }

        throw new Error('Could not extract public key from PEM');
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
            // Generate ephemeral key pair using elliptic
            const ephemeralKeyPairElliptic = ec.genKeyPair();

            // Convert recipient's public key to elliptic point
            let recipientPublicKey;
            if (publicKey.includes('-----BEGIN PUBLIC KEY-----')) {
                // PEM format
                recipientPublicKey = this.pemToEllipticPublicKey(publicKey);
            } else {
                // Hex format
                recipientPublicKey = ec.keyFromPublic(publicKey, 'hex');
            }

            // Compute shared secret using ECDH
            const sharedSecret = ephemeralKeyPairElliptic.derive(recipientPublicKey.getPublic());
            const sharedSecretHex = sharedSecret.toString(16).padStart(64, '0');

            // Derive encryption key from shared secret
            const encryptionKey = crypto.pbkdf2Sync(
                Buffer.from(sharedSecretHex, 'hex'),
                'blindflare-ecc',
                10000,
                32,
                'sha256'
            );

            // Encrypt data with derived key
            const iv = this.generateIV();
            const cipher = crypto.createCipheriv(this.config.algorithm, encryptionKey, iv) as any;
            cipher.setAAD(Buffer.from('blindflare-ecc'));

            let encrypted = cipher.update(data, 'utf8', 'hex');
            encrypted += cipher.final('hex');

            const tag = cipher.getAuthTag();

            // Convert ephemeral public key to PEM format
            const ephemeralPublicKeyPEM = this.hexToPEMPublic(ephemeralKeyPairElliptic.getPublic('hex'));

            return {
                data: encrypted,
                iv: iv.toString('hex'),
                tag: tag.toString('hex'),
                ephemeralPublicKey: ephemeralPublicKeyPEM
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
            // Convert our PEM private key to elliptic key
            const ourPrivateKey = this.pemToEllipticPrivateKey(privateKey);

            // Convert ephemeral PEM public key to elliptic point
            const ephemeralPublicKey = this.pemToEllipticPublicKey(encryptedData.ephemeralPublicKey);

            // Compute shared secret using ECDH
            const sharedSecret = ourPrivateKey.derive(ephemeralPublicKey.getPublic());
            const sharedSecretHex = sharedSecret.toString(16).padStart(64, '0');

            // Derive decryption key from shared secret
            const decryptionKey = crypto.pbkdf2Sync(
                Buffer.from(sharedSecretHex, 'hex'),
                'blindflare-ecc',
                10000,
                32,
                'sha256'
            );

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