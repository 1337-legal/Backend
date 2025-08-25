import { randomInt } from 'crypto';

import { wordlist as english } from '@scure/bip39/wordlists/english';
import EncryptionService from '@Services/EncryptionService';
import MailingService from '@Services/MailingService';

class HttpError extends Error {
    constructor(public status: number, message: string) {
        super(message);
        this.name = 'HttpError';
    }
}

type Verification = { code: string; expires: number; attempts: number; pgp?: string | null };

class VerificationService {
    private store = new Map<string, Verification>();
    private readonly CODE_TTL_MS = 10 * 60 * 1000; // 10 minutes
    private readonly MAX_ATTEMPTS = 5;

    private randomWord() {
        return english[randomInt(0, english.length)];
    }

    private generateCode() {
        return `${this.randomWord()} ${this.randomWord()} ${this.randomWord()}`;
    }

    private normalizeCode(code: string) {
        return (code || '').trim().toLowerCase().replace(/\s+/g, ' ');
    }

    private isValidEmail(email?: string): email is string {
        return !!email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    }

    public async sendCode(email?: string, pgp?: string | null) {
        const normalizedEmail = (email || '').trim().toLowerCase();
        if (!this.isValidEmail(normalizedEmail)) {
            throw new HttpError(400, 'Invalid email.');
        }

        let publicKey: string | null = null;
        const trimmed = (pgp || '').trim();
        if (trimmed) {
            try {
                const ok = await EncryptionService.isValidPublicKey(trimmed);
                if (ok) publicKey = trimmed;
            } catch {
                // ignore invalid keys; will send unencrypted
            }
        }

        const code = this.generateCode();
        this.store.set(normalizedEmail, {
            code,
            expires: Date.now() + this.CODE_TTL_MS,
            attempts: 0,
            pgp: publicKey,
        });

        const subject = 'Verify your email';
        const text = `Your 1337.legal verification code:\n\n${code}\n\nThis code expires in 10 minutes.`;
        const html = `
            <div style="font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#e5e7eb;background:#0a0a0a;padding:24px">
                <div style="max-width:560px;margin:0 auto;background:#0b0b0b;border:1px solid #262626;border-radius:10px;padding:20px">
                    <h1 style="margin:0 0 8px;font-size:18px;color:#f5f5f5">Verify your email</h1>
                    <p style="margin:0 0 12px;font-size:14px;color:#a3a3a3">Use this code to continue registration.</p>
                    <div style="display:inline-block;padding:10px 14px;border-radius:8px;background:#ea580c1a;border:1px solid #ea580c33;color:#fde68a;font-weight:700;letter-spacing:0.5px">${code}</div>
                    <p style="margin-top:12px;font-size:12px;color:#9ca3af">This code expires in 10 minutes.</p>
                </div>
            </div>`;

        try {
            const from = `No Reply <noreply@${MailingService.domain}>`;
            await MailingService.sendMail({
                from,
                to: normalizedEmail,
                subject,
                content: { text, html },
                publicKey: publicKey || undefined,
            });
        } catch (e) {
            // Clean up stored code on failure to send
            this.store.delete(normalizedEmail);
            throw new HttpError(500, 'Failed to send verification. Try again later.');
        }
    }

    public async verifyCode(email?: string, code?: string) {
        const normalizedEmail = (email || '').trim().toLowerCase();
        const normalizedCode = this.normalizeCode(code || '');

        if (!this.isValidEmail(normalizedEmail) || !normalizedCode) {
            throw new HttpError(400, 'Email and code are required.');
        }

        const entry = this.store.get(normalizedEmail);
        if (!entry) {
            throw new HttpError(400, 'No verification in progress.');
        }

        if (Date.now() > entry.expires) {
            this.store.delete(normalizedEmail);
            throw new HttpError(400, 'Code expired. Please restart verification.');
        }

        const expected = this.normalizeCode(entry.code);
        if (normalizedCode !== expected) {
            entry.attempts += 1;
            if (entry.attempts >= this.MAX_ATTEMPTS) {
                this.store.delete(normalizedEmail);
                throw new HttpError(429, 'Too many attempts. Please restart verification.');
            }
            throw new HttpError(400, 'Invalid code.');
        }

        this.store.delete(normalizedEmail);
    }
}

export default new VerificationService();
