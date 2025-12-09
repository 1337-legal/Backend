# 🛡️ 1337.legal Backend

Privacy‑first alias & session API built on the Blindflare Protocol.  
Current focus: secure handshake, auth, session key wrapping, and alias generation

---

## ✨ Current Capabilities (MVP)

| Domain | Status | Description |
| ------ | ------ | ----------- |
| 🔐 Blindflare Handshake | ✅ | `/api/v1/blindflare/hello` negotiates protocol context. |
| 👤 Auth (Public Key + Signature) | ✅ | `/api/v1/auth` registers or logs in user via signed AUTH intent. |
| 🔑 Session Wrapping | ✅ | Encrypted session key (ECC) + per-request TX encryption (FortressMiddleware). |
| 🧬 Alias Generation | ✅ | Human-ish aliases from random word triplets + domain (`PUT /api/v1/alias`). |
| 🔒 Transaction Encryption | ✅ | Requests & responses wrapped in Blindflare transaction envelope. |
| 📜 OpenAPI Docs | ✅ | Swagger auto-exposed (Elysia plugin). |

---

## 🧪 API Summary (Implemented)

Base prefix: `/api/v1`

| Method | Path | Purpose |
| ------ | ---- | ------- |
| POST | `/blindflare/hello` | ClientHello → ServerHello (capabilities + nonce + sig validation). |
| POST | `/auth` | Register/login via `{ blindflare: { type: 'AUTH', publicKey, signature } }`. |
| PUT | `/alias` | Create new alias (random word-word-word@1337.legal). |
| PATCH | `/alias/:address` | Retrieve alias & user context (placeholder for future status toggling). |

All non-handshake routes expect encrypted Blindflare transaction payload & require valid JWT + session key.

---

## 🧩 Architecture

| Component | Role |
| --------- | ---- |
| Elysia | Lightweight HTTP framework (fast Bun runtime support). |
| Fortress (`@blindflare/fortress`) | Blindflare Protocol primitives: ECC hybrid, TX encryption, signatures. |
| FortressMiddleware | Decrypt inbound TX → attach body → encrypt outbound TX. |
| SessionMiddleware | JWT verification & user binding. |
| AliasRepository | Persistence abstraction (currently basic ORM/repo style). |
| ListenerService | App bootstrap: plugins (CORS, Swagger, JWT), routing groups, env loading. |

---

## 🔐 Blindflare Flow (Simplified)

1. Client generates keypair ➜ sends HELLO with capabilities + nonce + signature.  
2. Server creates ServerHello (challenge/ack).  
3. Client performs AUTH (signed "AUTH" intent) ➜ receives JWT + encrypted session key.  
4. Subsequent requests: encrypted transaction envelope (`type: 'TX'`) using session key.  
5. Responses returned symmetrically encrypted & integrity‑protected.

---

## 🧪 Alias Generation

- Uses three random BIP39 words → `word-word-word@1337.legal`
- Not guaranteed unique across time (collision extremely low; DB constraint should enforce if added)
- Example: `echo-rain-gesture@1337.legal`

---

## 🛠️ Environment

```env
JWT_SECRET=replace_me
```

(Additional vars like SMTP, DB, inbound relay secrets intentionally unused until forwarding & mail intake land.)

---

## 🚀 Development

```bash
bun install
bun run dev
# or
bun run --hot src/globals.d.ts
```

Swagger / OpenAPI UI: auto-mounted (check console output for URL).

---

## 🧱 Security Notes

- Every TX encrypted (AES-256-GCM under Blindflare session key; session key wrapped via ECC).
- Signatures: secp256k1 + SHA-256 (via fortress).
- Session key stored encrypted per user (never plaintext at rest in app layer).
- No plaintext alias mapping exposures beyond runtime objects.
- Forwarding pipeline intentionally absent (prevents accidental data leakage during early iterations).

---

## 🗺️ Roadmap

| Priority | Item |
| -------- | ---- |
| 🔜 | Inbound relay ingestion (queue + normalization). |
| 🔜 | Forwarding pipeline (PGP / policy aware) — currently NOT implemented. |
| 🔜 | Alias status toggling (suspend / revoke / rotate secret). |
| 🔜 | Rate limiting & abuse heuristics. |
| 🧪 | Encrypted audit log (minimal metadata). |
| 🧪 | Blind index storage for deterministic lookup without plaintext disclosure. |
| 🧬 | PGP key registry & auto‑wrapping. |
| 🪪 | Webhook signing + delivery retries. |
| 🧵 | Streaming encryption for large payloads / attachments. |

---

## ⚠️ Disclaimer

This backend is pre-forwarding. Do not deploy for production email traffic yet. Crypto surfaces may change pending further protocol validation.

---

## 🤝 Contributing

Issues / PRs welcome once forwarding phase begins. Until then: expect refactors.

---

## 📄 License

MIT

---
Made with ⛓️, 🔐, and a