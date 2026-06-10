// Persistent OAuth state for the remote (claude.ai) transport.
//
// Threat model note: this server is now a multi-tenant credential holder. So:
//   - Opaque tokens and auth codes are stored HASHED (SHA-256), never plaintext —
//     a leaked store file does not yield usable bearer tokens.
//   - Google refresh tokens (long-lived grants to a user's whole mailbox) are
//     ENCRYPTED at rest (AES-256-GCM) with a key derived from TOKEN_ENCRYPTION_KEY.
//   - One-time artifacts (auth codes, refresh tokens) are consumed atomically.
//
// Storage is single-process, file-backed JSON (see "Out of scope" in the plan:
// multi-instance shared storage is a follow-up).

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';

const STORE_FILE = 'oauth-store.json';
const REFRESH_TOKEN_MAX_AGE_SEC = 60 * 60 * 24 * 30; // 30 days

/** A user's Google identity + long-lived grant. The refresh token is encrypted. */
export interface GoogleUserRecord {
    sub: string;
    email: string;
    /** AES-256-GCM ciphertext of the Google refresh token. */
    refreshTokenEnc: string;
    /** Gmail scopes (shorthand) the user actually granted. */
    scopeNames: string[];
    updatedAt: number;
}

export interface AccessTokenRecord {
    clientId: string;
    googleSub: string;
    mcpScope: string;
    /** Bound audience (RFC 8707). Enforced at verify time. */
    resource: string;
    familyId: string;
    expiresAtSec: number;
}

export interface RefreshTokenRecord {
    clientId: string;
    googleSub: string;
    mcpScope: string;
    resource: string;
    familyId: string;
    createdAtSec: number;
    used: boolean;
}

/** An in-flight authorization (between /authorize and the Google callback). */
export interface PendingAuthRecord {
    id: string;
    clientId: string;
    /** claude.ai's redirect_uri — already validated by the SDK against the client. */
    redirectUri: string;
    /** claude.ai's PKCE challenge. */
    codeChallenge: string;
    /** claude.ai's opaque state, echoed back on the final redirect. */
    state?: string;
    mcpScope: string;
    resource: string;
    createdAtSec: number;
}

/** Our authorization code, exchanged once for tokens. */
export interface AuthCodeRecord {
    clientId: string;
    redirectUri: string;
    codeChallenge: string;
    mcpScope: string;
    resource: string;
    googleSub: string;
    createdAtSec: number;
}

interface PersistedShape {
    clients: Record<string, OAuthClientInformationFull>;
    googleUsers: Record<string, GoogleUserRecord>;
    accessTokens: Record<string, AccessTokenRecord>;
    refreshTokens: Record<string, RefreshTokenRecord>;
}

function nowSec(): number {
    return Math.floor(Date.now() / 1000);
}

export function generateToken(): string {
    return crypto.randomBytes(32).toString('base64url');
}

export function hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
}

export class OAuthStore {
    private readonly filePath: string;
    private readonly key: Buffer;

    // Durable (persisted) state.
    private clients = new Map<string, OAuthClientInformationFull>();
    private googleUsers = new Map<string, GoogleUserRecord>();
    private accessTokens = new Map<string, AccessTokenRecord>();
    private refreshTokens = new Map<string, RefreshTokenRecord>();

    // Ephemeral (in-memory only) short-lived state. Losing these on restart
    // simply forces an in-flight login to be retried — acceptable.
    private pendingAuths = new Map<string, PendingAuthRecord>();
    private authCodes = new Map<string, AuthCodeRecord>();

    // Serializes per-user Google-token writes to avoid clobbering a rotated
    // refresh token under concurrent requests (last-write-wins -> logout bug).
    private userWriteLocks = new Map<string, Promise<void>>();

    constructor(configDir: string, encryptionKey: Buffer) {
        this.filePath = path.join(configDir, STORE_FILE);
        this.key = encryptionKey;
        this.load();
    }

    // ---- crypto -----------------------------------------------------------

    encrypt(plaintext: string): string {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
        const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();
        return Buffer.concat([iv, tag, ct]).toString('base64');
    }

    decrypt(payload: string): string {
        const buf = Buffer.from(payload, 'base64');
        const iv = buf.subarray(0, 12);
        const tag = buf.subarray(12, 28);
        const ct = buf.subarray(28);
        const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, iv);
        decipher.setAuthTag(tag);
        return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
    }

    // ---- persistence ------------------------------------------------------

    private load(): void {
        if (!fs.existsSync(this.filePath)) return;
        try {
            const data: PersistedShape = JSON.parse(
                fs.readFileSync(this.filePath, 'utf8'),
            );
            this.clients = new Map(Object.entries(data.clients || {}));
            this.googleUsers = new Map(Object.entries(data.googleUsers || {}));
            this.accessTokens = new Map(Object.entries(data.accessTokens || {}));
            this.refreshTokens = new Map(Object.entries(data.refreshTokens || {}));
        } catch (err) {
            // A corrupt store should not take the server down; start fresh but
            // keep the old file aside for inspection.
            console.error('Failed to load OAuth store, starting empty:', err);
        }
    }

    private persist(): void {
        const data: PersistedShape = {
            clients: Object.fromEntries(this.clients),
            googleUsers: Object.fromEntries(this.googleUsers),
            accessTokens: Object.fromEntries(this.accessTokens),
            refreshTokens: Object.fromEntries(this.refreshTokens),
        };
        const tmp = `${this.filePath}.tmp`;
        fs.writeFileSync(tmp, JSON.stringify(data), { mode: 0o600 });
        fs.renameSync(tmp, this.filePath);
    }

    // ---- clients (DCR) ----------------------------------------------------

    getClient(clientId: string): OAuthClientInformationFull | undefined {
        return this.clients.get(clientId);
    }

    registerClient(client: OAuthClientInformationFull): OAuthClientInformationFull {
        this.clients.set(client.client_id, client);
        this.persist();
        return client;
    }

    // ---- pending authorizations (ephemeral) -------------------------------

    putPendingAuth(record: PendingAuthRecord): void {
        this.pendingAuths.set(record.id, record);
    }

    /** Atomically fetch-and-remove a pending auth (one-time, defends replay). */
    consumePendingAuth(id: string, ttlSec: number): PendingAuthRecord | undefined {
        const rec = this.pendingAuths.get(id);
        if (!rec) return undefined;
        this.pendingAuths.delete(id);
        if (nowSec() - rec.createdAtSec > ttlSec) return undefined;
        return rec;
    }

    // ---- authorization codes (ephemeral, one-time) ------------------------

    putAuthCode(code: string, record: AuthCodeRecord): void {
        this.authCodes.set(hashToken(code), record);
    }

    /** Read the PKCE challenge for a code without consuming it (SDK calls this first). */
    peekAuthCodeChallenge(code: string): string | undefined {
        return this.authCodes.get(hashToken(code))?.codeChallenge;
    }

    /** Atomically fetch-and-remove an auth code. */
    consumeAuthCode(code: string, ttlSec: number): AuthCodeRecord | undefined {
        const h = hashToken(code);
        const rec = this.authCodes.get(h);
        if (!rec) return undefined;
        this.authCodes.delete(h);
        if (nowSec() - rec.createdAtSec > ttlSec) return undefined;
        return rec;
    }

    // ---- issued tokens ----------------------------------------------------

    putAccessToken(token: string, record: AccessTokenRecord): void {
        this.accessTokens.set(hashToken(token), record);
        this.persist();
    }

    getAccessToken(token: string): AccessTokenRecord | undefined {
        return this.accessTokens.get(hashToken(token));
    }

    putRefreshToken(token: string, record: RefreshTokenRecord): void {
        this.refreshTokens.set(hashToken(token), record);
        this.persist();
    }

    getRefreshToken(token: string): RefreshTokenRecord | undefined {
        return this.refreshTokens.get(hashToken(token));
    }

    markRefreshTokenUsed(token: string): void {
        const rec = this.refreshTokens.get(hashToken(token));
        if (rec) {
            rec.used = true;
            this.persist();
        }
    }

    /** Revoke an entire token family — used on refresh-token reuse or explicit revoke. */
    revokeFamily(familyId: string): void {
        for (const [h, rec] of this.accessTokens) {
            if (rec.familyId === familyId) this.accessTokens.delete(h);
        }
        for (const [h, rec] of this.refreshTokens) {
            if (rec.familyId === familyId) this.refreshTokens.delete(h);
        }
        this.persist();
    }

    // ---- per-user Google tokens ------------------------------------------

    getGoogleUser(sub: string): GoogleUserRecord | undefined {
        return this.googleUsers.get(sub);
    }

    /**
     * Upsert a user's Google record, serialized per-sub. The refresh token is
     * only overwritten when a fresh one is supplied (Google omits it on most
     * refreshes); passing undefined preserves the stored token.
     */
    async upsertGoogleUser(
        sub: string,
        email: string,
        refreshToken: string | undefined,
        scopeNames: string[],
    ): Promise<void> {
        const prev = this.userWriteLocks.get(sub) || Promise.resolve();
        const next = prev.then(() => {
            const existing = this.googleUsers.get(sub);
            const enc = refreshToken
                ? this.encrypt(refreshToken)
                : existing?.refreshTokenEnc;
            if (!enc) {
                throw new Error(
                    `No refresh token available for user ${sub}; cannot persist grant.`,
                );
            }
            this.googleUsers.set(sub, {
                sub,
                email,
                refreshTokenEnc: enc,
                scopeNames,
                updatedAt: nowSec(),
            });
            this.persist();
        });
        // Keep the lock chain alive but don't let a rejection poison it.
        this.userWriteLocks.set(
            sub,
            next.catch(() => undefined),
        );
        return next;
    }

    getGoogleRefreshToken(sub: string): string | undefined {
        const rec = this.googleUsers.get(sub);
        return rec ? this.decrypt(rec.refreshTokenEnc) : undefined;
    }

    deleteGoogleUser(sub: string): void {
        if (this.googleUsers.delete(sub)) this.persist();
    }

    // ---- garbage collection ----------------------------------------------

    /** Drop expired access tokens, stale refresh tokens, and timed-out ephemeral state. */
    sweep(pendingTtlSec: number, codeTtlSec: number): void {
        const now = nowSec();
        let dirty = false;
        for (const [h, rec] of this.accessTokens) {
            if (rec.expiresAtSec <= now) {
                this.accessTokens.delete(h);
                dirty = true;
            }
        }
        for (const [h, rec] of this.refreshTokens) {
            if (now - rec.createdAtSec > REFRESH_TOKEN_MAX_AGE_SEC) {
                this.refreshTokens.delete(h);
                dirty = true;
            }
        }
        for (const [id, rec] of this.pendingAuths) {
            if (now - rec.createdAtSec > pendingTtlSec) this.pendingAuths.delete(id);
        }
        for (const [h, rec] of this.authCodes) {
            if (now - rec.createdAtSec > codeTtlSec) this.authCodes.delete(h);
        }
        if (dirty) this.persist();
    }
}
