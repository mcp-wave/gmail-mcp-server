// Persistent OAuth state for the remote (claude.ai) transport.
//
// Threat model note: this server is a multi-tenant credential holder. So:
//   - Opaque tokens and auth codes are stored HASHED (SHA-256), never plaintext —
//     a leaked store does not yield usable bearer tokens.
//   - Google refresh tokens (long-lived grants to a user's whole mailbox) are
//     ENCRYPTED at rest (AES-256-GCM) with a key derived from TOKEN_ENCRYPTION_KEY.
//   - One-time artifacts (auth codes, refresh tokens) are consumed atomically.
//
// Two backends implement the OAuthStore interface:
//   - FileOAuthStore     single-process JSON file (local / stdio dev).
//   - FirestoreOAuthStore shared, durable, transactional (Cloud Run, multi-instance).
// Pick via createStore(config).

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { HttpConfig } from './config.js';
import type { SendPolicy } from '../session.js';

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
    /** LEGACY single-valued owner back-reference. No longer written, and never
     *  read as an authorization decision — one Google account may be a member of
     *  several principals. Retained only so getPrimaryPrincipal can migrate
     *  pre-existing records forward (see that method). */
    principalId?: string;
    /** LEGACY per-account send policy, superseded by PrincipalAccountRecord.
     *  Read as a fallback for un-migrated records; never written. */
    sendPolicy?: SendPolicy;
    updatedAt: number;
}

/** A principal = one connection's identity, owning one or more Google accounts. */
export interface PrincipalRecord {
    id: string;
    /** The account that established this principal. Only a sign-in as THIS
     *  account may resume the principal; it cannot be unlinked. */
    primarySub: string;
    /** All linked account subs (includes primarySub). */
    accountSubs: string[];
    createdAt: number;
}

/**
 * Membership of one Google account in one principal, and the settings that
 * belong to that pairing rather than to the Google account globally.
 *
 * The same mailbox can legitimately be linked into two different principals
 * (a shared or team address). Settings therefore MUST NOT live on the Google
 * user record, or one principal's changes would apply to the other's session.
 */
export interface PrincipalAccountRecord {
    principalId: string;
    sub: string;
    /** Outbound send policy for this account within this principal. */
    sendPolicy?: SendPolicy;
}

/** Short-lived ticket binding an account-link / first-connect sign-in. */
export interface LinkTicketRecord {
    /** The principal to attach the account to; absent on first connect (then created). */
    principalId?: string;
    /** Set when started from the manage page; return there after the callback. */
    authRequestId?: string;
    createdAtSec: number;
}

/**
 * A claude.ai authorization request parked while the user manages accounts on the
 * manage page. Finalized (exchanged for our auth code) when they click Continue.
 */
export interface AuthRequestRecord {
    clientId: string;
    redirectUri: string;
    codeChallenge: string;
    state?: string;
    resource: string;
    mcpScope: string;
    /** The principal established by the Google login WITHIN this request's flow.
     *  Set once the user signs in; the manage page + finalize key off this, never
     *  an ambient browser cookie (which would bleed across claude.ai accounts). */
    principalId?: string;
    createdAtSec: number;
}

export interface AccessTokenRecord {
    clientId: string;
    principalId: string;
    mcpScope: string;
    /** Bound audience (RFC 8707). Enforced at verify time. */
    resource: string;
    familyId: string;
    expiresAtSec: number;
}

export interface RefreshTokenRecord {
    clientId: string;
    principalId: string;
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
    principalId: string;
    createdAtSec: number;
}

/**
 * Storage contract for the OAuth authorization server. All methods are async so
 * a shared backend (Firestore) can implement it; the file backend simply
 * resolves immediately.
 */
export interface OAuthStore {
    getClient(clientId: string): Promise<OAuthClientInformationFull | undefined>;
    registerClient(client: OAuthClientInformationFull): Promise<OAuthClientInformationFull>;

    putPendingAuth(record: PendingAuthRecord): Promise<void>;
    consumePendingAuth(id: string, ttlSec: number): Promise<PendingAuthRecord | undefined>;

    putAuthCode(code: string, record: AuthCodeRecord): Promise<void>;
    peekAuthCodeChallenge(code: string): Promise<string | undefined>;
    consumeAuthCode(code: string, ttlSec: number): Promise<AuthCodeRecord | undefined>;

    putAccessToken(token: string, record: AccessTokenRecord): Promise<void>;
    getAccessToken(token: string): Promise<AccessTokenRecord | undefined>;
    putRefreshToken(token: string, record: RefreshTokenRecord): Promise<void>;
    getRefreshToken(token: string): Promise<RefreshTokenRecord | undefined>;
    markRefreshTokenUsed(token: string): Promise<void>;
    revokeFamily(familyId: string): Promise<void>;

    getGoogleUser(sub: string): Promise<GoogleUserRecord | undefined>;
    upsertGoogleUser(
        sub: string,
        email: string,
        refreshToken: string | undefined,
        scopeNames: string[],
    ): Promise<void>;
    getGoogleRefreshToken(sub: string): Promise<string | undefined>;
    /** Drop the shared Google grant outright (only when Google says it is dead). */
    deleteGoogleUser(sub: string): Promise<void>;

    /** The principal this sub is the PRIMARY of, if any. This is the only
     *  lookup permitted to resume an existing principal from a Google sign-in. */
    getPrimaryPrincipal(sub: string): Promise<string | undefined>;
    setPrimaryPrincipal(sub: string, principalId: string): Promise<void>;

    getSendPolicy(principalId: string, sub: string): Promise<SendPolicy | undefined>;
    setSendPolicy(principalId: string, sub: string, policy: SendPolicy): Promise<void>;

    getPrincipal(principalId: string): Promise<PrincipalRecord | undefined>;
    createPrincipal(record: PrincipalRecord): Promise<void>;
    addAccountToPrincipal(principalId: string, sub: string): Promise<void>;
    /** Remove one account from one principal: drops membership and that
     *  principal's settings, and deletes the shared Google grant only when no
     *  other principal still links the account. */
    unlinkAccount(principalId: string, sub: string): Promise<void>;

    putLinkTicket(ticket: string, record: LinkTicketRecord): Promise<void>;
    consumeLinkTicket(ticket: string, ttlSec: number): Promise<LinkTicketRecord | undefined>;

    putAuthRequest(id: string, record: AuthRequestRecord): Promise<void>;
    getAuthRequest(id: string, ttlSec: number): Promise<AuthRequestRecord | undefined>;
    setAuthRequestPrincipal(id: string, principalId: string): Promise<void>;
    consumeAuthRequest(id: string, ttlSec: number): Promise<AuthRequestRecord | undefined>;

    /** Best-effort GC of expired records. May be a no-op when the backend has TTL. */
    sweep(pendingTtlSec: number, codeTtlSec: number): Promise<void>;
}

export function nowSec(): number {
    return Math.floor(Date.now() / 1000);
}

export function generateToken(): string {
    return crypto.randomBytes(32).toString('base64url');
}

export function hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
}

/** AES-256-GCM encrypt; output is base64(iv | tag | ciphertext). */
export function encryptSecret(key: Buffer, plaintext: string): string {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, ct]).toString('base64');
}

export function decryptSecret(key: Buffer, payload: string): string {
    const buf = Buffer.from(payload, 'base64');
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const ct = buf.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

interface PersistedShape {
    clients: Record<string, OAuthClientInformationFull>;
    googleUsers: Record<string, GoogleUserRecord>;
    principals: Record<string, PrincipalRecord>;
    /** Keyed by `${principalId} ${sub}`. */
    principalAccounts: Record<string, PrincipalAccountRecord>;
    /** sub -> the principal it is the primary of. */
    primaryOwners: Record<string, string>;
    accessTokens: Record<string, AccessTokenRecord>;
    refreshTokens: Record<string, RefreshTokenRecord>;
}

/** Composite key for a (principal, account) pairing. */
export function accountKey(principalId: string, sub: string): string {
    return `${principalId} ${sub}`;
}

/**
 * Single-process, file-backed store. Durable across restarts on one machine;
 * NOT safe for multiple instances (use Firestore for Cloud Run).
 */
export class FileOAuthStore implements OAuthStore {
    private readonly filePath: string;
    private readonly key: Buffer;

    private clients = new Map<string, OAuthClientInformationFull>();
    private googleUsers = new Map<string, GoogleUserRecord>();
    private principals = new Map<string, PrincipalRecord>();
    private principalAccounts = new Map<string, PrincipalAccountRecord>();
    private primaryOwners = new Map<string, string>();
    private accessTokens = new Map<string, AccessTokenRecord>();
    private refreshTokens = new Map<string, RefreshTokenRecord>();
    private pendingAuths = new Map<string, PendingAuthRecord>();
    private authCodes = new Map<string, AuthCodeRecord>();
    private linkTickets = new Map<string, LinkTicketRecord>();
    private authRequests = new Map<string, AuthRequestRecord>();
    private userWriteLocks = new Map<string, Promise<void>>();

    constructor(configDir: string, encryptionKey: Buffer) {
        this.filePath = path.join(configDir, STORE_FILE);
        this.key = encryptionKey;
        this.load();
    }

    private load(): void {
        if (!fs.existsSync(this.filePath)) return;
        try {
            const data: PersistedShape = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
            this.clients = new Map(Object.entries(data.clients || {}));
            this.googleUsers = new Map(Object.entries(data.googleUsers || {}));
            this.principals = new Map(Object.entries(data.principals || {}));
            this.principalAccounts = new Map(Object.entries(data.principalAccounts || {}));
            this.primaryOwners = new Map(Object.entries(data.primaryOwners || {}));
            this.accessTokens = new Map(Object.entries(data.accessTokens || {}));
            this.refreshTokens = new Map(Object.entries(data.refreshTokens || {}));
        } catch (err) {
            console.error('Failed to load OAuth store, starting empty:', err);
        }
    }

    private persist(): void {
        const data: PersistedShape = {
            clients: Object.fromEntries(this.clients),
            googleUsers: Object.fromEntries(this.googleUsers),
            principals: Object.fromEntries(this.principals),
            principalAccounts: Object.fromEntries(this.principalAccounts),
            primaryOwners: Object.fromEntries(this.primaryOwners),
            accessTokens: Object.fromEntries(this.accessTokens),
            refreshTokens: Object.fromEntries(this.refreshTokens),
        };
        const tmp = `${this.filePath}.tmp`;
        fs.writeFileSync(tmp, JSON.stringify(data), { mode: 0o600 });
        fs.renameSync(tmp, this.filePath);
    }

    async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
        return this.clients.get(clientId);
    }

    async registerClient(
        client: OAuthClientInformationFull,
    ): Promise<OAuthClientInformationFull> {
        this.clients.set(client.client_id, client);
        this.persist();
        return client;
    }

    async putPendingAuth(record: PendingAuthRecord): Promise<void> {
        this.pendingAuths.set(record.id, record);
    }

    async consumePendingAuth(
        id: string,
        ttlSec: number,
    ): Promise<PendingAuthRecord | undefined> {
        const rec = this.pendingAuths.get(id);
        if (!rec) return undefined;
        this.pendingAuths.delete(id);
        if (nowSec() - rec.createdAtSec > ttlSec) return undefined;
        return rec;
    }

    async putAuthCode(code: string, record: AuthCodeRecord): Promise<void> {
        this.authCodes.set(hashToken(code), record);
    }

    async peekAuthCodeChallenge(code: string): Promise<string | undefined> {
        return this.authCodes.get(hashToken(code))?.codeChallenge;
    }

    async consumeAuthCode(
        code: string,
        ttlSec: number,
    ): Promise<AuthCodeRecord | undefined> {
        const h = hashToken(code);
        const rec = this.authCodes.get(h);
        if (!rec) return undefined;
        this.authCodes.delete(h);
        if (nowSec() - rec.createdAtSec > ttlSec) return undefined;
        return rec;
    }

    async putAccessToken(token: string, record: AccessTokenRecord): Promise<void> {
        this.accessTokens.set(hashToken(token), record);
        this.persist();
    }

    async getAccessToken(token: string): Promise<AccessTokenRecord | undefined> {
        return this.accessTokens.get(hashToken(token));
    }

    async putRefreshToken(token: string, record: RefreshTokenRecord): Promise<void> {
        this.refreshTokens.set(hashToken(token), record);
        this.persist();
    }

    async getRefreshToken(token: string): Promise<RefreshTokenRecord | undefined> {
        return this.refreshTokens.get(hashToken(token));
    }

    async markRefreshTokenUsed(token: string): Promise<void> {
        const rec = this.refreshTokens.get(hashToken(token));
        if (rec) {
            rec.used = true;
            this.persist();
        }
    }

    async revokeFamily(familyId: string): Promise<void> {
        for (const [h, rec] of this.accessTokens) {
            if (rec.familyId === familyId) this.accessTokens.delete(h);
        }
        for (const [h, rec] of this.refreshTokens) {
            if (rec.familyId === familyId) this.refreshTokens.delete(h);
        }
        this.persist();
    }

    async getGoogleUser(sub: string): Promise<GoogleUserRecord | undefined> {
        return this.googleUsers.get(sub);
    }

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
                ? encryptSecret(this.key, refreshToken)
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
                principalId: existing?.principalId, // preserve the back-reference
                sendPolicy: existing?.sendPolicy, // preserve send policy
                updatedAt: nowSec(),
            });
            this.persist();
        });
        this.userWriteLocks.set(
            sub,
            next.catch(() => undefined),
        );
        return next;
    }

    async getGoogleRefreshToken(sub: string): Promise<string | undefined> {
        const rec = this.googleUsers.get(sub);
        return rec ? decryptSecret(this.key, rec.refreshTokenEnc) : undefined;
    }

    async deleteGoogleUser(sub: string): Promise<void> {
        if (this.googleUsers.delete(sub)) this.persist();
    }

    async getPrimaryPrincipal(sub: string): Promise<string | undefined> {
        const known = this.primaryOwners.get(sub);
        if (known) return known;
        // Migrate a pre-index record forward, but ONLY when the legacy
        // back-reference names a principal this sub actually established. A sub
        // that was merely linked as a secondary gets nothing.
        const legacy = this.googleUsers.get(sub)?.principalId;
        if (!legacy) return undefined;
        if (this.principals.get(legacy)?.primarySub !== sub) return undefined;
        this.primaryOwners.set(sub, legacy);
        this.persist();
        return legacy;
    }

    async setPrimaryPrincipal(sub: string, principalId: string): Promise<void> {
        this.primaryOwners.set(sub, principalId);
        this.persist();
    }

    async getSendPolicy(principalId: string, sub: string): Promise<SendPolicy | undefined> {
        const rec = this.principalAccounts.get(accountKey(principalId, sub));
        if (rec) return rec.sendPolicy;
        // Un-migrated: fall back to the legacy per-sub policy so an existing
        // user's allowlist is not silently dropped on upgrade.
        return this.googleUsers.get(sub)?.sendPolicy;
    }

    async setSendPolicy(principalId: string, sub: string, policy: SendPolicy): Promise<void> {
        this.principalAccounts.set(accountKey(principalId, sub), {
            principalId,
            sub,
            sendPolicy: policy,
        });
        this.persist();
    }

    async getPrincipal(principalId: string): Promise<PrincipalRecord | undefined> {
        return this.principals.get(principalId);
    }

    async createPrincipal(record: PrincipalRecord): Promise<void> {
        this.principals.set(record.id, record);
        this.persist();
    }

    async addAccountToPrincipal(principalId: string, sub: string): Promise<void> {
        const p = this.principals.get(principalId);
        if (p && !p.accountSubs.includes(sub)) {
            p.accountSubs.push(sub);
            this.persist();
        }
    }

    async unlinkAccount(principalId: string, sub: string): Promise<void> {
        const p = this.principals.get(principalId);
        if (!p || sub === p.primarySub) return; // the primary is never unlinkable
        p.accountSubs = p.accountSubs.filter((s) => s !== sub);
        this.principalAccounts.delete(accountKey(principalId, sub));
        // Keep the shared Google grant alive while any other principal links it.
        const stillLinked = [...this.principals.values()].some((o) =>
            o.accountSubs.includes(sub),
        );
        if (!stillLinked) {
            this.googleUsers.delete(sub);
            this.primaryOwners.delete(sub);
        }
        this.persist();
    }

    async putLinkTicket(ticket: string, record: LinkTicketRecord): Promise<void> {
        this.linkTickets.set(hashToken(ticket), record);
    }

    async consumeLinkTicket(
        ticket: string,
        ttlSec: number,
    ): Promise<LinkTicketRecord | undefined> {
        const h = hashToken(ticket);
        const rec = this.linkTickets.get(h);
        if (!rec) return undefined;
        this.linkTickets.delete(h);
        if (nowSec() - rec.createdAtSec > ttlSec) return undefined;
        return rec;
    }

    async putAuthRequest(id: string, record: AuthRequestRecord): Promise<void> {
        this.authRequests.set(id, record);
    }

    async getAuthRequest(id: string, ttlSec: number): Promise<AuthRequestRecord | undefined> {
        const rec = this.authRequests.get(id);
        if (!rec) return undefined;
        if (nowSec() - rec.createdAtSec > ttlSec) return undefined;
        return rec;
    }

    async setAuthRequestPrincipal(id: string, principalId: string): Promise<void> {
        const rec = this.authRequests.get(id);
        if (rec) rec.principalId = principalId;
    }

    async consumeAuthRequest(id: string, ttlSec: number): Promise<AuthRequestRecord | undefined> {
        const rec = this.authRequests.get(id);
        if (!rec) return undefined;
        this.authRequests.delete(id);
        if (nowSec() - rec.createdAtSec > ttlSec) return undefined;
        return rec;
    }

    async sweep(pendingTtlSec: number, codeTtlSec: number): Promise<void> {
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
        for (const [h, rec] of this.linkTickets) {
            if (now - rec.createdAtSec > pendingTtlSec) this.linkTickets.delete(h);
        }
        if (dirty) this.persist();
    }
}

export { REFRESH_TOKEN_MAX_AGE_SEC };

/**
 * Build the configured store. Firestore is loaded lazily so the file/stdio path
 * never pulls in the (heavy) Firestore client library.
 */
export async function createStore(config: HttpConfig): Promise<OAuthStore> {
    if (config.storeBackend === 'firestore') {
        const { FirestoreOAuthStore } = await import('./firestore-store.js');
        return new FirestoreOAuthStore(config);
    }
    return new FileOAuthStore(config.configDir, config.encryptionKey);
}
