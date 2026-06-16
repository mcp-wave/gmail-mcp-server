// Google (upstream IdP) side of the federation: build the consent URL, exchange
// the authorization code while verifying the id_token, and hand out per-user
// Gmail clients backed by auto-refreshing Google credentials.

import { google } from 'googleapis';
import { OAuth2Client } from 'google-auth-library';
import { scopeUrlToName, SCOPE_MAP } from '../scopes.js';
import type { HttpConfig } from './config.js';
import type { OAuthStore } from './store.js';

/** Thrown when a user's Google grant is gone (revoked / expired) and they must re-auth. */
export class ReauthRequiredError extends Error {
    constructor(message = 'Google authorization required. Please reconnect the Gmail connector.') {
        super(message);
        this.name = 'ReauthRequiredError';
    }
}

export interface GoogleIdentity {
    sub: string;
    email: string;
    refreshToken: string | undefined;
    /** Gmail scopes (shorthand) actually granted by the user. */
    scopeNames: string[];
}

function newGoogleClient(config: HttpConfig): OAuth2Client {
    return new OAuth2Client(
        config.googleKeys.clientId,
        config.googleKeys.clientSecret,
        config.googleCallbackUrl,
    );
}

/** Keep only the Gmail scopes we recognize (drop openid/email/profile etc.). */
function grantedGmailScopeNames(scopeString: string | null | undefined): string[] {
    if (!scopeString) return [];
    return scopeString
        .split(/\s+/)
        .map(scopeUrlToName)
        .filter((name) => name in SCOPE_MAP);
}

/**
 * The Google consent URL the user is redirected to. We request offline access and
 * force the consent screen so Google reliably returns a refresh token (identity is
 * unknown at this point, so we cannot skip consent for already-enrolled users).
 */
export function buildGoogleAuthUrl(config: HttpConfig, state: string): string {
    return newGoogleClient(config).generateAuthUrl({
        access_type: 'offline',
        prompt: 'consent',
        scope: ['openid', 'email', ...config.googleScopeUrls],
        state,
    });
}

/**
 * Exchange a Google authorization code for tokens and the verified user identity.
 * The id_token signature/issuer/audience are verified by the library — we read
 * `sub`/`email` from the verified claims, never from an unverified userinfo call.
 */
export async function exchangeGoogleCode(
    config: HttpConfig,
    code: string,
): Promise<GoogleIdentity> {
    const client = newGoogleClient(config);
    const { tokens } = await client.getToken(code);
    if (!tokens.id_token) {
        throw new Error('Google did not return an id_token; cannot establish identity.');
    }
    const ticket = await client.verifyIdToken({
        idToken: tokens.id_token,
        audience: config.googleKeys.clientId,
    });
    const payload = ticket.getPayload();
    if (!payload?.sub) {
        throw new Error('Google id_token missing subject claim.');
    }
    return {
        sub: payload.sub,
        email: payload.email || '',
        refreshToken: tokens.refresh_token || undefined,
        scopeNames: grantedGmailScopeNames(tokens.scope),
    };
}

interface CacheEntry {
    client: OAuth2Client;
    gmail: ReturnType<typeof google.gmail>;
    scopeNames: string[];
    lastUsed: number;
}

const CACHE_MAX = 200;
const CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes idle

/**
 * Per-user Gmail client cache. Keyed by Google `sub` + granted-scope set (so a
 * scope change yields a fresh client). Builds an OAuth2Client whose `tokens`
 * event persists rotated refresh tokens (serialized in the store), and evicts +
 * clears the stored grant when Google reports `invalid_grant`.
 */
export class GmailClientCache {
    private entries = new Map<string, CacheEntry>();

    constructor(
        private readonly config: HttpConfig,
        private readonly store: OAuthStore,
    ) {}

    private static key(sub: string, scopeNames: string[]): string {
        return `${sub}:${[...scopeNames].sort().join(',')}`;
    }

    private evictIfNeeded(): void {
        const now = Date.now();
        for (const [k, e] of this.entries) {
            if (now - e.lastUsed > CACHE_TTL_MS) this.entries.delete(k);
        }
        while (this.entries.size > CACHE_MAX) {
            // Map preserves insertion order; drop the oldest.
            const oldest = this.entries.keys().next().value;
            if (oldest === undefined) break;
            this.entries.delete(oldest);
        }
    }

    evict(sub: string): void {
        for (const k of this.entries.keys()) {
            if (k.startsWith(`${sub}:`)) this.entries.delete(k);
        }
    }

    /**
     * Resolve the Gmail client and granted scopes for a user. Throws
     * ReauthRequiredError if the stored grant is missing or has been revoked.
     */
    async getForUser(
        sub: string,
    ): Promise<{ gmail: CacheEntry['gmail']; scopeNames: string[] }> {
        const record = await this.store.getGoogleUser(sub);
        if (!record) throw new ReauthRequiredError();

        const key = GmailClientCache.key(sub, record.scopeNames);
        const cached = this.entries.get(key);
        if (cached) {
            cached.lastUsed = Date.now();
            return { gmail: cached.gmail, scopeNames: cached.scopeNames };
        }

        const refreshToken = await this.store.getGoogleRefreshToken(sub);
        if (!refreshToken) throw new ReauthRequiredError();

        const client = newGoogleClient(this.config);
        client.setCredentials({ refresh_token: refreshToken });

        // Persist rotated refresh tokens; Google only sends one occasionally.
        client.on('tokens', (tokens) => {
            if (tokens.refresh_token) {
                void this.store.upsertGoogleUser(
                    sub,
                    record.email,
                    tokens.refresh_token,
                    record.scopeNames,
                );
            }
        });

        const gmail = google.gmail({ version: 'v1', auth: client });
        const entry: CacheEntry = {
            client,
            gmail,
            scopeNames: record.scopeNames,
            lastUsed: Date.now(),
        };
        this.entries.set(key, entry);
        this.evictIfNeeded();
        return { gmail, scopeNames: record.scopeNames };
    }

    /** Called when a Gmail API call fails with invalid_grant: clear the dead grant. */
    async handleInvalidGrant(sub: string): Promise<void> {
        this.evict(sub);
        await this.store.deleteGoogleUser(sub);
    }
}

/** Heuristic: does this googleapis error mean the Google grant is dead? */
export function isInvalidGrant(err: any): boolean {
    const msg = String(err?.message || err?.response?.data?.error || '').toLowerCase();
    return msg.includes('invalid_grant') || err?.response?.data?.error === 'invalid_grant';
}
