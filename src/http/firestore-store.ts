// Firestore-backed OAuthStore: shared, durable, transactional storage for
// multi-instance Cloud Run. One-time artifacts (auth codes, refresh tokens,
// pending auths) are consumed inside transactions, so replay is impossible even
// across concurrent instances. Expiring records carry an `expireAt` Timestamp;
// configure a Firestore TTL policy on that field per collection (see deploy
// docs). Reads also check expiry lazily, so correctness never depends on TTL
// deletion latency.

import { Firestore, Timestamp, type DocumentData } from '@google-cloud/firestore';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { HttpConfig } from './config.js';
import {
    type OAuthStore,
    type GoogleUserRecord,
    type AccessTokenRecord,
    type RefreshTokenRecord,
    type PendingAuthRecord,
    type AuthCodeRecord,
    REFRESH_TOKEN_MAX_AGE_SEC,
    hashToken,
    encryptSecret,
    decryptSecret,
    nowSec,
} from './store.js';

const C = {
    clients: 'oauth_clients',
    pendingAuths: 'oauth_pending_auths',
    authCodes: 'oauth_auth_codes',
    accessTokens: 'oauth_access_tokens',
    refreshTokens: 'oauth_refresh_tokens',
    googleUsers: 'oauth_google_users',
} as const;

function ttl(sec: number): Timestamp {
    return Timestamp.fromMillis((nowSec() + sec) * 1000);
}

export class FirestoreOAuthStore implements OAuthStore {
    private readonly db: Firestore;
    private readonly key: Buffer;

    constructor(config: HttpConfig) {
        this.db = new Firestore({
            projectId: config.gcpProject,
            databaseId: config.firestoreDatabaseId,
            ignoreUndefinedProperties: true,
        });
        this.key = config.encryptionKey;
    }

    // ---- clients ----------------------------------------------------------

    async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
        const snap = await this.db.collection(C.clients).doc(clientId).get();
        return snap.exists ? (snap.data() as OAuthClientInformationFull) : undefined;
    }

    async registerClient(
        client: OAuthClientInformationFull,
    ): Promise<OAuthClientInformationFull> {
        await this.db.collection(C.clients).doc(client.client_id).set(client);
        return client;
    }

    // ---- pending auths (one-time) -----------------------------------------

    async putPendingAuth(record: PendingAuthRecord): Promise<void> {
        await this.db
            .collection(C.pendingAuths)
            .doc(record.id)
            .set({ ...record, expireAt: ttl(this.pendingTtlGuess(record)) });
    }

    private pendingTtlGuess(_r: PendingAuthRecord): number {
        // Pending auths are short-lived; give the TTL field generous headroom
        // (actual enforcement is the ttlSec passed to consumePendingAuth).
        return 60 * 60;
    }

    async consumePendingAuth(
        id: string,
        ttlSec: number,
    ): Promise<PendingAuthRecord | undefined> {
        const ref = this.db.collection(C.pendingAuths).doc(id);
        return this.db.runTransaction(async (tx) => {
            const snap = await tx.get(ref);
            if (!snap.exists) return undefined;
            tx.delete(ref);
            const rec = snap.data() as DocumentData;
            if (nowSec() - rec.createdAtSec > ttlSec) return undefined;
            return stripMeta(rec) as PendingAuthRecord;
        });
    }

    // ---- auth codes (one-time) --------------------------------------------

    async putAuthCode(code: string, record: AuthCodeRecord): Promise<void> {
        await this.db
            .collection(C.authCodes)
            .doc(hashToken(code))
            .set({ ...record, expireAt: ttl(60 * 60) });
    }

    async peekAuthCodeChallenge(code: string): Promise<string | undefined> {
        const snap = await this.db.collection(C.authCodes).doc(hashToken(code)).get();
        return snap.exists ? (snap.data() as AuthCodeRecord).codeChallenge : undefined;
    }

    async consumeAuthCode(
        code: string,
        ttlSec: number,
    ): Promise<AuthCodeRecord | undefined> {
        const ref = this.db.collection(C.authCodes).doc(hashToken(code));
        return this.db.runTransaction(async (tx) => {
            const snap = await tx.get(ref);
            if (!snap.exists) return undefined;
            tx.delete(ref);
            const rec = snap.data() as DocumentData;
            if (nowSec() - rec.createdAtSec > ttlSec) return undefined;
            return stripMeta(rec) as AuthCodeRecord;
        });
    }

    // ---- issued tokens ----------------------------------------------------

    async putAccessToken(token: string, record: AccessTokenRecord): Promise<void> {
        await this.db
            .collection(C.accessTokens)
            .doc(hashToken(token))
            .set({ ...record, expireAt: Timestamp.fromMillis(record.expiresAtSec * 1000) });
    }

    async getAccessToken(token: string): Promise<AccessTokenRecord | undefined> {
        const snap = await this.db.collection(C.accessTokens).doc(hashToken(token)).get();
        return snap.exists ? (stripMeta(snap.data()!) as AccessTokenRecord) : undefined;
    }

    async putRefreshToken(token: string, record: RefreshTokenRecord): Promise<void> {
        await this.db
            .collection(C.refreshTokens)
            .doc(hashToken(token))
            .set({
                ...record,
                expireAt: Timestamp.fromMillis(
                    (record.createdAtSec + REFRESH_TOKEN_MAX_AGE_SEC) * 1000,
                ),
            });
    }

    async getRefreshToken(token: string): Promise<RefreshTokenRecord | undefined> {
        const snap = await this.db.collection(C.refreshTokens).doc(hashToken(token)).get();
        return snap.exists ? (stripMeta(snap.data()!) as RefreshTokenRecord) : undefined;
    }

    async markRefreshTokenUsed(token: string): Promise<void> {
        await this.db
            .collection(C.refreshTokens)
            .doc(hashToken(token))
            .set({ used: true }, { merge: true });
    }

    async revokeFamily(familyId: string): Promise<void> {
        for (const col of [C.accessTokens, C.refreshTokens]) {
            const q = await this.db.collection(col).where('familyId', '==', familyId).get();
            const batch = this.db.batch();
            q.docs.forEach((d) => batch.delete(d.ref));
            if (!q.empty) await batch.commit();
        }
    }

    // ---- per-user Google tokens -------------------------------------------

    async getGoogleUser(sub: string): Promise<GoogleUserRecord | undefined> {
        const snap = await this.db.collection(C.googleUsers).doc(sub).get();
        return snap.exists ? (stripMeta(snap.data()!) as GoogleUserRecord) : undefined;
    }

    async upsertGoogleUser(
        sub: string,
        email: string,
        refreshToken: string | undefined,
        scopeNames: string[],
    ): Promise<void> {
        const ref = this.db.collection(C.googleUsers).doc(sub);
        // Transaction preserves the stored refresh token when Google omits a new
        // one, and serializes concurrent writes without an in-process lock.
        await this.db.runTransaction(async (tx) => {
            const snap = await tx.get(ref);
            const existing = snap.exists ? (snap.data() as GoogleUserRecord) : undefined;
            const enc = refreshToken
                ? encryptSecret(this.key, refreshToken)
                : existing?.refreshTokenEnc;
            if (!enc) {
                throw new Error(
                    `No refresh token available for user ${sub}; cannot persist grant.`,
                );
            }
            tx.set(ref, {
                sub,
                email,
                refreshTokenEnc: enc,
                scopeNames,
                updatedAt: nowSec(),
            });
        });
    }

    async getGoogleRefreshToken(sub: string): Promise<string | undefined> {
        const rec = await this.getGoogleUser(sub);
        return rec ? decryptSecret(this.key, rec.refreshTokenEnc) : undefined;
    }

    async deleteGoogleUser(sub: string): Promise<void> {
        await this.db.collection(C.googleUsers).doc(sub).delete();
    }

    // ---- GC ---------------------------------------------------------------

    async sweep(): Promise<void> {
        // No-op: Firestore TTL policies on `expireAt` reclaim expired records,
        // and all reads re-check expiry, so stale rows are never honored.
    }
}

/** Drop the Firestore-only `expireAt` field before returning a typed record. */
function stripMeta(data: DocumentData): DocumentData {
    const { expireAt, ...rest } = data;
    void expireAt;
    return rest;
}
