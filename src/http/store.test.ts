import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { OAuthStore, hashToken, generateToken } from './store.js';

function tmpDir(): string {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'gmail-mcp-store-'));
}

describe('OAuthStore crypto', () => {
    let dir: string;
    let store: OAuthStore;
    beforeEach(() => {
        dir = tmpDir();
        store = new OAuthStore(dir, crypto.randomBytes(32));
    });
    afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

    it('encrypts and decrypts round-trip', () => {
        const secret = 'a-google-refresh-token-value';
        const enc = store.encrypt(secret);
        expect(enc).not.toContain(secret);
        expect(store.decrypt(enc)).toBe(secret);
    });

    it('produces a different ciphertext each time (random IV)', () => {
        expect(store.encrypt('x')).not.toBe(store.encrypt('x'));
    });

    it('hashToken is stable and non-reversible-looking', () => {
        const t = generateToken();
        expect(hashToken(t)).toBe(hashToken(t));
        expect(hashToken(t)).not.toBe(t);
        expect(hashToken(t)).toHaveLength(64);
    });
});

describe('OAuthStore one-time consume', () => {
    let dir: string;
    let store: OAuthStore;
    beforeEach(() => {
        dir = tmpDir();
        store = new OAuthStore(dir, crypto.randomBytes(32));
    });
    afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

    it('consumes an auth code exactly once', () => {
        const code = generateToken();
        store.putAuthCode(code, {
            clientId: 'c1',
            redirectUri: 'https://claude.ai/cb',
            codeChallenge: 'chal',
            mcpScope: 'gmail',
            resource: 'https://x/mcp',
            googleSub: 'sub-1',
            createdAtSec: Math.floor(Date.now() / 1000),
        });
        expect(store.peekAuthCodeChallenge(code)).toBe('chal');
        const first = store.consumeAuthCode(code, 60);
        expect(first?.googleSub).toBe('sub-1');
        expect(store.consumeAuthCode(code, 60)).toBeUndefined(); // replay fails
    });

    it('rejects an expired auth code', () => {
        const code = generateToken();
        store.putAuthCode(code, {
            clientId: 'c1',
            redirectUri: 'https://claude.ai/cb',
            codeChallenge: 'chal',
            mcpScope: 'gmail',
            resource: 'https://x/mcp',
            googleSub: 'sub-1',
            createdAtSec: Math.floor(Date.now() / 1000) - 120,
        });
        expect(store.consumeAuthCode(code, 60)).toBeUndefined();
    });

    it('consumes a pending auth exactly once', () => {
        store.putPendingAuth({
            id: 'pid',
            clientId: 'c1',
            redirectUri: 'https://claude.ai/cb',
            codeChallenge: 'chal',
            state: 'claude-state',
            mcpScope: 'gmail',
            resource: 'https://x/mcp',
            createdAtSec: Math.floor(Date.now() / 1000),
        });
        expect(store.consumePendingAuth('pid', 600)?.state).toBe('claude-state');
        expect(store.consumePendingAuth('pid', 600)).toBeUndefined();
    });
});

describe('OAuthStore token families', () => {
    let dir: string;
    let store: OAuthStore;
    beforeEach(() => {
        dir = tmpDir();
        store = new OAuthStore(dir, crypto.randomBytes(32));
    });
    afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

    it('revokeFamily removes all access + refresh tokens in the family', () => {
        const at = generateToken();
        const rt = generateToken();
        const now = Math.floor(Date.now() / 1000);
        store.putAccessToken(at, { clientId: 'c1', googleSub: 's', mcpScope: 'gmail', resource: 'r', familyId: 'fam', expiresAtSec: now + 3600 });
        store.putRefreshToken(rt, { clientId: 'c1', googleSub: 's', mcpScope: 'gmail', resource: 'r', familyId: 'fam', createdAtSec: now, used: false });
        expect(store.getAccessToken(at)).toBeDefined();
        store.revokeFamily('fam');
        expect(store.getAccessToken(at)).toBeUndefined();
        expect(store.getRefreshToken(rt)).toBeUndefined();
    });
});

describe('OAuthStore Google user persistence', () => {
    let dir: string;
    let store: OAuthStore;
    beforeEach(() => {
        dir = tmpDir();
        store = new OAuthStore(dir, crypto.randomBytes(32));
    });
    afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

    it('stores and decrypts a refresh token, preserving it when later omitted', async () => {
        await store.upsertGoogleUser('sub-1', 'a@b.com', 'refresh-original', ['gmail.modify']);
        expect(store.getGoogleRefreshToken('sub-1')).toBe('refresh-original');

        // A later refresh without a new refresh_token must NOT wipe the stored one.
        await store.upsertGoogleUser('sub-1', 'a@b.com', undefined, ['gmail.modify']);
        expect(store.getGoogleRefreshToken('sub-1')).toBe('refresh-original');

        // A rotated refresh_token replaces it.
        await store.upsertGoogleUser('sub-1', 'a@b.com', 'refresh-rotated', ['gmail.modify']);
        expect(store.getGoogleRefreshToken('sub-1')).toBe('refresh-rotated');
    });

    it('persists across reloads and keeps the refresh token encrypted on disk', async () => {
        await store.upsertGoogleUser('sub-1', 'a@b.com', 'refresh-secret', ['gmail.modify']);
        const onDisk = fs.readFileSync(path.join(dir, 'oauth-store.json'), 'utf8');
        expect(onDisk).not.toContain('refresh-secret');

        const key = (store as any).key as Buffer;
        const reloaded = new OAuthStore(dir, key);
        expect(reloaded.getGoogleRefreshToken('sub-1')).toBe('refresh-secret');
    });

    it('throws when no refresh token is available and none stored', async () => {
        await expect(
            store.upsertGoogleUser('sub-new', 'a@b.com', undefined, ['gmail.modify']),
        ).rejects.toThrow(/No refresh token/);
    });
});

describe('OAuthStore sweep', () => {
    it('drops expired access tokens', () => {
        const dir = tmpDir();
        const store = new OAuthStore(dir, crypto.randomBytes(32));
        const now = Math.floor(Date.now() / 1000);
        const expired = generateToken();
        const live = generateToken();
        store.putAccessToken(expired, { clientId: 'c', googleSub: 's', mcpScope: 'gmail', resource: 'r', familyId: 'f1', expiresAtSec: now - 1 });
        store.putAccessToken(live, { clientId: 'c', googleSub: 's', mcpScope: 'gmail', resource: 'r', familyId: 'f2', expiresAtSec: now + 3600 });
        store.sweep(600, 60);
        expect(store.getAccessToken(expired)).toBeUndefined();
        expect(store.getAccessToken(live)).toBeDefined();
        fs.rmSync(dir, { recursive: true, force: true });
    });
});
