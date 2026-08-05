import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
    FileOAuthStore,
    hashToken,
    generateToken,
    encryptSecret,
    decryptSecret,
} from './store.js';

function tmpDir(): string {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'gmail-mcp-store-'));
}

describe('crypto helpers', () => {
    const key = crypto.randomBytes(32);

    it('encrypts and decrypts round-trip', () => {
        const secret = 'a-google-refresh-token-value';
        const enc = encryptSecret(key, secret);
        expect(enc).not.toContain(secret);
        expect(decryptSecret(key, enc)).toBe(secret);
    });

    it('produces a different ciphertext each time (random IV)', () => {
        expect(encryptSecret(key, 'x')).not.toBe(encryptSecret(key, 'x'));
    });

    it('hashToken is stable and not the token', () => {
        const t = generateToken();
        expect(hashToken(t)).toBe(hashToken(t));
        expect(hashToken(t)).not.toBe(t);
        expect(hashToken(t)).toHaveLength(64);
    });
});

describe('FileOAuthStore one-time consume', () => {
    let dir: string;
    let store: FileOAuthStore;
    beforeEach(() => {
        dir = tmpDir();
        store = new FileOAuthStore(dir, crypto.randomBytes(32));
    });
    afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

    it('consumes an auth code exactly once', async () => {
        const code = generateToken();
        await store.putAuthCode(code, {
            clientId: 'c1',
            redirectUri: 'https://claude.ai/cb',
            codeChallenge: 'chal',
            mcpScope: 'gmail',
            resource: 'https://x/mcp',
            principalId: 'sub-1',
            createdAtSec: Math.floor(Date.now() / 1000),
        });
        expect(await store.peekAuthCodeChallenge(code)).toBe('chal');
        const first = await store.consumeAuthCode(code, 60);
        expect(first?.principalId).toBe('sub-1');
        expect(await store.consumeAuthCode(code, 60)).toBeUndefined(); // replay fails
    });

    it('rejects an expired auth code', async () => {
        const code = generateToken();
        await store.putAuthCode(code, {
            clientId: 'c1',
            redirectUri: 'https://claude.ai/cb',
            codeChallenge: 'chal',
            mcpScope: 'gmail',
            resource: 'https://x/mcp',
            principalId: 'sub-1',
            createdAtSec: Math.floor(Date.now() / 1000) - 120,
        });
        expect(await store.consumeAuthCode(code, 60)).toBeUndefined();
    });

    it('consumes a pending auth exactly once', async () => {
        await store.putPendingAuth({
            id: 'pid',
            clientId: 'c1',
            redirectUri: 'https://claude.ai/cb',
            codeChallenge: 'chal',
            state: 'claude-state',
            mcpScope: 'gmail',
            resource: 'https://x/mcp',
            createdAtSec: Math.floor(Date.now() / 1000),
        });
        expect((await store.consumePendingAuth('pid', 600))?.state).toBe('claude-state');
        expect(await store.consumePendingAuth('pid', 600)).toBeUndefined();
    });
});

describe('FileOAuthStore token families', () => {
    let dir: string;
    let store: FileOAuthStore;
    beforeEach(() => {
        dir = tmpDir();
        store = new FileOAuthStore(dir, crypto.randomBytes(32));
    });
    afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

    it('revokeFamily removes all access + refresh tokens in the family', async () => {
        const at = generateToken();
        const rt = generateToken();
        const now = Math.floor(Date.now() / 1000);
        await store.putAccessToken(at, { clientId: 'c1', principalId: 's', mcpScope: 'gmail', resource: 'r', familyId: 'fam', expiresAtSec: now + 3600 });
        await store.putRefreshToken(rt, { clientId: 'c1', principalId: 's', mcpScope: 'gmail', resource: 'r', familyId: 'fam', createdAtSec: now, used: false });
        expect(await store.getAccessToken(at)).toBeDefined();
        await store.revokeFamily('fam');
        expect(await store.getAccessToken(at)).toBeUndefined();
        expect(await store.getRefreshToken(rt)).toBeUndefined();
    });
});

describe('FileOAuthStore Google user persistence', () => {
    let dir: string;
    let store: FileOAuthStore;
    beforeEach(() => {
        dir = tmpDir();
        store = new FileOAuthStore(dir, crypto.randomBytes(32));
    });
    afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

    it('stores and decrypts a refresh token, preserving it when later omitted', async () => {
        await store.upsertGoogleUser('sub-1', 'a@b.com', 'refresh-original', ['gmail.modify']);
        expect(await store.getGoogleRefreshToken('sub-1')).toBe('refresh-original');

        // A later refresh without a new refresh_token must NOT wipe the stored one.
        await store.upsertGoogleUser('sub-1', 'a@b.com', undefined, ['gmail.modify']);
        expect(await store.getGoogleRefreshToken('sub-1')).toBe('refresh-original');

        // A rotated refresh_token replaces it.
        await store.upsertGoogleUser('sub-1', 'a@b.com', 'refresh-rotated', ['gmail.modify']);
        expect(await store.getGoogleRefreshToken('sub-1')).toBe('refresh-rotated');
    });

    it('persists across reloads and keeps the refresh token encrypted on disk', async () => {
        const key = crypto.randomBytes(32);
        const s1 = new FileOAuthStore(dir, key);
        await s1.upsertGoogleUser('sub-1', 'a@b.com', 'refresh-secret', ['gmail.modify']);
        const onDisk = fs.readFileSync(path.join(dir, 'oauth-store.json'), 'utf8');
        expect(onDisk).not.toContain('refresh-secret');

        const s2 = new FileOAuthStore(dir, key);
        expect(await s2.getGoogleRefreshToken('sub-1')).toBe('refresh-secret');
    });

    it('throws when no refresh token is available and none stored', async () => {
        await expect(
            store.upsertGoogleUser('sub-new', 'a@b.com', undefined, ['gmail.modify']),
        ).rejects.toThrow(/No refresh token/);
    });
});

describe('FileOAuthStore sweep', () => {
    it('drops expired access tokens', async () => {
        const dir = tmpDir();
        const store = new FileOAuthStore(dir, crypto.randomBytes(32));
        const now = Math.floor(Date.now() / 1000);
        const expired = generateToken();
        const live = generateToken();
        await store.putAccessToken(expired, { clientId: 'c', principalId: 's', mcpScope: 'gmail', resource: 'r', familyId: 'f1', expiresAtSec: now - 1 });
        await store.putAccessToken(live, { clientId: 'c', principalId: 's', mcpScope: 'gmail', resource: 'r', familyId: 'f2', expiresAtSec: now + 3600 });
        await store.sweep(600, 60);
        expect(await store.getAccessToken(expired)).toBeUndefined();
        expect(await store.getAccessToken(live)).toBeDefined();
        fs.rmSync(dir, { recursive: true, force: true });
    });
});
