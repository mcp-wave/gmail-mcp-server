import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { GmailOAuthProvider } from './provider.js';
import { FileOAuthStore } from './store.js';
import type { HttpConfig } from './config.js';
import type { GoogleIdentity } from './google.js';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';

const RESOURCE = 'https://gmail.example.com/mcp';

function makeConfig(dir: string, resourceUrl = RESOURCE): HttpConfig {
    const baseUrl = resourceUrl.replace(/\/mcp$/, '');
    return {
        baseUrl,
        issuerUrl: new URL(baseUrl),
        resourceUrl,
        googleCallbackUrl: `${baseUrl}/oauth2/google/callback`,
        port: 3000,
        googleKeys: { clientId: 'gid.apps.googleusercontent.com', clientSecret: 'gsecret' },
        googleScopeNames: ['gmail.modify'],
        googleScopeUrls: ['https://www.googleapis.com/auth/gmail.modify'],
        mcpScope: 'gmail',
        configDir: dir,
        encryptionKey: crypto.randomBytes(32),
        allowedOrigins: [],
        accessTokenTtlSec: 3600,
        authCodeTtlSec: 60,
        pendingAuthTtlSec: 600,
    };
}

const CLIENT: OAuthClientInformationFull = {
    client_id: 'claude-client',
    redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
    token_endpoint_auth_method: 'none',
};

const IDENTITY: GoogleIdentity = {
    sub: 'google-sub-1',
    email: 'user@example.com',
    refreshToken: 'google-refresh-token',
    scopeNames: ['gmail.modify'],
};

const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

/** Drive authorize -> Google redirect, returning the pendingId (Google `state`). */
function runAuthorize(provider: GmailOAuthProvider): Promise<string> {
    let captured = '';
    const res = { redirect: (url: string) => { captured = url; } } as any;
    return provider
        .authorize(CLIENT, {
            state: 'claude-state',
            scopes: ['gmail'],
            redirectUri: CLIENT.redirect_uris[0],
            codeChallenge: CHALLENGE,
            resource: new URL(RESOURCE),
        }, res)
        .then(() => new URL(captured).searchParams.get('state')!);
}

describe('GmailOAuthProvider full flow', () => {
    let dir: string;
    let store: FileOAuthStore;
    let provider: GmailOAuthProvider;
    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gmail-mcp-prov-'));
        store = new FileOAuthStore(dir, crypto.randomBytes(32));
        provider = new GmailOAuthProvider(makeConfig(dir), store);
    });
    afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

    it('authorize -> callback -> code -> token issues a verifiable bearer', async () => {
        const pendingId = await runAuthorize(provider);
        const { redirectUri, code, state } = await provider.completeGoogleAuth(pendingId, IDENTITY);
        expect(redirectUri).toBe(CLIENT.redirect_uris[0]);
        expect(state).toBe('claude-state');

        // SDK reads the PKCE challenge for the code before exchanging.
        expect(await provider.challengeForAuthorizationCode(CLIENT, code)).toBe(CHALLENGE);

        const tokens = await provider.exchangeAuthorizationCode(
            CLIENT, code, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE),
        );
        expect(tokens.token_type).toBe('bearer');
        expect(tokens.access_token).toBeTruthy();
        expect(tokens.refresh_token).toBeTruthy();
        expect(tokens.expires_in).toBe(3600);

        const auth = await provider.verifyAccessToken(tokens.access_token);
        expect(auth.clientId).toBe('claude-client');
        expect(auth.scopes).toEqual(['gmail']);
        // Token binds to a PRINCIPAL; the principal owns the primary account.
        const principalId = (auth.extra as any).principalId as string;
        expect(principalId).toBeTruthy();
        const principal = await store.getPrincipal(principalId);
        expect(principal?.primarySub).toBe('google-sub-1');
        expect(principal?.accountSubs).toEqual(['google-sub-1']);
        // expiresAt must be seconds-since-epoch in the near future (bearerAuth requires this).
        expect(auth.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
        expect(auth.expiresAt).toBeLessThan(Math.floor(Date.now() / 1000) + 3700);

        // The Google grant was persisted for this user.
        expect(await store.getGoogleRefreshToken('google-sub-1')).toBe('google-refresh-token');
    });

    it('rejects a replayed authorization code', async () => {
        const pendingId = await runAuthorize(provider);
        const { code } = await provider.completeGoogleAuth(pendingId, IDENTITY);
        await provider.exchangeAuthorizationCode(CLIENT, code, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE));
        await expect(
            provider.exchangeAuthorizationCode(CLIENT, code, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE)),
        ).rejects.toThrow(/Invalid or expired authorization code/);
    });

    it('rejects a code exchanged with a mismatched redirect_uri', async () => {
        const pendingId = await runAuthorize(provider);
        const { code } = await provider.completeGoogleAuth(pendingId, IDENTITY);
        await expect(
            provider.exchangeAuthorizationCode(CLIENT, code, undefined, 'https://evil.example/cb', new URL(RESOURCE)),
        ).rejects.toThrow(/redirect_uri/);
    });

    it('rejects a code exchanged for the wrong resource (audience)', async () => {
        const pendingId = await runAuthorize(provider);
        const { code } = await provider.completeGoogleAuth(pendingId, IDENTITY);
        await expect(
            provider.exchangeAuthorizationCode(CLIENT, code, undefined, CLIENT.redirect_uris[0], new URL('https://other.example/mcp')),
        ).rejects.toThrow(/resource/);
    });

    it('rejects an unknown authorization code at PKCE lookup', async () => {
        await expect(provider.challengeForAuthorizationCode(CLIENT, 'nope')).rejects.toThrow(/Invalid or expired/);
    });

    it('enforces audience binding at verify time', async () => {
        const pendingId = await runAuthorize(provider);
        const { code } = await provider.completeGoogleAuth(pendingId, IDENTITY);
        const tokens = await provider.exchangeAuthorizationCode(CLIENT, code, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE));

        // A provider serving a DIFFERENT resource, sharing the same store, must
        // reject a token minted for the original audience.
        const otherProvider = new GmailOAuthProvider(makeConfig(dir, 'https://other.example/mcp'), store);
        await expect(otherProvider.verifyAccessToken(tokens.access_token)).rejects.toThrow(/audience/);
    });

    it('rotates refresh tokens and detects reuse, revoking the family', async () => {
        const pendingId = await runAuthorize(provider);
        const { code } = await provider.completeGoogleAuth(pendingId, IDENTITY);
        const first = await provider.exchangeAuthorizationCode(CLIENT, code, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE));

        const rotated = await provider.exchangeRefreshToken(CLIENT, first.refresh_token!, undefined, new URL(RESOURCE));
        expect(rotated.access_token).not.toBe(first.access_token);
        expect(rotated.refresh_token).not.toBe(first.refresh_token);

        // Reusing the now-consumed first refresh token is treated as theft.
        await expect(
            provider.exchangeRefreshToken(CLIENT, first.refresh_token!, undefined, new URL(RESOURCE)),
        ).rejects.toThrow(/reuse detected/);

        // Family revoked: the rotated access token no longer verifies.
        await expect(provider.verifyAccessToken(rotated.access_token)).rejects.toThrow();
    });

    it('links a second account to the same principal (one-time ticket)', async () => {
        // Primary connect → principal owns account A.
        const pendingId = await runAuthorize(provider);
        const { code } = await provider.completeGoogleAuth(pendingId, IDENTITY);
        const tokens = await provider.exchangeAuthorizationCode(
            CLIENT, code, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE),
        );
        const principalId = (await provider.verifyAccessToken(tokens.access_token)).extra!
            .principalId as string;

        // Link account B via a one-time ticket (as the /link callback would).
        const ticket = await provider.createLinkTicket(principalId);
        expect(await provider.consumeLinkTicket(ticket)).toBe(principalId);
        expect(await provider.consumeLinkTicket(ticket)).toBeUndefined(); // one-time

        const ACCOUNT_B: GoogleIdentity = {
            sub: 'google-sub-2',
            email: 'work@example.com',
            refreshToken: 'google-refresh-token-B',
            scopeNames: ['gmail.modify'],
        };
        await provider.linkGoogleAccount(principalId, ACCOUNT_B);

        const principal = await store.getPrincipal(principalId);
        expect(principal?.primarySub).toBe('google-sub-1');
        expect(principal?.accountSubs.sort()).toEqual(['google-sub-1', 'google-sub-2']);
        expect(await store.getGoogleRefreshToken('google-sub-2')).toBe('google-refresh-token-B');
        // The linked account points back at the same principal.
        expect((await store.getGoogleUser('google-sub-2'))?.principalId).toBe(principalId);
    });

    it('reuses the existing principal when the same primary reconnects', async () => {
        const p1 = await runAuthorize(provider);
        const c1 = (await provider.completeGoogleAuth(p1, IDENTITY)).code;
        const t1 = await provider.exchangeAuthorizationCode(CLIENT, c1, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE));
        const pid1 = (await provider.verifyAccessToken(t1.access_token)).extra!.principalId;

        const p2 = await runAuthorize(provider);
        const c2 = (await provider.completeGoogleAuth(p2, IDENTITY)).code;
        const t2 = await provider.exchangeAuthorizationCode(CLIENT, c2, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE));
        const pid2 = (await provider.verifyAccessToken(t2.access_token)).extra!.principalId;

        expect(pid2).toBe(pid1); // same Google primary → same principal
    });

    it('rejects a refresh token issued to a different client', async () => {
        const pendingId = await runAuthorize(provider);
        const { code } = await provider.completeGoogleAuth(pendingId, IDENTITY);
        const tokens = await provider.exchangeAuthorizationCode(CLIENT, code, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE));
        const otherClient = { ...CLIENT, client_id: 'someone-else' };
        await expect(
            provider.exchangeRefreshToken(otherClient, tokens.refresh_token!, undefined, new URL(RESOURCE)),
        ).rejects.toThrow(/another client/);
    });

    it('revokeToken burns the whole family', async () => {
        const pendingId = await runAuthorize(provider);
        const { code } = await provider.completeGoogleAuth(pendingId, IDENTITY);
        const tokens = await provider.exchangeAuthorizationCode(CLIENT, code, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE));
        await provider.revokeToken(CLIENT, { token: tokens.access_token });
        await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow();
    });

    it('rejects a stale pending auth (expired state)', async () => {
        const provShort = new GmailOAuthProvider({ ...makeConfig(dir), pendingAuthTtlSec: 0 }, store);
        const pendingId = await runAuthorize(provShort);
        await new Promise((r) => setTimeout(r, 1100));
        await expect(provShort.completeGoogleAuth(pendingId, IDENTITY)).rejects.toThrow(/Unknown, expired/);
    });
});
