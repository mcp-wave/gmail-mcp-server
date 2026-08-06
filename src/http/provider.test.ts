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
async function connect(
    provider: GmailOAuthProvider,
    identity: GoogleIdentity = IDENTITY,
): Promise<{ principalId: string; redirectUri: string; code: string; state?: string }> {
    // Simulate the Google login that establishes the principal, then run the
    // always-manage authorize flow and click "Continue" (finalize).
    const principalId = await provider.ensurePrincipal(identity);
    let captured = "";
    const res = { redirect: (u: string) => { captured = u; } } as any;
    await provider.authorize(CLIENT, {
        state: "claude-state", scopes: ["gmail"], redirectUri: CLIENT.redirect_uris[0],
        codeChallenge: CHALLENGE, resource: new URL(RESOURCE),
    }, res);
    const reqId = new URL(captured).searchParams.get("req")!;
    const fin = await provider.finalizeAuthorization(reqId, principalId);
    return { principalId, ...fin };
}

/** Park an authorize request and return its reqId. */
async function park(provider: GmailOAuthProvider): Promise<string> {
    let captured = '';
    const res = { redirect: (u: string) => { captured = u; } } as any;
    await provider.authorize(CLIENT, {
        state: 's', scopes: ['gmail'], redirectUri: CLIENT.redirect_uris[0],
        codeChallenge: CHALLENGE, resource: new URL(RESOURCE),
    }, res);
    return new URL(captured).searchParams.get('req')!;
}

describe('GmailOAuthProvider full flow', () => {
    let dir: string;
    let store: FileOAuthStore;
    let provider: GmailOAuthProvider;
    let encryptionKey: Buffer;
    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gmail-mcp-prov-'));
        encryptionKey = crypto.randomBytes(32);
        store = new FileOAuthStore(dir, encryptionKey);
        provider = new GmailOAuthProvider(makeConfig(dir), store);
    });
    afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

    it('authorize -> callback -> code -> token issues a verifiable bearer', async () => {
        const { redirectUri, code, state } = await connect(provider);
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
        const { code } = await connect(provider);
        await provider.exchangeAuthorizationCode(CLIENT, code, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE));
        await expect(
            provider.exchangeAuthorizationCode(CLIENT, code, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE)),
        ).rejects.toThrow(/Invalid or expired authorization code/);
    });

    it('rejects a code exchanged with a mismatched redirect_uri', async () => {
        const { code } = await connect(provider);
        await expect(
            provider.exchangeAuthorizationCode(CLIENT, code, undefined, 'https://evil.example/cb', new URL(RESOURCE)),
        ).rejects.toThrow(/redirect_uri/);
    });

    it('rejects a code exchanged for the wrong resource (audience)', async () => {
        const { code } = await connect(provider);
        await expect(
            provider.exchangeAuthorizationCode(CLIENT, code, undefined, CLIENT.redirect_uris[0], new URL('https://other.example/mcp')),
        ).rejects.toThrow(/resource/);
    });

    it('rejects an unknown authorization code at PKCE lookup', async () => {
        await expect(provider.challengeForAuthorizationCode(CLIENT, 'nope')).rejects.toThrow(/Invalid or expired/);
    });

    it('enforces audience binding at verify time', async () => {
        const { code } = await connect(provider);
        const tokens = await provider.exchangeAuthorizationCode(CLIENT, code, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE));

        // A provider serving a DIFFERENT resource, sharing the same store, must
        // reject a token minted for the original audience.
        const otherProvider = new GmailOAuthProvider(makeConfig(dir, 'https://other.example/mcp'), store);
        await expect(otherProvider.verifyAccessToken(tokens.access_token)).rejects.toThrow(/audience/);
    });

    it('rotates refresh tokens and detects reuse, revoking the family', async () => {
        const { code } = await connect(provider);
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
        const { code } = await connect(provider);
        const tokens = await provider.exchangeAuthorizationCode(
            CLIENT, code, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE),
        );
        const principalId = (await provider.verifyAccessToken(tokens.access_token)).extra!
            .principalId as string;

        // Link account B via a one-time ticket (as the /link callback would).
        const ticket = await provider.createLinkTicket(principalId);
        expect((await provider.consumeLinkTicket(ticket))?.principalId).toBe(principalId);
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
        // Linking records membership only: it must NOT claim the account, or
        // signing in with it would resume someone else's principal.
        expect(await store.getPrimaryPrincipal('google-sub-2')).toBeUndefined();
    });

    it('routes /authorize to the manage page; Continue issues a code', async () => {
        const principalId = await provider.ensurePrincipal(IDENTITY);

        // /authorize always parks the request and redirects to the manage page.
        // No cookie is read: any Cookie header present must be irrelevant.
        let captured = '';
        const res = {
            redirect: (u: string) => { captured = u; },
            req: { headers: { cookie: 'mcp_session=stale-value-from-another-account' } },
        } as any;
        await provider.authorize(CLIENT, {
            state: 'cs', scopes: ['gmail'], redirectUri: CLIENT.redirect_uris[0],
            codeChallenge: CHALLENGE, resource: new URL(RESOURCE),
        }, res);
        expect(captured).toContain('/manage?req=');
        const reqId = new URL(captured).searchParams.get('req')!;

        // "Continue" finalizes: mints a code bound to the principal + original request.
        const { redirectUri, code, state } = await provider.finalizeAuthorization(reqId, principalId);
        expect(redirectUri).toBe(CLIENT.redirect_uris[0]);
        expect(state).toBe('cs');

        const tokens = await provider.exchangeAuthorizationCode(
            CLIENT, code, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE),
        );
        const auth = await provider.verifyAccessToken(tokens.access_token);
        expect((auth.extra as any).principalId).toBe(principalId);
    });

    it('binds each authorize request to its OWN principal (no cross-request/cookie bleed)', async () => {
        const IDENTITY_B: GoogleIdentity = {
            sub: 'google-sub-2', email: 'b@example.com',
            refreshToken: 'rt-b', scopeNames: ['gmail.modify'],
        };
        const park = async () => {
            let captured = '';
            const res = { redirect: (u: string) => { captured = u; } } as any;
            await provider.authorize(CLIENT, {
                state: 's', scopes: ['gmail'], redirectUri: CLIENT.redirect_uris[0],
                codeChallenge: CHALLENGE, resource: new URL(RESOURCE),
            }, res);
            return new URL(captured).searchParams.get('req')!;
        };
        // Two separate connections (e.g. two claude.ai accounts in one browser).
        const reqA = await park();
        const reqB = await park();

        // Each is signed in as a different Google identity, bound to its request.
        const pA = await provider.ensurePrincipal(IDENTITY);
        await store.setAuthRequestPrincipal(reqA, pA);
        const pB = await provider.ensurePrincipal(IDENTITY_B);
        await store.setAuthRequestPrincipal(reqB, pB);
        expect(pA).not.toBe(pB);

        // The manage page reads the principal from the request, not an ambient cookie.
        expect((await store.getAuthRequest(reqA, 3600))?.principalId).toBe(pA);
        expect((await store.getAuthRequest(reqB, 3600))?.principalId).toBe(pB);

        // Finalizing each yields a token bound to its OWN principal.
        const finA = await provider.finalizeAuthorization(reqA, (await store.getAuthRequest(reqA, 3600))!.principalId!);
        const finB = await provider.finalizeAuthorization(reqB, (await store.getAuthRequest(reqB, 3600))!.principalId!);
        const tA = await provider.exchangeAuthorizationCode(CLIENT, finA.code, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE));
        const tB = await provider.exchangeAuthorizationCode(CLIENT, finB.code, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE));
        expect((await provider.verifyAccessToken(tA.access_token)).extra!.principalId).toBe(pA);
        expect((await provider.verifyAccessToken(tB.access_token)).extra!.principalId).toBe(pB);
    });

    it('reuses the existing principal when the same primary reconnects', async () => {
        const c1 = await connect(provider);
        const t1 = await provider.exchangeAuthorizationCode(CLIENT, c1.code, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE));
        const pid1 = (await provider.verifyAccessToken(t1.access_token)).extra!.principalId;

        const c2 = await connect(provider);
        const t2 = await provider.exchangeAuthorizationCode(CLIENT, c2.code, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE));
        const pid2 = (await provider.verifyAccessToken(t2.access_token)).extra!.principalId;

        expect(pid2).toBe(pid1); // same Google primary → same principal
    });

    it('rejects a refresh token issued to a different client', async () => {
        const { code } = await connect(provider);
        const tokens = await provider.exchangeAuthorizationCode(CLIENT, code, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE));
        const otherClient = { ...CLIENT, client_id: 'someone-else' };
        await expect(
            provider.exchangeRefreshToken(otherClient, tokens.refresh_token!, undefined, new URL(RESOURCE)),
        ).rejects.toThrow(/another client/);
    });

    it('revokeToken burns the whole family', async () => {
        const { code } = await connect(provider);
        const tokens = await provider.exchangeAuthorizationCode(CLIENT, code, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE));
        await provider.revokeToken(CLIENT, { token: tokens.access_token });
        await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow();
    });

    it('rejects finalizing an expired authorize request', async () => {
        const provShort = new GmailOAuthProvider({ ...makeConfig(dir), authRequestTtlSec: 0 }, store);
        const principalId = await provShort.ensurePrincipal(IDENTITY);
        let captured = '';
        const res = { redirect: (u: string) => { captured = u; } } as any;
        await provShort.authorize(CLIENT, {
            state: 'cs', scopes: ['gmail'], redirectUri: CLIENT.redirect_uris[0],
            codeChallenge: CHALLENGE, resource: new URL(RESOURCE),
        }, res);
        const reqId = new URL(captured).searchParams.get('req')!;
        await new Promise((r) => setTimeout(r, 1100));
        await expect(provShort.finalizeAuthorization(reqId, principalId)).rejects.toThrow(/expired/);
    });

    it('stores and returns a per-account send policy', async () => {
        const p = await provider.ensurePrincipal(IDENTITY);
        await store.setSendPolicy(p, IDENTITY.sub, { allowlist: ['acme.com', 'boss@partner.com'], dangerouslyAllowAll: false });
        const policy = await store.getSendPolicy(p, IDENTITY.sub);
        expect(policy?.allowlist).toEqual(['acme.com', 'boss@partner.com']);
        expect(policy?.dangerouslyAllowAll).toBe(false);
        // Survives a refresh-token upsert (no new policy supplied).
        await store.upsertGoogleUser(IDENTITY.sub, IDENTITY.email, undefined, IDENTITY.scopeNames);
        expect((await store.getSendPolicy(p, IDENTITY.sub))?.allowlist).toEqual(['acme.com', 'boss@partner.com']);
    });

    // --- Cross-principal isolation ------------------------------------------
    //
    // Regression cover for the bleed where connecting a second client and signing
    // in with an account that was merely LINKED to an existing principal handed
    // over that whole principal: every sibling mailbox, read and send.

    const SECONDARY: GoogleIdentity = {
        sub: 'google-sub-2', email: 'shared@example.com',
        refreshToken: 'rt-secondary', scopeNames: ['gmail.modify'],
    };

    it('a secondary-account sign-in gets its OWN principal, not the one it is linked to', async () => {
        const p1 = await provider.ensurePrincipal(IDENTITY);
        await provider.linkGoogleAccount(p1, SECONDARY);

        // A second connection signs in with the linked (secondary) account.
        const p2 = await provider.ensurePrincipal(SECONDARY);

        expect(p2).not.toBe(p1);
        expect((await store.getPrincipal(p2))?.accountSubs).toEqual([SECONDARY.sub]);
        // The original principal is untouched and still owns both.
        expect((await store.getPrincipal(p1))?.accountSubs.sort())
            .toEqual([IDENTITY.sub, SECONDARY.sub]);
        // Crucially, the newcomer cannot reach the primary's mailbox.
        expect((await store.getPrincipal(p2))?.accountSubs).not.toContain(IDENTITY.sub);
    });

    it('only the primary resumes its principal; the token is bound to it', async () => {
        const p1 = await provider.ensurePrincipal(IDENTITY);
        await provider.linkGoogleAccount(p1, SECONDARY);

        // Same primary reconnecting → same principal (reconnect must keep working).
        expect(await provider.ensurePrincipal(IDENTITY)).toBe(p1);

        // The secondary connecting elsewhere gets a token bound to its own principal.
        const p2 = await provider.ensurePrincipal(SECONDARY);
        const fin = await provider.finalizeAuthorization(await park(provider), p2);
        const t = await provider.exchangeAuthorizationCode(
            CLIENT, fin.code, undefined, CLIENT.redirect_uris[0], new URL(RESOURCE),
        );
        expect((await provider.verifyAccessToken(t.access_token)).extra!.principalId).toBe(p2);
    });

    it('send policy is per-principal, not shared across principals on one mailbox', async () => {
        const p1 = await provider.ensurePrincipal(IDENTITY);
        await provider.linkGoogleAccount(p1, SECONDARY);
        const p2 = await provider.ensurePrincipal(SECONDARY);

        await store.setSendPolicy(p1, SECONDARY.sub, { allowlist: ['a.com'], dangerouslyAllowAll: false });
        await store.setSendPolicy(p2, SECONDARY.sub, { allowlist: [], dangerouslyAllowAll: true });

        expect((await store.getSendPolicy(p1, SECONDARY.sub))?.allowlist).toEqual(['a.com']);
        expect((await store.getSendPolicy(p1, SECONDARY.sub))?.dangerouslyAllowAll).toBe(false);
        expect((await store.getSendPolicy(p2, SECONDARY.sub))?.dangerouslyAllowAll).toBe(true);
    });

    it('unlinking from one principal leaves the mailbox working in another', async () => {
        const p1 = await provider.ensurePrincipal(IDENTITY);
        await provider.linkGoogleAccount(p1, SECONDARY);
        const p2 = await provider.ensurePrincipal(SECONDARY);

        await store.unlinkAccount(p1, SECONDARY.sub);

        expect((await store.getPrincipal(p1))?.accountSubs).toEqual([IDENTITY.sub]);
        // p2 still owns it, so the shared Google grant must survive.
        expect((await store.getPrincipal(p2))?.accountSubs).toEqual([SECONDARY.sub]);
        expect(await store.getGoogleRefreshToken(SECONDARY.sub)).toBe('rt-secondary');
    });

    it('unlinking the last reference drops the shared Google grant', async () => {
        const p1 = await provider.ensurePrincipal(IDENTITY);
        await provider.linkGoogleAccount(p1, SECONDARY);

        await store.unlinkAccount(p1, SECONDARY.sub);

        expect(await store.getGoogleUser(SECONDARY.sub)).toBeUndefined();
        expect(await store.getGoogleRefreshToken(SECONDARY.sub)).toBeUndefined();
    });

    it('refuses to unlink the primary', async () => {
        const p1 = await provider.ensurePrincipal(IDENTITY);
        await store.unlinkAccount(p1, IDENTITY.sub);
        expect((await store.getPrincipal(p1))?.accountSubs).toEqual([IDENTITY.sub]);
    });

    it('migrates a legacy primary back-reference, but never a legacy secondary one', async () => {
        const p1 = await provider.ensurePrincipal(IDENTITY);
        await provider.linkGoogleAccount(p1, SECONDARY);

        // Simulate pre-fix storage: both accounts carry a principalId back-ref
        // and neither is in the primary-owner index.
        const legacy = new FileOAuthStore(dir, encryptionKey);
        (legacy as any).primaryOwners.clear();
        (legacy as any).googleUsers.get(IDENTITY.sub).principalId = p1;
        (legacy as any).googleUsers.get(SECONDARY.sub).principalId = p1;

        // The real primary migrates forward and resumes.
        expect(await legacy.getPrimaryPrincipal(IDENTITY.sub)).toBe(p1);
        // The secondary's stale back-reference must NOT resume p1.
        expect(await legacy.getPrimaryPrincipal(SECONDARY.sub)).toBeUndefined();
    });

    it('falls back to a legacy per-sub send policy until one is set per-principal', async () => {
        const p1 = await provider.ensurePrincipal(IDENTITY);
        const legacy = new FileOAuthStore(dir, encryptionKey);
        (legacy as any).googleUsers.get(IDENTITY.sub).sendPolicy = {
            allowlist: ['old.com'], dangerouslyAllowAll: false,
        };
        expect((await legacy.getSendPolicy(p1, IDENTITY.sub))?.allowlist).toEqual(['old.com']);

        await legacy.setSendPolicy(p1, IDENTITY.sub, { allowlist: ['new.com'], dangerouslyAllowAll: false });
        expect((await legacy.getSendPolicy(p1, IDENTITY.sub))?.allowlist).toEqual(['new.com']);
    });
});
