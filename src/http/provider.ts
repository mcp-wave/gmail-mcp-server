// Custom OAuthServerProvider: this MCP server is its own OAuth 2.1 Authorization
// Server, federating to Google as the upstream IdP. claude.ai speaks MCP OAuth
// to us (DCR + PKCE + opaque bearer tokens we mint); we hold the Google
// relationship and map each of our tokens to a user's Google grant.

import type { Response } from 'express';
import {
    InvalidGrantError,
    InvalidTokenError,
    InvalidTargetError,
} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type {
    OAuthServerProvider,
    AuthorizationParams,
} from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type {
    OAuthClientInformationFull,
    OAuthTokens,
    OAuthTokenRevocationRequest,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import type { HttpConfig } from './config.js';
import { generateToken } from './store.js';
import type { OAuthStore } from './store.js';
import { buildGoogleAuthUrl, type GoogleIdentity } from './google.js';

function nowSec(): number {
    return Math.floor(Date.now() / 1000);
}

function canonical(url: string): string {
    return new URL(url).href;
}

export class GmailOAuthProvider implements OAuthServerProvider {
    // We perform PKCE validation locally (against claude.ai's challenge); we do
    // NOT forward the verifier upstream — Google verifies its own separate code.
    readonly skipLocalPkceValidation = false;

    private readonly resource: string;

    constructor(
        private readonly config: HttpConfig,
        private readonly store: OAuthStore,
    ) {
        this.resource = canonical(config.resourceUrl);
    }

    get clientsStore(): OAuthRegisteredClientsStore {
        return {
            getClient: (clientId) => this.store.getClient(clientId),
            registerClient: (client) =>
                this.store.registerClient(client as OAuthClientInformationFull),
        };
    }

    async authorize(
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
        res: Response,
    ): Promise<void> {
        // ALWAYS route through the setup/manage screen. Park the claude.ai
        // authorize request; the user finishes by clicking Continue, which is the
        // only thing that issues a code back to the agent. /manage handles the
        // case where no session exists yet (first connect → Google login).
        const reqId = generateToken();
        await this.store.putAuthRequest(reqId, {
            clientId: client.client_id,
            redirectUri: params.redirectUri,
            codeChallenge: params.codeChallenge,
            state: params.state,
            resource: params.resource ? canonical(params.resource.href) : this.resource,
            mcpScope: this.config.mcpScope,
            createdAtSec: nowSec(),
        });
        res.redirect(`${this.config.baseUrl}/manage?req=${encodeURIComponent(reqId)}`);
    }

    /** Mint a browser session for a principal; returns the raw session id (cookie value). */
    async createSession(principalId: string): Promise<string> {
        const sessionId = generateToken();
        await this.store.putSession(sessionId, { principalId, createdAtSec: nowSec() });
        return sessionId;
    }

    /** Find-or-create the principal owning a freshly-authorized Google account. */
    async ensurePrincipal(identity: GoogleIdentity): Promise<string> {
        await this.store.upsertGoogleUser(
            identity.sub, identity.email, identity.refreshToken, identity.scopeNames,
        );
        const existing = await this.store.getGoogleUser(identity.sub);
        let principalId = existing?.principalId;
        if (!principalId) {
            principalId = generateToken();
            await this.store.createPrincipal({
                id: principalId,
                primarySub: identity.sub,
                accountSubs: [identity.sub],
                createdAt: nowSec(),
            });
            await this.store.setUserPrincipal(identity.sub, principalId);
        }
        return principalId;
    }

    /**
     * Create a one-time ticket for an account-link / first-connect sign-in.
     * Omit principalId on first connect (the callback creates the principal).
     */
    async createLinkTicket(principalId?: string, authRequestId?: string): Promise<string> {
        const ticket = generateToken();
        await this.store.putLinkTicket(ticket, { principalId, authRequestId, createdAtSec: nowSec() });
        return ticket;
    }

    /** Resolve+consume a link ticket (Google `state` during a link flow). */
    async consumeLinkTicket(ticket: string) {
        return this.store.consumeLinkTicket(ticket, this.config.pendingAuthTtlSec);
    }

    /**
     * Finalize a parked authorize request (manage-page "Continue"): mint our auth
     * code bound to the principal and the original claude.ai request parameters.
     */
    async finalizeAuthorization(
        authRequestId: string,
        principalId: string,
    ): Promise<{ redirectUri: string; code: string; state?: string }> {
        const ar = await this.store.consumeAuthRequest(authRequestId, this.config.authRequestTtlSec);
        if (!ar) throw new InvalidGrantError('Authorization request expired; please reconnect.');
        const code = generateToken();
        await this.store.putAuthCode(code, {
            clientId: ar.clientId,
            redirectUri: ar.redirectUri,
            codeChallenge: ar.codeChallenge,
            mcpScope: ar.mcpScope,
            resource: ar.resource,
            principalId,
            createdAtSec: nowSec(),
        });
        return { redirectUri: ar.redirectUri, code, state: ar.state };
    }

    /** Attach a newly-authorized Google account to an existing principal. */
    async linkGoogleAccount(principalId: string, identity: GoogleIdentity): Promise<void> {
        await this.store.upsertGoogleUser(
            identity.sub,
            identity.email,
            identity.refreshToken,
            identity.scopeNames,
        );
        await this.store.setUserPrincipal(identity.sub, principalId);
        await this.store.addAccountToPrincipal(principalId, identity.sub);
    }

    async challengeForAuthorizationCode(
        _client: OAuthClientInformationFull,
        authorizationCode: string,
    ): Promise<string> {
        const challenge = await this.store.peekAuthCodeChallenge(authorizationCode);
        if (challenge === undefined) {
            throw new InvalidGrantError('Invalid or expired authorization code');
        }
        return challenge;
    }

    async exchangeAuthorizationCode(
        client: OAuthClientInformationFull,
        authorizationCode: string,
        _codeVerifier?: string,
        redirectUri?: string,
        resource?: URL,
    ): Promise<OAuthTokens> {
        const rec = await this.store.consumeAuthCode(
            authorizationCode,
            this.config.authCodeTtlSec,
        );
        if (!rec) throw new InvalidGrantError('Invalid or expired authorization code');
        if (rec.clientId !== client.client_id) {
            throw new InvalidGrantError('Authorization code was issued to another client');
        }
        if (redirectUri !== undefined && redirectUri !== rec.redirectUri) {
            throw new InvalidGrantError('redirect_uri does not match the authorization request');
        }
        if (resource && canonical(resource.href) !== rec.resource) {
            throw new InvalidTargetError('resource does not match the authorization request');
        }
        return this.issueTokens(rec.clientId, rec.principalId, rec.mcpScope, rec.resource, generateToken());
    }

    async exchangeRefreshToken(
        client: OAuthClientInformationFull,
        refreshToken: string,
        _scopes?: string[],
        resource?: URL,
    ): Promise<OAuthTokens> {
        const rec = await this.store.getRefreshToken(refreshToken);
        if (!rec) throw new InvalidGrantError('Invalid refresh token');
        if (rec.clientId !== client.client_id) {
            throw new InvalidGrantError('Refresh token was issued to another client');
        }
        if (rec.used) {
            // Reuse of a rotated refresh token is the canonical theft signal:
            // burn the whole family.
            await this.store.revokeFamily(rec.familyId);
            throw new InvalidGrantError('Refresh token reuse detected; session revoked');
        }
        if (resource && canonical(resource.href) !== rec.resource) {
            throw new InvalidTargetError('resource does not match the original grant');
        }
        await this.store.markRefreshTokenUsed(refreshToken);
        return this.issueTokens(rec.clientId, rec.principalId, rec.mcpScope, rec.resource, rec.familyId);
    }

    async verifyAccessToken(token: string): Promise<AuthInfo> {
        const rec = await this.store.getAccessToken(token);
        if (!rec) throw new InvalidTokenError('Invalid access token');
        if (rec.expiresAtSec <= nowSec()) throw new InvalidTokenError('Access token expired');
        // Audience binding (RFC 8707) — the SDK does NOT enforce this for us.
        if (rec.resource !== this.resource) {
            throw new InvalidTokenError('Access token audience mismatch');
        }
        return {
            token,
            clientId: rec.clientId,
            scopes: [rec.mcpScope],
            expiresAt: rec.expiresAtSec, // seconds since epoch — required by bearerAuth
            resource: new URL(rec.resource),
            extra: { principalId: rec.principalId },
        };
    }

    async revokeToken(
        _client: OAuthClientInformationFull,
        request: OAuthTokenRevocationRequest,
    ): Promise<void> {
        const token = request.token;
        const at = await this.store.getAccessToken(token);
        const family = at?.familyId ?? (await this.store.getRefreshToken(token))?.familyId;
        if (family) await this.store.revokeFamily(family);
    }

    private async issueTokens(
        clientId: string,
        principalId: string,
        mcpScope: string,
        resource: string,
        familyId: string,
    ): Promise<OAuthTokens> {
        const accessToken = generateToken();
        const refreshToken = generateToken();
        const expiresAtSec = nowSec() + this.config.accessTokenTtlSec;
        await this.store.putAccessToken(accessToken, {
            clientId,
            principalId,
            mcpScope,
            resource,
            familyId,
            expiresAtSec,
        });
        await this.store.putRefreshToken(refreshToken, {
            clientId,
            principalId,
            mcpScope,
            resource,
            familyId,
            createdAtSec: nowSec(),
            used: false,
        });
        return {
            access_token: accessToken,
            token_type: 'bearer',
            expires_in: this.config.accessTokenTtlSec,
            scope: mcpScope,
            refresh_token: refreshToken,
        };
    }
}

export type { OAuthStore };
