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
        // High-entropy, one-time id ties Google's callback back to this request
        // (it is the OAuth `state` we send to Google). Stored server-side; the
        // claude redirect_uri here was already validated by the SDK.
        const pendingId = generateToken();
        await this.store.putPendingAuth({
            id: pendingId,
            clientId: client.client_id,
            redirectUri: params.redirectUri,
            codeChallenge: params.codeChallenge,
            state: params.state,
            mcpScope: this.config.mcpScope,
            resource: params.resource ? canonical(params.resource.href) : this.resource,
            createdAtSec: nowSec(),
        });
        res.redirect(buildGoogleAuthUrl(this.config, pendingId));
    }

    /**
     * Completes the flow after Google redirects back. Called by the
     * /oauth2/google/callback route (not part of the provider interface).
     * Returns where to send the user's browser next (claude's redirect_uri).
     */
    async completeGoogleAuth(
        pendingId: string,
        identity: GoogleIdentity,
    ): Promise<{ redirectUri: string; code: string; state?: string }> {
        const pending = await this.store.consumePendingAuth(
            pendingId,
            this.config.pendingAuthTtlSec,
        );
        if (!pending) {
            throw new InvalidGrantError('Unknown, expired, or already-used authorization state');
        }

        // Persist the user's Google grant (serialized per-user). Throws if no
        // refresh token is available and none was previously stored.
        await this.store.upsertGoogleUser(
            identity.sub,
            identity.email,
            identity.refreshToken,
            identity.scopeNames,
        );

        // Find-or-create the principal this primary account belongs to. The token
        // we ultimately mint is bound to the PRINCIPAL, not the single account,
        // so additional mailboxes can be linked under the same connection.
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

        const code = generateToken();
        await this.store.putAuthCode(code, {
            clientId: pending.clientId,
            redirectUri: pending.redirectUri,
            codeChallenge: pending.codeChallenge,
            mcpScope: pending.mcpScope,
            resource: pending.resource,
            principalId,
            createdAtSec: nowSec(),
        });

        return { redirectUri: pending.redirectUri, code, state: pending.state };
    }

    /** Create a one-time ticket that links a new Google account to a principal. */
    async createLinkTicket(principalId: string): Promise<string> {
        const ticket = generateToken();
        await this.store.putLinkTicket(ticket, { principalId, createdAtSec: nowSec() });
        return ticket;
    }

    /** Resolve a link ticket (Google `state` during a link flow) to its principal. */
    async consumeLinkTicket(ticket: string): Promise<string | undefined> {
        const rec = await this.store.consumeLinkTicket(ticket, this.config.pendingAuthTtlSec);
        return rec?.principalId;
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
