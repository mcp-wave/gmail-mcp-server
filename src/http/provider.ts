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
import { OAuthStore, generateToken } from './store.js';
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
        this.store.putPendingAuth({
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
        const pending = this.store.consumePendingAuth(
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

        const code = generateToken();
        this.store.putAuthCode(code, {
            clientId: pending.clientId,
            redirectUri: pending.redirectUri,
            codeChallenge: pending.codeChallenge,
            mcpScope: pending.mcpScope,
            resource: pending.resource,
            googleSub: identity.sub,
            createdAtSec: nowSec(),
        });

        return { redirectUri: pending.redirectUri, code, state: pending.state };
    }

    async challengeForAuthorizationCode(
        _client: OAuthClientInformationFull,
        authorizationCode: string,
    ): Promise<string> {
        const challenge = this.store.peekAuthCodeChallenge(authorizationCode);
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
        const rec = this.store.consumeAuthCode(
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
        return this.issueTokens(rec.clientId, rec.googleSub, rec.mcpScope, rec.resource, generateToken());
    }

    async exchangeRefreshToken(
        client: OAuthClientInformationFull,
        refreshToken: string,
        _scopes?: string[],
        resource?: URL,
    ): Promise<OAuthTokens> {
        const rec = this.store.getRefreshToken(refreshToken);
        if (!rec) throw new InvalidGrantError('Invalid refresh token');
        if (rec.clientId !== client.client_id) {
            throw new InvalidGrantError('Refresh token was issued to another client');
        }
        if (rec.used) {
            // Reuse of a rotated refresh token is the canonical theft signal:
            // burn the whole family.
            this.store.revokeFamily(rec.familyId);
            throw new InvalidGrantError('Refresh token reuse detected; session revoked');
        }
        if (resource && canonical(resource.href) !== rec.resource) {
            throw new InvalidTargetError('resource does not match the original grant');
        }
        this.store.markRefreshTokenUsed(refreshToken);
        return this.issueTokens(rec.clientId, rec.googleSub, rec.mcpScope, rec.resource, rec.familyId);
    }

    async verifyAccessToken(token: string): Promise<AuthInfo> {
        const rec = this.store.getAccessToken(token);
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
            extra: { googleSub: rec.googleSub },
        };
    }

    async revokeToken(
        _client: OAuthClientInformationFull,
        request: OAuthTokenRevocationRequest,
    ): Promise<void> {
        const token = request.token;
        const family =
            this.store.getAccessToken(token)?.familyId ??
            this.store.getRefreshToken(token)?.familyId;
        if (family) this.store.revokeFamily(family);
    }

    private issueTokens(
        clientId: string,
        googleSub: string,
        mcpScope: string,
        resource: string,
        familyId: string,
    ): OAuthTokens {
        const accessToken = generateToken();
        const refreshToken = generateToken();
        const expiresAtSec = nowSec() + this.config.accessTokenTtlSec;
        this.store.putAccessToken(accessToken, {
            clientId,
            googleSub,
            mcpScope,
            resource,
            familyId,
            expiresAtSec,
        });
        this.store.putRefreshToken(refreshToken, {
            clientId,
            googleSub,
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
