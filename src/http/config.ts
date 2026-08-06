// HTTP / remote-mode configuration.
//
// This module centralizes every environment variable and file the remote
// (claude.ai) transport depends on. It is only loaded when the server is
// started in `http` mode, so stdio users never pay for any of this.

import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
    DEFAULT_SCOPES,
    parseScopes,
    validateScopes,
    scopeNamesToUrls,
    getAvailableScopeNames,
} from '../scopes.js';

export interface GoogleKeys {
    clientId: string;
    clientSecret: string;
}

export interface HttpConfig {
    /** Public base URL of this server, e.g. https://gmail.example.com (no trailing slash). */
    baseUrl: string;
    /** Issuer identifier for OAuth metadata — equals baseUrl. */
    issuerUrl: URL;
    /** Canonical resource identifier (RFC 8707 audience) advertised + enforced: `${baseUrl}/mcp`. */
    resourceUrl: string;
    /** Where Google redirects after consent: `${baseUrl}/oauth2/google/callback`. */
    googleCallbackUrl: string;
    /** TCP port to bind. */
    port: number;
    /** Google OAuth web-client credentials from gcp-oauth.keys.json. */
    googleKeys: GoogleKeys;
    /** Gmail scopes (shorthand) the server requests from Google during consent. */
    googleScopeNames: string[];
    /** Same scopes as full Google API URLs (for the consent request). */
    googleScopeUrls: string[];
    /** MCP-level scope advertised to claude.ai (kept distinct from Google scopes). */
    mcpScope: string;
    /** Which storage backend the OAuth store uses. */
    storeBackend: 'file' | 'firestore';
    /** Firestore database id (firestore backend only). */
    firestoreDatabaseId: string;
    /** GCP project id for Firestore; auto-detected on Cloud Run if unset. */
    gcpProject?: string;
    /** Directory where the file-backed OAuth store persists its JSON. */
    configDir: string;
    /** 32-byte key (derived) for AES-256-GCM encryption of Google refresh tokens at rest. */
    encryptionKey: Buffer;
    /** Allowed `Origin` header values for the /mcp endpoint (DNS-rebinding protection). */
    allowedOrigins: string[];
    /** Lifetime of an issued MCP access token, in seconds. */
    accessTokenTtlSec: number;
    /** Lifetime of an issued authorization code, in seconds. */
    authCodeTtlSec: number;
    /** Lifetime of a pending (in-flight) authorization, in seconds. */
    pendingAuthTtlSec: number;
    /** Lifetime of a parked authorize request (while managing accounts), in seconds. */
    authRequestTtlSec: number;
}

// The single MCP-level scope. We deliberately do NOT expose Google scope URLs
// to claude.ai — what a token can actually do is governed by the Google scopes
// the user granted, checked per-tool at call time.
const MCP_SCOPE = 'gmail';

function requireEnv(name: string): string {
    const value = process.env[name];
    if (!value || value.trim() === '') {
        throw new Error(
            `Missing required environment variable ${name} (required for http mode).`,
        );
    }
    return value.trim();
}

function loadGoogleKeys(configDir: string): GoogleKeys {
    const oauthPath =
        process.env.GMAIL_OAUTH_PATH || path.join(configDir, 'gcp-oauth.keys.json');
    if (!fs.existsSync(oauthPath)) {
        throw new Error(
            `OAuth keys file not found at ${oauthPath}. Place a Google "web" OAuth client ` +
                `as gcp-oauth.keys.json (or set GMAIL_OAUTH_PATH).`,
        );
    }
    const parsed = JSON.parse(fs.readFileSync(oauthPath, 'utf8'));
    // Remote mode needs a "web" client (it has a server-side redirect URI). An
    // "installed" (desktop) client will not work for the federated flow.
    const keys = parsed.web;
    if (!keys || !keys.client_id || !keys.client_secret) {
        throw new Error(
            'Invalid OAuth keys file for http mode: expected a "web" client with ' +
                'client_id and client_secret. Create an OAuth client of type "Web application" ' +
                'in the Google Cloud Console.',
        );
    }
    return { clientId: keys.client_id, clientSecret: keys.client_secret };
}

function resolveGoogleScopes(): { names: string[]; urls: string[] } {
    const raw = process.env.GMAIL_MCP_SCOPES;
    if (!raw || raw.trim() === '') {
        return { names: DEFAULT_SCOPES, urls: scopeNamesToUrls(DEFAULT_SCOPES) };
    }
    const names = parseScopes(raw);
    const validation = validateScopes(names);
    if (!validation.valid) {
        throw new Error(
            `Invalid GMAIL_MCP_SCOPES: ${validation.invalid.join(', ')}. ` +
                `Available: ${getAvailableScopeNames().join(', ')}`,
        );
    }
    return { names, urls: scopeNamesToUrls(names) };
}

/**
 * Build and validate the http-mode configuration from the environment.
 * Throws a descriptive error (which main() reports and exits on) if anything
 * required is missing or malformed.
 */
export function loadHttpConfig(): HttpConfig {
    const configDir =
        process.env.GMAIL_MCP_CONFIG_DIR || path.join(os.homedir(), '.gmail-mcp');
    if (!fs.existsSync(configDir)) {
        fs.mkdirSync(configDir, { recursive: true, mode: 0o700 });
    }

    const baseUrlRaw = requireEnv('BASE_URL').replace(/\/+$/, '');
    let issuerUrl: URL;
    try {
        issuerUrl = new URL(baseUrlRaw);
    } catch {
        throw new Error(`BASE_URL is not a valid URL: ${baseUrlRaw}`);
    }
    if (issuerUrl.search || issuerUrl.hash) {
        throw new Error('BASE_URL must not contain a query string or fragment.');
    }
    const isLocalhost =
        issuerUrl.hostname === 'localhost' || issuerUrl.hostname === '127.0.0.1';
    if (issuerUrl.protocol !== 'https:' && !isLocalhost) {
        throw new Error(
            `BASE_URL must use https (got ${issuerUrl.protocol}//). ` +
                `claude.ai only connects to HTTPS issuers. Terminate TLS at a proxy/tunnel ` +
                `and set BASE_URL to the external https URL.`,
        );
    }

    // Derive a 32-byte key deterministically so the server can decrypt across
    // restarts. The raw secret never touches disk; only ciphertext does.
    const encryptionSecret = requireEnv('TOKEN_ENCRYPTION_KEY');
    if (encryptionSecret.length < 16) {
        throw new Error('TOKEN_ENCRYPTION_KEY must be at least 16 characters.');
    }

    const { names: googleScopeNames, urls: googleScopeUrls } = resolveGoogleScopes();

    const allowedOrigins = (process.env.MCP_ALLOWED_ORIGINS || '')
        .split(',')
        .map((s) => s.trim())
        .filter((s) => s.length > 0);

    const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
    if (Number.isNaN(port)) {
        throw new Error(`PORT is not a number: ${process.env.PORT}`);
    }

    // Default to Firestore when running on Cloud Run (K_SERVICE is set there),
    // otherwise the local file store. Override explicitly with STORE_BACKEND.
    const storeBackendEnv = (process.env.STORE_BACKEND || '').toLowerCase();
    const storeBackend: 'file' | 'firestore' =
        storeBackendEnv === 'firestore' || storeBackendEnv === 'file'
            ? (storeBackendEnv as 'file' | 'firestore')
            : process.env.K_SERVICE
              ? 'firestore'
              : 'file';

    return {
        storeBackend,
        firestoreDatabaseId: process.env.FIRESTORE_DATABASE_ID || '(default)',
        gcpProject:
            process.env.GOOGLE_CLOUD_PROJECT || process.env.GCP_PROJECT || undefined,
        baseUrl: baseUrlRaw,
        issuerUrl,
        resourceUrl: `${baseUrlRaw}/mcp`,
        googleCallbackUrl: `${baseUrlRaw}/oauth2/google/callback`,
        port,
        googleKeys: loadGoogleKeys(configDir),
        googleScopeNames,
        googleScopeUrls,
        mcpScope: MCP_SCOPE,
        configDir,
        // scrypt with a fixed app salt keeps key derivation deterministic.
        encryptionKey: deriveKey(encryptionSecret),
        allowedOrigins,
        accessTokenTtlSec: 60 * 60, // 1 hour
        authCodeTtlSec: 60, // 1 minute
        pendingAuthTtlSec: 10 * 60, // 10 minutes
        authRequestTtlSec: 30 * 60, // 30 minutes (manage page may stay open)
    };
}

// scrypt with a fixed app salt → deterministic 32-byte key, so the server can
// decrypt stored grants across restarts. The raw secret never touches disk.
function deriveKey(secret: string): Buffer {
    return crypto.scryptSync(secret, 'gmail-mcp-oauth-v1', 32);
}
