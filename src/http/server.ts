// Remote (claude.ai) transport: an Express app that exposes the MCP server over
// Streamable HTTP, guarded by the OAuth 2.1 authorization layer.
//
// Wiring:
//   - mcpAuthRouter: serves discovery metadata (.well-known/*), dynamic client
//     registration, /authorize, /token, /revoke — backed by GmailOAuthProvider.
//   - /oauth2/google/callback: the upstream (Google) redirect target.
//   - /mcp: bearer-authenticated MCP endpoint. Each request resolves the caller's
//     own Gmail client from its token, so the server is multi-tenant.

import express from 'express';
import type { Request, Response } from 'express';
import { randomUUID } from 'crypto';
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { loadHttpConfig, type HttpConfig } from './config.js';
import { createStore } from './store.js';
import { GmailOAuthProvider } from './provider.js';
import { GmailClientCache, exchangeGoogleCode, buildGoogleAuthUrl, ReauthRequiredError } from './google.js';
import type { OAuthStore } from './store.js';
import type { PrincipalSession, Account, ResolveSession } from '../session.js';

/** What each tool call needs: a Gmail client + the caller's granted scopes. */
/** Builds the MCP Server with all tool handlers (implemented in index.ts). */
export type McpServerFactory = (resolve: ResolveSession) => Server;

/** Reject browser requests from disallowed origins (DNS-rebinding protection). */
function originGuard(config: HttpConfig) {
    const allowed = new Set([config.baseUrl, ...config.allowedOrigins]);
    return (req: Request, res: Response, next: express.NextFunction) => {
        const origin = req.headers.origin;
        // Server-to-server callers (e.g. claude.ai's backend) send no Origin.
        if (!origin || allowed.has(origin)) return next();
        res.status(403).json({ error: 'forbidden_origin' });
    };
}

export async function startHttpServer(createMcpServer: McpServerFactory): Promise<void> {
    const config = loadHttpConfig();
    const store = await createStore(config);
    const provider = new GmailOAuthProvider(config, store);
    const cache = new GmailClientCache(config, store);

    // Periodic GC of expired tokens / codes / pending auths (no-op on Firestore).
    const sweep = setInterval(
        () => void store.sweep(config.pendingAuthTtlSec, config.authCodeTtlSec),
        5 * 60 * 1000,
    );
    sweep.unref?.();

    // Resolve the caller's principal (and all its linked Gmail accounts) from the
    // bearer token. Clients are pre-resolved so getClient() can be synchronous.
    const resolveSession: ResolveSession = async (extra) => {
        const principalId = extra?.authInfo?.extra?.principalId as string | undefined;
        if (!principalId) throw new ReauthRequiredError('Missing authentication context.');
        return buildPrincipalSession(config, store, cache, provider, principalId);
    };

    const app = express();
    app.disable('x-powered-by');

    // OAuth 2.1 Authorization Server endpoints + discovery metadata.
    app.use(
        mcpAuthRouter({
            provider,
            issuerUrl: config.issuerUrl,
            resourceServerUrl: new URL(config.resourceUrl),
            scopesSupported: [config.mcpScope],
            resourceName: 'Gmail MCP Server',
        }),
    );

    // Upstream (Google) redirect target. redirect_uri is taken ONLY from the
    // server-stored pending record — never from a query param (no open redirect).
    app.get('/oauth2/google/callback', async (req: Request, res: Response) => {
        const code = req.query.code as string | undefined;
        const state = req.query.state as string | undefined;
        const error = req.query.error as string | undefined;
        if (error) {
            res.status(400).send(`Google authorization failed: ${sanitize(error)}`);
            return;
        }
        if (!code || !state) {
            res.status(400).send('Missing code or state.');
            return;
        }
        try {
            const identity = await exchangeGoogleCode(config, code);

            // Linking flow: `state` is a one-time link ticket bound to a principal.
            // (A primary-connect `state` is a pendingAuthId, which won't match here
            // and falls through to completeGoogleAuth.)
            const linkPrincipalId = await provider.consumeLinkTicket(state);
            if (linkPrincipalId) {
                await provider.linkGoogleAccount(linkPrincipalId, identity);
                res.status(200).send(linkedAccountPage(identity.email));
                return;
            }

            const { redirectUri, code: ourCode, state: claudeState } =
                await provider.completeGoogleAuth(state, identity);
            const dest = new URL(redirectUri);
            dest.searchParams.set('code', ourCode);
            if (claudeState) dest.searchParams.set('state', claudeState);
            res.redirect(dest.toString());
        } catch (err: any) {
            // Never log tokens/codes; report a generic message.
            console.error('Google callback error:', err?.message || err);
            res.status(400).send('Authorization could not be completed. Please try connecting again.');
        }
    });

    // Start an account-link flow: redirect to Google with the link ticket as
    // state and the account chooser forced. The ticket is validated (consumed)
    // back at /oauth2/google/callback.
    app.get('/link/start', (req: Request, res: Response) => {
        const ticket = req.query.ticket as string | undefined;
        if (!ticket) {
            res.status(400).send('Missing link ticket.');
            return;
        }
        res.redirect(buildGoogleAuthUrl(config, ticket, true));
    });

    const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(
        new URL(config.resourceUrl),
    );
    const bearer = requireBearerAuth({ verifier: provider, resourceMetadataUrl });
    const origin = originGuard(config);

    // Stateful Streamable HTTP: one transport per MCP session, keyed by session id.
    const transports: Record<string, StreamableHTTPServerTransport> = {};

    app.post('/mcp', origin, bearer, express.json(), async (req: Request, res: Response) => {
        try {
            const sessionId = req.headers['mcp-session-id'] as string | undefined;
            let transport = sessionId ? transports[sessionId] : undefined;

            if (!transport && isInitializeRequest(req.body)) {
                transport = new StreamableHTTPServerTransport({
                    sessionIdGenerator: () => randomUUID(),
                    onsessioninitialized: (sid) => {
                        transports[sid] = transport!;
                    },
                });
                transport.onclose = () => {
                    if (transport!.sessionId) delete transports[transport!.sessionId];
                };
                const server = createMcpServer(resolveSession);
                await server.connect(transport);
            } else if (!transport) {
                res.status(400).json({
                    jsonrpc: '2.0',
                    error: { code: -32000, message: 'No valid session; send an initialize request first.' },
                    id: null,
                });
                return;
            }

            await transport.handleRequest(req, res, req.body);
        } catch (err: any) {
            console.error('MCP request error:', err?.message || err);
            if (!res.headersSent) {
                res.status(500).json({
                    jsonrpc: '2.0',
                    error: { code: -32603, message: 'Internal server error' },
                    id: null,
                });
            }
        }
    });

    // GET (server->client SSE stream) and DELETE (session teardown).
    const sessionRequest = async (req: Request, res: Response) => {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        const transport = sessionId ? transports[sessionId] : undefined;
        if (!transport) {
            res.status(400).send('Invalid or missing session id');
            return;
        }
        await transport.handleRequest(req, res);
    };
    app.get('/mcp', origin, bearer, sessionRequest);
    app.delete('/mcp', origin, bearer, sessionRequest);

    app.get('/healthz', (_req, res) => res.json({ status: 'ok' }));

    app.listen(config.port, () => {
        console.error(`Gmail MCP server (http) listening on port ${config.port}`);
        console.error(`Public base URL: ${config.baseUrl}`);
        console.error(`MCP endpoint:    ${config.resourceUrl}`);
        console.error(`Google callback: ${config.googleCallbackUrl}`);
        console.error(`Google scopes:   ${config.googleScopeNames.join(', ')}`);
    });
}

function sanitize(s: string): string {
    return s.replace(/[^a-zA-Z0-9_\- ]/g, '').slice(0, 100);
}

function escapeHtml(s: string): string {
    return s.replace(/[&<>"']/g, (c) =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string),
    );
}

function linkedAccountPage(email: string): string {
    return `<!doctype html><html><head><meta charset="utf-8"><title>Account linked</title></head>
<body style="font-family:system-ui;max-width:32rem;margin:4rem auto;text-align:center">
<h2>✓ ${escapeHtml(email)} linked</h2>
<p>This mailbox is now available to your assistant. You can close this window and return to your chat.</p>
</body></html>`;
}

/**
 * Build the per-request principal session: load the principal, pre-resolve a
 * Gmail client for each linked account (so getClient is synchronous), and expose
 * link/unlink operations. Dead grants on secondary accounts are skipped; a dead
 * primary surfaces as a re-auth error.
 */
async function buildPrincipalSession(
    config: HttpConfig,
    store: OAuthStore,
    cache: GmailClientCache,
    provider: GmailOAuthProvider,
    principalId: string,
): Promise<PrincipalSession> {
    const principal = await store.getPrincipal(principalId);
    if (!principal) throw new ReauthRequiredError('Connection not found. Please reconnect.');

    const clients = new Map<string, { gmail: any; authorizedScopes: string[] }>();
    const accounts: Account[] = [];

    for (const sub of principal.accountSubs) {
        const user = await store.getGoogleUser(sub);
        if (!user) continue;
        const isPrimary = sub === principal.primarySub;
        try {
            const { gmail, scopeNames } = await cache.getForUser(sub);
            clients.set(sub, { gmail, authorizedScopes: scopeNames });
            accounts.push({ sub, email: user.email, primary: isPrimary, scopeNames });
        } catch (err) {
            // Secondary with a dead grant: skip it. Dead primary: fail the session.
            if (isPrimary) throw err;
        }
    }
    if (accounts.length === 0) throw new ReauthRequiredError('No active mailbox. Please reconnect.');

    return {
        principalId,
        accounts,
        getClient: (sub: string) => {
            const c = clients.get(sub);
            if (!c) throw new ReauthRequiredError('Mailbox unavailable. Please reconnect that account.');
            return c;
        },
        linkAccount: async () => {
            const ticket = await provider.createLinkTicket(principalId);
            return `${config.baseUrl}/link/start?ticket=${encodeURIComponent(ticket)}`;
        },
        unlinkAccount: async (sub: string) => {
            await store.removeAccountFromPrincipal(principalId, sub);
            await store.deleteGoogleUser(sub);
            cache.evict(sub);
        },
    };
}
