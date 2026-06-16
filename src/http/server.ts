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
import { GmailClientCache, exchangeGoogleCode, ReauthRequiredError } from './google.js';

/** What each tool call needs: a Gmail client + the caller's granted scopes. */
export interface Session {
    gmail: any;
    authorizedScopes: string[];
}

/** Resolves the per-request session from the validated bearer token. */
export type ResolveSession = (extra: any) => Promise<Session> | Session;

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

    // Resolve the caller's Gmail client from their bearer token's identity.
    const resolveSession: ResolveSession = async (extra) => {
        const sub = extra?.authInfo?.extra?.googleSub as string | undefined;
        if (!sub) throw new ReauthRequiredError('Missing authentication context.');
        const { gmail, scopeNames } = await cache.getForUser(sub);
        return { gmail, authorizedScopes: scopeNames };
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
