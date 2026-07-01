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
import { rejectedAllowlistEntry } from '../send-policy.js';
import type { PrincipalSession, Account, ResolveSession, SendPolicy } from '../session.js';

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

            // `state` is always a one-time link ticket. It carries:
            //  - a principalId  → link this account to that existing principal
            //    (the manage-page "Add account" or the in-chat link tool);
            //    none → this is the sign-in that ESTABLISHES the principal for
            //    the authRequest (bound to it, never to an ambient cookie).
            //  - an authRequestId → started from the manage/setup screen; bind +
            //    return there. Otherwise (in-chat link) → show a success page.
            const ticket = await provider.consumeLinkTicket(state);
            if (!ticket) {
                res.status(400).send('This sign-in link has expired. Please reconnect from your client.');
                return;
            }

            if (ticket.principalId) {
                // Adding/linking an account to an already-established principal.
                await provider.linkGoogleAccount(ticket.principalId, identity);
                if (ticket.authRequestId) {
                    res.redirect(`${config.baseUrl}/manage?req=${encodeURIComponent(ticket.authRequestId)}`);
                    return;
                }
                res.status(200).send(linkedAccountPage(identity.email));
                return;
            }

            // First sign-in for this authorize request: find/create the principal
            // for whoever actually logged in, and bind it to THIS request. This is
            // what makes different claude.ai accounts (same browser) land on their
            // own principal instead of an ambient session.
            const principalId = await provider.ensurePrincipal(identity);
            if (ticket.authRequestId) {
                await store.setAuthRequestPrincipal(ticket.authRequestId, principalId);
                res.redirect(`${config.baseUrl}/manage?req=${encodeURIComponent(ticket.authRequestId)}`);
                return;
            }
            res.status(200).send(linkedAccountPage(identity.email));
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

    // --- Account management surface (shown during (re)connect) -------------
    const form = express.urlencoded({ extended: false });

    // The principal is read from the authorize request itself (bound by the
    // in-flow Google login), NOT from an ambient browser cookie. Possession of
    // the high-entropy, short-lived reqId is the capability for that flow.
    const reqPrincipal = async (reqId: string | undefined): Promise<string | undefined> => {
        if (!reqId) return undefined;
        const ar = await store.getAuthRequest(reqId, config.authRequestTtlSec);
        return ar?.principalId;
    };

    // Setup/manage page: shown on EVERY connect. Lists linked accounts with per-
    // account send settings, Add / Remove, and Continue (the only thing that
    // completes the OAuth link back to the agent). With no session yet (first
    // connect), it kicks off a Google sign-in bound to this request.
    app.get('/manage', async (req: Request, res: Response) => {
        const reqId = req.query.req as string | undefined;
        if (!reqId || !(await store.getAuthRequest(reqId, config.authRequestTtlSec))) {
            res.status(400).send('This authorization request has expired. Please reconnect from your client.');
            return;
        }
        const principalId = await reqPrincipal(reqId);
        if (!principalId) {
            // No session — identify the user with Google first, then return here.
            const ticket = await provider.createLinkTicket(undefined, reqId);
            res.redirect(buildGoogleAuthUrl(config, ticket, true));
            return;
        }
        res.status(200).send(managePage(reqId, await listPrincipalAccounts(store, principalId)));
    });

    // Add account: start a Google sign-in (account chooser) bound to this request.
    app.get('/manage/add', async (req: Request, res: Response) => {
        const reqId = req.query.req as string | undefined;
        const principalId = await reqPrincipal(reqId);
        if (!reqId || !principalId) {
            res.status(400).send('Invalid request. Please reconnect from your client.');
            return;
        }
        const ticket = await provider.createLinkTicket(principalId, reqId);
        res.redirect(buildGoogleAuthUrl(config, ticket, true));
    });

    // Remove a linked account (cannot remove the primary).
    app.post('/manage/remove', form, async (req: Request, res: Response) => {
        const reqId = req.body?.req as string | undefined;
        const sub = req.body?.sub as string | undefined;
        const principalId = await reqPrincipal(reqId);
        if (!reqId || !sub || !principalId) {
            res.status(400).send('Invalid request.');
            return;
        }
        const principal = await store.getPrincipal(principalId);
        if (principal && sub !== principal.primarySub && principal.accountSubs.includes(sub)) {
            await store.removeAccountFromPrincipal(principalId, sub);
            await store.deleteGoogleUser(sub);
            cache.evict(sub);
        }
        res.redirect(`/manage?req=${encodeURIComponent(reqId)}`);
    });

    // Save a per-account send policy (allowlist + dangerous blanket toggle).
    app.post('/manage/account-settings', form, async (req: Request, res: Response) => {
        const reqId = req.body?.req as string | undefined;
        const sub = req.body?.sub as string | undefined;
        const principalId = await reqPrincipal(reqId);
        if (!reqId || !sub || !principalId) {
            res.status(400).send('Invalid request.');
            return;
        }
        const principal = await store.getPrincipal(principalId);
        if (principal && principal.accountSubs.includes(sub)) {
            const allowlist = String(req.body?.allowlist || '')
                .split(/[\s,;]+/)
                .map((s) => s.trim().toLowerCase())
                .filter((s) => s.length > 0)
                // Drop forbidden domain-level entries (public email providers).
                .filter((s) => !rejectedAllowlistEntry(s));
            const dangerouslyAllowAll = req.body?.dangerous === 'on' || req.body?.dangerous === 'true';
            await store.setSendPolicy(sub, { allowlist, dangerouslyAllowAll });
            cache.evict(sub); // pick up the new policy on next use
        }
        res.redirect(`/manage?req=${encodeURIComponent(reqId)}`);
    });

    // Continue: finish the connection — issue our auth code back to the client.
    app.post('/manage/continue', form, async (req: Request, res: Response) => {
        const reqId = req.body?.req as string | undefined;
        const principalId = await reqPrincipal(reqId);
        if (!reqId || !principalId) {
            res.status(400).send('Invalid request. Please reconnect from your client.');
            return;
        }
        try {
            const { redirectUri, code, state } = await provider.finalizeAuthorization(reqId, principalId);
            const dest = new URL(redirectUri);
            dest.searchParams.set('code', code);
            if (state) dest.searchParams.set('state', state);
            res.redirect(dest.toString());
        } catch (err: any) {
            res.status(400).send('Could not complete the connection. Please reconnect from your client.');
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


interface ManageAccount {
    sub: string;
    email: string;
    primary: boolean;
    sendPolicy?: SendPolicy;
}

/** Lightweight account list for the manage page (no Gmail clients built). */
async function listPrincipalAccounts(
    store: OAuthStore,
    principalId: string,
): Promise<ManageAccount[]> {
    const principal = await store.getPrincipal(principalId);
    if (!principal) return [];
    const out: ManageAccount[] = [];
    for (const sub of principal.accountSubs) {
        const user = await store.getGoogleUser(sub);
        out.push({
            sub,
            email: user?.email || sub,
            primary: sub === principal.primarySub,
            sendPolicy: user?.sendPolicy,
        });
    }
    return out;
}

function accountCard(reqId: string, a: ManageAccount): string {
    const r = escapeHtml(reqId);
    const policy = a.sendPolicy || { allowlist: [], dangerouslyAllowAll: false };
    const allowText = escapeHtml((policy.allowlist || []).join('\n'));
    const dangerChecked = policy.dangerouslyAllowAll ? 'checked' : '';
    const removeBtn = a.primary
        ? '<span style="color:#999;font-size:.85rem">primary</span>'
        : `<form method="post" action="/manage/remove" style="margin:0">
<input type="hidden" name="req" value="${r}"><input type="hidden" name="sub" value="${escapeHtml(a.sub)}">
<button type="submit" style="color:#b00;background:none;border:1px solid #b00;border-radius:6px;padding:.2rem .6rem;cursor:pointer">Remove account</button></form>`;
    return `<div style="border:1px solid #e3e3e3;border-radius:10px;padding:1rem;margin:.8rem 0">
<div style="display:flex;justify-content:space-between;align-items:center;gap:1rem">
<strong>${escapeHtml(a.email)}</strong>${removeBtn}</div>
<form method="post" action="/manage/account-settings" style="margin-top:.8rem">
<input type="hidden" name="req" value="${r}"><input type="hidden" name="sub" value="${escapeHtml(a.sub)}">
<label style="display:block;font-size:.9rem;color:#444;margin-bottom:.3rem">Sending — replies to <b>${escapeHtml(a.email)}</b> itself are always allowed. Allow other recipients by email or domain (one per line, e.g. <code>boss@acme.com</code> or <code>acme.com</code>):</label>
<textarea name="allowlist" rows="3" style="width:100%;box-sizing:border-box;font-family:monospace;font-size:.85rem;padding:.4rem" placeholder="acme.com&#10;someone@partner.com">${allowText}</textarea>
<label style="display:flex;align-items:center;gap:.5rem;margin:.6rem 0;color:#b00;font-size:.9rem">
<input type="checkbox" name="dangerous" ${dangerChecked}> Dangerously allow sending to <b>anyone</b> (overrides the list above)</label>
<button type="submit" style="background:#f1f3f4;border:1px solid #ccc;border-radius:6px;padding:.4rem .9rem;cursor:pointer">Save send settings</button>
</form>
</div>`;
}

function managePage(reqId: string, accounts: ManageAccount[]): string {
    const r = escapeHtml(reqId);
    const cards = accounts.map((a) => accountCard(reqId, a)).join('');
    return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Set up Gmail connection</title></head>
<body style="font-family:system-ui;max-width:36rem;margin:2.5rem auto;padding:0 1rem;color:#202124">
<h2>Set up your Gmail connection</h2>
<p style="color:#555">Your assistant works across every mailbox you link here. Set how each account is allowed to send, then click <b>Continue</b> to finish connecting.</p>
${cards}
<p><a href="/manage/add?req=${r}" style="display:inline-block;margin:.5rem 0;padding:.5rem 1rem;border:1px solid #1a73e8;color:#1a73e8;border-radius:8px;text-decoration:none">+ Add another account</a></p>
<form method="post" action="/manage/continue" style="margin-top:1.5rem;border-top:1px solid #eee;padding-top:1.2rem">
<input type="hidden" name="req" value="${r}">
<button type="submit" style="background:#1a73e8;color:#fff;border:none;border-radius:8px;padding:.7rem 1.6rem;font-size:1rem;cursor:pointer">Continue</button>
<p style="color:#777;font-size:.8rem;margin-top:.6rem">Continue completes the connection and returns you to your assistant.</p>
</form>
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
            accounts.push({
                sub,
                email: user.email,
                primary: isPrimary,
                scopeNames,
                sendPolicy: user.sendPolicy,
            });
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
        setSendPolicy: async (sub: string, policy: SendPolicy) => {
            await store.setSendPolicy(sub, policy);
            cache.evict(sub); // rebuild with the new policy next request
        },
    };
}
