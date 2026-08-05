// The MCP endpoint itself: stateless Streamable HTTP (MCP 2025-11-25).
//
// The spec makes sessions optional: a server MAY assign an `Mcp-Session-Id` at
// initialization, and a client only echoes one back if it was given one. We do
// not assign one. Every POST is self-contained: it carries its own bearer token,
// resolves its own principal, gets its own transport and MCP Server, and is torn
// down when the response closes. Nothing about a connection is held between
// requests, so any instance can serve any request and a redeploy does not strand
// connected clients on a session id that no longer exists.
//
// Consequences, all of them spec-sanctioned:
//   - No `Mcp-Session-Id` header on the initialize response.
//   - GET (the standalone notification stream) answers 405. We never send
//     unsolicited notifications, so there is nothing to stream. The spec
//     explicitly allows 405 here.
//   - DELETE answers 405 as well: there is no session to tear down.
//   - Requests the server makes of the client (elicitation) still work, on any
//     instance; see ClientRequestBridge and relay.ts for how the answers find
//     their way home.

import type { RequestHandler, Request, Response } from 'express';
import { randomUUID } from 'crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { ClientRequestBridge } from './client-requests.js';
import type { ClientRequestRelay } from './relay.js';
import type { ResolveSession } from '../session.js';

/** Builds the MCP Server with all tool handlers (implemented in index.ts). */
export type McpServerFactory = (resolve: ResolveSession) => Server;

export interface StatelessMcpEndpoint {
    /** POST /mcp: every JSON-RPC message the client sends. */
    post: RequestHandler;
    /** GET and DELETE /mcp: no stream, no session. */
    methodNotAllowed: RequestHandler;
    /** In-flight server -> client requests (diagnostics / tests). */
    readonly pendingClientRequests: number;
}

/** The caller's identity, or a value that can never match anything else. */
function principalOf(req: Request): string {
    const auth = (req as Request & { auth?: AuthInfo }).auth;
    const principalId = auth?.extra?.principalId;
    return typeof principalId === 'string' && principalId ? principalId : `anon-${randomUUID()}`;
}

function jsonRpcError(res: Response, status: number, code: number, message: string): void {
    res.status(status).json({ jsonrpc: '2.0', error: { code, message }, id: null });
}

export function createStatelessMcpEndpoint(
    createMcpServer: McpServerFactory,
    resolveSession: ResolveSession,
    relay?: ClientRequestRelay,
): StatelessMcpEndpoint {
    const bridge = new ClientRequestBridge(relay);

    const post: RequestHandler = async (req, res) => {
        const principalId = principalOf(req);

        // An answer to something we asked (elicitation) belongs to the request
        // that is still waiting for it, here or on another instance, not to a
        // fresh server.
        if (await bridge.deliver(req.body, principalId)) {
            res.status(202).end();
            return;
        }

        const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
        const server = createMcpServer(resolveSession);
        const untrack = bridge.track(transport, principalId);

        // The response closing is the end of this request's world: drop anything
        // it was waiting on and abort its in-flight handlers.
        res.on('close', () => {
            untrack();
            void server.close().catch(() => {});
        });

        try {
            await server.connect(transport);
            await transport.handleRequest(req, res, req.body);
        } catch (err: any) {
            console.error('MCP request error:', err?.message || err);
            if (!res.headersSent) {
                jsonRpcError(res, 500, -32603, 'Internal server error');
            }
        }
    };

    const methodNotAllowed: RequestHandler = (_req, res) => {
        res.set('Allow', 'POST');
        jsonRpcError(res, 405, -32000, 'This MCP endpoint is stateless: use POST.');
    };

    return {
        post,
        methodNotAllowed,
        get pendingClientRequests() {
            return bridge.size;
        },
    };
}
