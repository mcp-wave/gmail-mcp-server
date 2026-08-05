// End-to-end coverage for the stateless MCP endpoint, driven by the real SDK
// client over a real HTTP server. The point is to prove the things statelessness
// puts at risk: no session id anywhere, every request standing on its own, and
// elicitation still completing across two separate POSTs.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import express from 'express';
import http from 'http';
import type { AddressInfo } from 'net';
import { Server as McpServer } from '@modelcontextprotocol/sdk/server/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {
    CallToolRequestSchema,
    ElicitRequestSchema,
    ElicitResultSchema,
    ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { createStatelessMcpEndpoint } from './mcp-endpoint.js';
import type { PrincipalSession, ResolveSession } from '../session.js';

const SESSION: PrincipalSession = {
    principalId: 'principal-1',
    accounts: [{ sub: 'sub-1', email: 'user@example.com', primary: true, scopeNames: ['gmail.modify'] }],
    getClient: () => ({ gmail: {}, authorizedScopes: ['gmail.modify'] }),
};

const resolveSession: ResolveSession = async () => SESSION;

/**
 * A stand-in for the real Gmail server: one plain tool, and one that asks the
 * user a question mid-call the way the send gate and permanent delete do.
 */
function createTestMcpServer(): McpServer {
    const server = new McpServer({ name: 'test', version: '0.0.0' }, { capabilities: { tools: {} } });

    server.setRequestHandler(ListToolsRequestSchema, async () => ({
        tools: [
            { name: 'ping', description: 'ping', inputSchema: { type: 'object', properties: {} } },
            { name: 'confirm', description: 'asks first', inputSchema: { type: 'object', properties: {} } },
        ],
    }));

    server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
        if (request.params.name === 'ping') {
            return { content: [{ type: 'text', text: 'pong' }] };
        }
        // Same path the real gates use: related to this call, so it rides this
        // call's response stream instead of a standalone one.
        const res = await extra.sendRequest(
            {
                method: 'elicitation/create',
                params: {
                    mode: 'form',
                    message: 'Proceed?',
                    requestedSchema: {
                        type: 'object',
                        properties: { choice: { type: 'string', enum: ['yes', 'no'] } },
                        required: ['choice'],
                    },
                },
            },
            ElicitResultSchema,
            { timeout: 10_000 },
        );
        const choice = (res.content as any)?.choice ?? '';
        return { content: [{ type: 'text', text: `${res.action}:${choice}` }] };
    });

    return server;
}

let server: http.Server;
let url: URL;

beforeAll(async () => {
    const app = express();
    // Stand in for requireBearerAuth: the endpoint only needs the principal.
    app.use((req, _res, next) => {
        (req as any).auth = { token: 't', clientId: 'c', scopes: ['gmail'], extra: { principalId: 'principal-1' } };
        next();
    });
    const mcp = createStatelessMcpEndpoint(createTestMcpServer, resolveSession);
    app.post('/mcp', express.json(), mcp.post);
    app.get('/mcp', mcp.methodNotAllowed);
    app.delete('/mcp', mcp.methodNotAllowed);

    server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    url = new URL(`http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`);
});

afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
});

async function connect(elicitAnswer?: { action: string; content?: unknown }) {
    const client = new Client(
        { name: 'test-client', version: '0.0.0' },
        { capabilities: elicitAnswer ? { elicitation: {} } : {} },
    );
    if (elicitAnswer) {
        client.setRequestHandler(ElicitRequestSchema, async () => elicitAnswer as any);
    }
    const transport = new StreamableHTTPClientTransport(url);
    await client.connect(transport);
    return { client, transport };
}

describe('stateless MCP endpoint', () => {
    it('initializes without handing out a session id', async () => {
        const { client, transport } = await connect();
        expect(transport.sessionId).toBeUndefined();
        await client.close();
    });

    it('serves later requests with no session to point at', async () => {
        const { client } = await connect();
        const tools = await client.listTools();
        expect(tools.tools.map((t) => t.name)).toEqual(['ping', 'confirm']);

        const result = await client.callTool({ name: 'ping', arguments: {} });
        expect((result.content as any)[0].text).toBe('pong');
        await client.close();
    });

    it('does not carry state between two clients', async () => {
        const first = await connect();
        const second = await connect();
        expect(first.transport.sessionId).toBeUndefined();
        expect(second.transport.sessionId).toBeUndefined();

        // Interleaved, on separate connections, with nothing shared server-side.
        const [a, b] = await Promise.all([
            first.client.callTool({ name: 'ping', arguments: {} }),
            second.client.callTool({ name: 'ping', arguments: {} }),
        ]);
        expect((a.content as any)[0].text).toBe('pong');
        expect((b.content as any)[0].text).toBe('pong');
        await first.client.close();
        await second.client.close();
    });

    it('completes an elicitation whose answer arrives on a separate POST', async () => {
        const { client } = await connect({ action: 'accept', content: { choice: 'yes' } });
        const result = await client.callTool({ name: 'confirm', arguments: {} });
        expect((result.content as any)[0].text).toBe('accept:yes');
        await client.close();
    });

    it('carries a declined elicitation back to the waiting tool call', async () => {
        const { client } = await connect({ action: 'decline' });
        const result = await client.callTool({ name: 'confirm', arguments: {} });
        expect((result.content as any)[0].text).toBe('decline:');
        await client.close();
    });

    it('keeps two concurrent elicitations on their own connections', async () => {
        const yes = await connect({ action: 'accept', content: { choice: 'yes' } });
        const no = await connect({ action: 'accept', content: { choice: 'no' } });

        const [a, b] = await Promise.all([
            yes.client.callTool({ name: 'confirm', arguments: {} }),
            no.client.callTool({ name: 'confirm', arguments: {} }),
        ]);
        expect((a.content as any)[0].text).toBe('accept:yes');
        expect((b.content as any)[0].text).toBe('accept:no');

        await yes.client.close();
        await no.client.close();
    });

    it('answers 405 on GET (no standalone notification stream) and DELETE (no session)', async () => {
        for (const method of ['GET', 'DELETE']) {
            const res = await fetch(url, { method, headers: { Accept: 'text/event-stream' } });
            expect(res.status).toBe(405);
            expect(res.headers.get('allow')).toBe('POST');
            const body = await res.json();
            expect(body).toMatchObject({ jsonrpc: '2.0', id: null });
            expect(body.error.message).toContain('stateless');
        }
    });

    it('reports no leaked in-flight requests once everything has closed', async () => {
        const mcp = createStatelessMcpEndpoint(createTestMcpServer, resolveSession);
        expect(mcp.pendingClientRequests).toBe(0);
    });
});
