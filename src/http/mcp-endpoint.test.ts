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
import { MemoryRelay, type ClientRequestRelay } from './relay.js';
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

/** One server instance of the endpoint, optionally sharing a relay with others. */
async function startInstance(relay?: ClientRequestRelay): Promise<{ server: http.Server; port: number }> {
    const app = express();
    // Stand in for requireBearerAuth: the endpoint only needs the principal.
    app.use((req, _res, next) => {
        (req as any).auth = { token: 't', clientId: 'c', scopes: ['gmail'], extra: { principalId: 'principal-1' } };
        next();
    });
    const mcp = createStatelessMcpEndpoint(createTestMcpServer, resolveSession, relay);
    app.post('/mcp', express.json(), mcp.post);
    app.get('/mcp', mcp.methodNotAllowed);
    app.delete('/mcp', mcp.methodNotAllowed);

    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    return { server, port: (server.address() as AddressInfo).port };
}

const stop = (server: http.Server) => new Promise<void>((resolve) => server.close(() => resolve()));

let server: http.Server;
let url: URL;

beforeAll(async () => {
    const instance = await startInstance();
    server = instance.server;
    url = new URL(`http://127.0.0.1:${instance.port}/mcp`);
});

afterAll(async () => {
    await stop(server);
});

async function connect(elicitAnswer?: { action: string; content?: unknown }, at: URL = url) {
    const client = new Client(
        { name: 'test-client', version: '0.0.0' },
        { capabilities: elicitAnswer ? { elicitation: {} } : {} },
    );
    if (elicitAnswer) {
        client.setRequestHandler(ElicitRequestSchema, async () => elicitAnswer as any);
    }
    const transport = new StreamableHTTPClientTransport(at);
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

/**
 * A deliberately hostile load balancer: calls go to one instance, and every
 * JSON-RPC answer goes to the other. This is the worst case a deploy without
 * session affinity can produce, so if elicitation survives here it survives
 * anywhere.
 */
function crossRoutingBalancer(callPort: number, answerPort: number): http.Server {
    return http.createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on('data', (c) => chunks.push(c));
        req.on('end', () => {
            const body = Buffer.concat(chunks);
            let isAnswer = false;
            try {
                const parsed = JSON.parse(body.toString() || '{}');
                isAnswer = !!parsed && !parsed.method && ('result' in parsed || 'error' in parsed);
            } catch {
                // Not JSON: treat as a call.
            }
            const port = isAnswer ? answerPort : callPort;
            const headers = { ...req.headers, host: `127.0.0.1:${port}`, 'content-length': String(body.length) };
            const upstream = http.request(
                { host: '127.0.0.1', port, path: req.url, method: req.method, headers },
                (ures) => {
                    res.writeHead(ures.statusCode ?? 502, ures.headers);
                    ures.pipe(res);
                },
            );
            upstream.on('error', () => {
                if (!res.headersSent) res.writeHead(502);
                res.end();
            });
            upstream.end(body);
        });
    });
}

describe('stateless MCP endpoint across instances', () => {
    let a: { server: http.Server; port: number };
    let b: { server: http.Server; port: number };
    let balancer: http.Server;
    let balancedUrl: URL;

    beforeAll(async () => {
        // The relay is the only thing the two instances share, exactly as
        // Firestore would be in a real deploy.
        const relay = new MemoryRelay();
        a = await startInstance(relay);
        b = await startInstance(relay);

        balancer = crossRoutingBalancer(a.port, b.port);
        await new Promise<void>((resolve) => balancer.listen(0, '127.0.0.1', resolve));
        balancedUrl = new URL(`http://127.0.0.1:${(balancer.address() as AddressInfo).port}/mcp`);
    });

    afterAll(async () => {
        await Promise.all([stop(balancer), stop(a.server), stop(b.server)]);
    });

    it('completes an elicitation answered by the instance that never asked', async () => {
        const { client } = await connect({ action: 'accept', content: { choice: 'yes' } }, balancedUrl);
        const result = await client.callTool({ name: 'confirm', arguments: {} });
        expect((result.content as any)[0].text).toBe('accept:yes');
        await client.close();
    });

    it('carries a decline across instances too', async () => {
        const { client } = await connect({ action: 'decline' }, balancedUrl);
        const result = await client.callTool({ name: 'confirm', arguments: {} });
        expect((result.content as any)[0].text).toBe('decline:');
        await client.close();
    });

    it('keeps two concurrent cross-instance elicitations apart', async () => {
        const yes = await connect({ action: 'accept', content: { choice: 'yes' } }, balancedUrl);
        const no = await connect({ action: 'accept', content: { choice: 'no' } }, balancedUrl);

        const [first, second] = await Promise.all([
            yes.client.callTool({ name: 'confirm', arguments: {} }),
            no.client.callTool({ name: 'confirm', arguments: {} }),
        ]);
        expect((first.content as any)[0].text).toBe('accept:yes');
        expect((second.content as any)[0].text).toBe('accept:no');

        await yes.client.close();
        await no.client.close();
    });

    it('still serves ordinary calls whichever instance takes them', async () => {
        const { client } = await connect(undefined, balancedUrl);
        const result = await client.callTool({ name: 'ping', arguments: {} });
        expect((result.content as any)[0].text).toBe('pong');
        await client.close();
    });
});
