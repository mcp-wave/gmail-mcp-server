import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import type { Express } from 'express';
import { createMcpServer } from '../index.js';
import { createHttpApp } from './server.js';
import { FileOAuthStore } from './store.js';
import { GmailOAuthProvider } from './provider.js';
import { GmailClientCache } from './google.js';
import { MemoryRelay } from './relay.js';
import type { HttpConfig } from './config.js';
import type { PrincipalSession } from '../session.js';

const MAX_MCP_JSON_BYTES = 32 * 1024 * 1024;
const BEARER = 'attachment-boundary-bearer';

type FakeGmail = {
    users: {
        messages: { send: (request: { requestBody: { raw: string } }) => Promise<{ data: { id: string } }> };
    };
};

type FakeGmailState = {
    rawMessages: string[];
    client: FakeGmail;
};

function fakeGmail(): FakeGmailState {
    const rawMessages: string[] = [];
    return {
        rawMessages,
        client: {
            users: {
                messages: {
                    send: ({ requestBody }) => {
                        rawMessages.push(requestBody.raw);
                        return Promise.resolve({ data: { id: `fake-${rawMessages.length}` } });
                    },
                },
            },
        },
    };
}

function makeConfig(directory: string): HttpConfig {
    const baseUrl = 'http://127.0.0.1';
    return {
        baseUrl,
        issuerUrl: new URL(baseUrl),
        resourceUrl: `${baseUrl}/mcp`,
        googleCallbackUrl: `${baseUrl}/oauth2/google/callback`,
        port: 0,
        googleKeys: { clientId: 'fake-client', clientSecret: 'fake-secret' },
        googleScopeNames: ['gmail.modify'],
        googleScopeUrls: ['https://www.googleapis.com/auth/gmail.modify'],
        mcpScope: 'gmail',
        storeBackend: 'file',
        firestoreDatabaseId: '(default)',
        configDir: directory,
        encryptionKey: crypto.randomBytes(32),
        allowedOrigins: [],
        accessTokenTtlSec: 3600,
        authCodeTtlSec: 60,
        pendingAuthTtlSec: 600,
        authRequestTtlSec: 600,
    };
}

function makeHostedSession(state: FakeGmailState): PrincipalSession {
    return {
        principalId: 'test-principal',
        accounts: [{ sub: 'test-sub', email: 'user@example.com', primary: true, scopeNames: ['gmail.modify'] }],
        localFileAccess: false,
        getClient: () => ({ gmail: state.client, authorizedScopes: ['gmail.modify'] }),
    };
}

function decodeRaw(raw: string): string {
    return Buffer.from(raw.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

function jsonRpcBody(content: string): string {
    return JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
            name: 'not_a_tool',
            arguments: { content },
        },
    });
}

async function listen(app: Express): Promise<{ server: http.Server; baseUrl: string }> {
    const server = app.listen(0);
    await new Promise<void>((resolve) => server.once('listening', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Loopback server did not expose a TCP address.');
    const { port } = address;
    return { server, baseUrl: `http://127.0.0.1:${port}` };
}

async function stop(server: http.Server): Promise<void> {
    await new Promise<void>((resolve, reject) => {
        server.close(error => error ? reject(error) : resolve());
    });
}

describe('hosted MCP attachment boundary over HTTP', () => {
    let directory: string;
    let server: http.Server;
    let baseUrl: string;
    let state: FakeGmailState;

    beforeEach(async () => {
        directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gmail-mcp-http-attachment-'));
        const config = makeConfig(directory);
        const store = new FileOAuthStore(directory, config.encryptionKey);
        const provider = new GmailOAuthProvider(config, store);
        await store.putAccessToken(BEARER, {
            clientId: 'test-client',
            principalId: 'test-principal',
            mcpScope: 'gmail',
            resource: config.resourceUrl,
            familyId: 'test-family',
            expiresAtSec: Math.floor(Date.now() / 1000) + 3600,
        });
        state = fakeGmail();
        const app = createHttpApp(
            config,
            store,
            new MemoryRelay(),
            provider,
            new GmailClientCache(config, store),
            createMcpServer,
            async () => makeHostedSession(state),
        );
        ({ server, baseUrl } = await listen(app));
    });

    afterEach(async () => {
        await stop(server);
        fs.rmSync(directory, { recursive: true, force: true });
    });

    it('delivers a 128 KiB inline document through the real authenticated HTTP endpoint', async () => {
        const document = Buffer.alloc(128 * 1024, 0x61);
        const response = await fetch(`${baseUrl}/mcp`, {
            method: 'POST',
            headers: {
                authorization: `Bearer ${BEARER}`,
                'content-type': 'application/json',
                accept: 'application/json, text/event-stream',
            },
            body: JSON.stringify({
                jsonrpc: '2.0',
                id: 1,
                method: 'tools/call',
                params: {
                    name: 'send_email',
                    arguments: {
                        to: ['user@example.com'],
                        subject: 'document',
                        body: 'attached',
                        includeSignature: false,
                        attachments: [{ filename: 'document.bin', content: document.toString('base64') }],
                    },
                },
            }),
        });

        expect(response.status).toBe(200);
        expect(state.rawMessages).toHaveLength(1);
        expect(decodeRaw(state.rawMessages[0]).replace(/\s/g, '')).toContain(document.toString('base64'));
    });

    it('rejects a filesystem attachment over HTTP before the fake Gmail client is used', async () => {
        const response = await fetch(`${baseUrl}/mcp`, {
            method: 'POST',
            headers: {
                authorization: `Bearer ${BEARER}`,
                'content-type': 'application/json',
                accept: 'application/json, text/event-stream',
            },
            body: JSON.stringify({
                jsonrpc: '2.0',
                id: 1,
                method: 'tools/call',
                params: {
                    name: 'send_email',
                    arguments: {
                        to: ['user@example.com'],
                        subject: 'document',
                        body: 'attached',
                        attachments: ['/private/canary.txt'],
                    },
                },
            }),
        });

        expect(response.status).toBe(200);
        expect(await response.text()).toMatch(/inline/i);
        expect(state.rawMessages).toEqual([]);
    });

    it('accepts a request below the MCP JSON limit and rejects one byte above it before execution', async () => {
        const template = jsonRpcBody('');
        const withinContent = 'A'.repeat(MAX_MCP_JSON_BYTES - Buffer.byteLength(template));
        const within = jsonRpcBody(withinContent);
        expect(Buffer.byteLength(within)).toBe(MAX_MCP_JSON_BYTES);
        const withinResponse = await fetch(`${baseUrl}/mcp`, {
            method: 'POST',
            headers: { authorization: `Bearer ${BEARER}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
            body: within,
        });
        expect(withinResponse.status).toBe(200);

        const tooLarge = jsonRpcBody(`${withinContent}A`);
        expect(Buffer.byteLength(tooLarge)).toBe(MAX_MCP_JSON_BYTES + 1);
        const oversizedResponse = await fetch(`${baseUrl}/mcp`, {
            method: 'POST',
            headers: { authorization: `Bearer ${BEARER}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
            body: tooLarge,
        });
        expect(oversizedResponse.status).toBe(413);
        expect(state.rawMessages).toEqual([]);
    });

    it('rejects an unauthenticated oversized request before JSON parsing or Gmail access', async () => {
        const response = await fetch(`${baseUrl}/mcp`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: 'x'.repeat(MAX_MCP_JSON_BYTES + 1),
        });

        expect(response.status).toBe(401);
        expect(state.rawMessages).toEqual([]);
    });
});
