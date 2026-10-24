import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createMcpServer } from './index.js';
import type { PrincipalSession } from './session.js';

const CANARY = 'attachment-boundary-canary';
const SCOPES = ['gmail.modify'];

type FakeGmail = {
    users: {
        messages: {
            send: (request: { requestBody: { raw: string } }) => Promise<{ data: { id: string } }>;
            get: () => Promise<{ data: Record<string, never> }>;
        };
        drafts: {
            create: (request: { requestBody: { message: { raw: string } } }) => Promise<{ data: { id: string } }>;
            get: () => Promise<{ data: Record<string, never> }>;
        };
        threads: { get: () => Promise<{ data: Record<string, never> }> };
    };
};

type FakeGmailState = {
    calls: string[];
    rawMessages: string[];
    client: FakeGmail;
};

function fakeGmail(): FakeGmailState {
    const calls: string[] = [];
    const rawMessages: string[] = [];
    const unexpected = (operation: string) => {
        calls.push(operation);
        return Promise.resolve({ data: {} });
    };
    const record = (operation: string, raw: string) => {
        calls.push(operation);
        rawMessages.push(raw);
        return Promise.resolve({ data: { id: `fake-${rawMessages.length}` } });
    };
    return {
        calls,
        rawMessages,
        client: {
            users: {
                messages: {
                    send: ({ requestBody }) => record('messages.send', requestBody.raw),
                    get: () => unexpected('messages.get'),
                },
                drafts: {
                    create: ({ requestBody }) => record('drafts.create', requestBody.message.raw),
                    get: () => unexpected('drafts.get'),
                },
                threads: { get: () => unexpected('threads.get') },
            },
        },
    };
}

function makeSession(state: FakeGmailState, localFileAccess?: boolean): PrincipalSession {
    return {
        principalId: 'test-principal',
        accounts: [{ sub: 'test-sub', email: 'user@example.com', primary: true, scopeNames: SCOPES }],
        localFileAccess,
        getClient: () => ({ gmail: state.client, authorizedScopes: SCOPES }),
    };
}

async function callTool(session: PrincipalSession, name: string, args: Record<string, unknown>) {
    const server = createMcpServer(() => session);
    const client = new Client({ name: 'attachment-boundary-test', version: '1.0.0' });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    try {
        return await client.callTool({ name, arguments: args });
    } finally {
        await Promise.all([client.close(), server.close()]);
    }
}

async function listTools(session: PrincipalSession) {
    const server = createMcpServer(() => session);
    const client = new Client({ name: 'attachment-boundary-test', version: '1.0.0' });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    try {
        return await client.listTools();
    } finally {
        await Promise.all([client.close(), server.close()]);
    }
}

function rawMessage(raw: string): string {
    return Buffer.from(raw.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

const tempDirectories: string[] = [];

afterEach(() => {
    for (const directory of tempDirectories.splice(0)) {
        fs.rmSync(directory, { recursive: true, force: true });
    }
});

describe('hosted attachment boundary', () => {
    it('denies path, missing, relative, symlink, and mixed attachments for every attachment tool before Gmail access', async () => {
        const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gmail-mcp-attachment-'));
        tempDirectories.push(directory);
        const canaryPath = path.join(directory, 'canary.txt');
        const symlinkPath = path.join(directory, 'canary-link.txt');
        fs.writeFileSync(canaryPath, CANARY);
        fs.symlinkSync(canaryPath, symlinkPath);
        const paths = [canaryPath, path.join(directory, 'missing.txt'), 'relative.txt', symlinkPath];
        const tools: Array<[string, Record<string, unknown>]> = [
            ['send_email', { to: ['user@example.com'], subject: 's', body: 'b' }],
            ['draft_email', { to: ['user@example.com'], subject: 's', body: 'b' }],
            ['update_draft', { draftId: 'draft', baseToken: 'v1:message:history' }],
            ['reply_all', { messageId: 'message', body: 'b' }],
        ];

        for (const [tool, baseArgs] of tools) {
            for (const attachment of [...paths, [canaryPath, { filename: 'safe.txt', content: Buffer.from(CANARY).toString('base64') }]]) {
                const state = fakeGmail();
                const result = await callTool(makeSession(state, false), tool, { ...baseArgs, attachments: Array.isArray(attachment) ? attachment : [attachment] });
                expect(result.isError).toBe(true);
                expect(JSON.stringify(result.content)).toMatch(/inline/i);
                expect(state.rawMessages).toEqual([]);
                expect(state.calls).toEqual([]);
            }
        }
    });

    it('treats absent and false capability identically, even when tool arguments claim local access', async () => {
        for (const localFileAccess of [undefined, false]) {
            const state = fakeGmail();
            const result = await callTool(makeSession(state, localFileAccess), 'send_email', {
                to: ['user@example.com'],
                subject: 's',
                body: 'b',
                localFileAccess: true,
                attachments: ['/private/canary.txt'],
            });
            expect(result.isError).toBe(true);
            expect(state.rawMessages).toEqual([]);
            expect(state.calls).toEqual([]);
        }
    });

    it('permits a local stdio session to attach its own canary file', async () => {
        const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gmail-mcp-attachment-'));
        tempDirectories.push(directory);
        const canaryPath = path.join(directory, 'canary.txt');
        fs.writeFileSync(canaryPath, CANARY);
        const state = fakeGmail();

        const result = await callTool(makeSession(state, true), 'send_email', {
            to: ['user@example.com'], subject: 's', body: 'b', includeSignature: false, attachments: [canaryPath],
        });

        expect(result.isError).not.toBe(true);
        expect(state.rawMessages).toHaveLength(1);
        expect(rawMessage(state.rawMessages[0])).toContain(Buffer.from(CANARY).toString('base64'));
    });

    it('allows inline bytes with a path-shaped filename without reading a path', async () => {
        const state = fakeGmail();
        const result = await callTool(makeSession(state, false), 'send_email', {
            to: ['user@example.com'],
            subject: 's',
            body: 'b',
            includeSignature: false,
            attachments: [{ filename: '/private/canary.txt', content: Buffer.from(CANARY).toString('base64') }],
        });

        expect(result.isError).not.toBe(true);
        expect(state.rawMessages).toHaveLength(1);
        expect(rawMessage(state.rawMessages[0])).toContain(Buffer.from(CANARY).toString('base64'));
    });

    it('keeps interleaved hosted and stdio listings isolated', async () => {
        const state = fakeGmail();
        const hostedBefore = await listTools(makeSession(state, false));
        const local = await listTools(makeSession(state, true));
        const hostedAfter = await listTools(makeSession(state, false));
        const names = ['send_email', 'draft_email', 'update_draft', 'reply_all'];

        for (const name of names) {
            const hostedSchema = JSON.stringify(hostedBefore.tools.find(tool => tool.name === name)?.inputSchema);
            const localSchema = JSON.stringify(local.tools.find(tool => tool.name === name)?.inputSchema);
            const repeatedHostedSchema = JSON.stringify(hostedAfter.tools.find(tool => tool.name === name)?.inputSchema);
            expect(hostedSchema).not.toContain('Absolute path to a file');
            expect(localSchema).toContain('Absolute path to a file');
            expect(repeatedHostedSchema).not.toContain('Absolute path to a file');
        }
    });
});
