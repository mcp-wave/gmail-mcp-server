import { describe, it, expect, beforeEach } from 'vitest';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import { ClientRequestBridge } from './client-requests.js';
import { MemoryRelay } from './relay.js';

/** Minimal Transport stand-in that records what it sent and what it was handed. */
function fakeTransport() {
    const sent: any[] = [];
    const delivered: any[] = [];
    const transport: Transport = {
        start: async () => {},
        close: async () => {},
        send: async (message: JSONRPCMessage) => {
            sent.push(message);
        },
        onmessage: (message: JSONRPCMessage) => {
            delivered.push(message);
        },
    };
    return { transport, sent, delivered };
}

const reply = (id: unknown, result: unknown = { action: 'accept' }) => ({ jsonrpc: '2.0', id, result });

describe('ClientRequestBridge', () => {
    let bridge: ClientRequestBridge;

    beforeEach(() => {
        bridge = new ClientRequestBridge();
    });

    it('replaces the outbound request id and restores it on the way back', async () => {
        const { transport, sent, delivered } = fakeTransport();
        bridge.track(transport, 'principal-1');

        await transport.send({ jsonrpc: '2.0', id: 0, method: 'elicitation/create', params: {} } as any);

        const token = sent[0].id;
        expect(token).not.toBe(0);
        expect(typeof token).toBe('string');
        expect(bridge.size).toBe(1);

        expect(await bridge.deliver(reply(token), 'principal-1')).toBe(true);
        expect(delivered).toHaveLength(1);
        // The SDK matches responses on the id it generated, so it must come back as 0.
        expect(delivered[0].id).toBe(0);
        expect(delivered[0].result).toEqual({ action: 'accept' });
        expect(bridge.size).toBe(0);
    });

    it('keeps concurrent requests apart even when both use id 0', async () => {
        const a = fakeTransport();
        const b = fakeTransport();
        bridge.track(a.transport, 'principal-1');
        bridge.track(b.transport, 'principal-2');

        // Each MCP Server numbers its own requests from zero.
        await a.transport.send({ jsonrpc: '2.0', id: 0, method: 'elicitation/create' } as any);
        await b.transport.send({ jsonrpc: '2.0', id: 0, method: 'elicitation/create' } as any);

        expect(a.sent[0].id).not.toBe(b.sent[0].id);

        expect(await bridge.deliver(reply(b.sent[0].id, { action: 'decline' }), 'principal-2')).toBe(true);
        expect(a.delivered).toHaveLength(0);
        expect(b.delivered).toHaveLength(1);
        expect(b.delivered[0].result).toEqual({ action: 'decline' });
    });

    it('refuses an answer from a different principal', async () => {
        const { transport, sent, delivered } = fakeTransport();
        bridge.track(transport, 'principal-1');
        await transport.send({ jsonrpc: '2.0', id: 3, method: 'elicitation/create' } as any);

        expect(await bridge.deliver(reply(sent[0].id), 'principal-2')).toBe(false);
        expect(delivered).toHaveLength(0);
        // Still waiting for the real owner.
        expect(bridge.size).toBe(1);
        expect(await bridge.deliver(reply(sent[0].id), 'principal-1')).toBe(true);
    });

    it('answers each request only once', async () => {
        const { transport, sent } = fakeTransport();
        bridge.track(transport, 'p');
        await transport.send({ jsonrpc: '2.0', id: 1, method: 'elicitation/create' } as any);

        expect(await bridge.deliver(reply(sent[0].id), 'p')).toBe(true);
        expect(await bridge.deliver(reply(sent[0].id), 'p')).toBe(false);
    });

    it('routes JSON-RPC error replies too', async () => {
        const { transport, sent, delivered } = fakeTransport();
        bridge.track(transport, 'p');
        await transport.send({ jsonrpc: '2.0', id: 9, method: 'elicitation/create' } as any);

        const errorReply = { jsonrpc: '2.0', id: sent[0].id, error: { code: -32601, message: 'Method not found' } };
        expect(await bridge.deliver(errorReply, 'p')).toBe(true);
        expect(delivered[0]).toEqual({ jsonrpc: '2.0', id: 9, error: { code: -32601, message: 'Method not found' } });
    });

    it('leaves notifications and outbound responses untouched', async () => {
        const { transport, sent } = fakeTransport();
        bridge.track(transport, 'p');

        await transport.send({ jsonrpc: '2.0', method: 'notifications/progress', params: {} } as any);
        await transport.send({ jsonrpc: '2.0', id: 4, result: { ok: true } } as any);

        expect(sent[0]).toEqual({ jsonrpc: '2.0', method: 'notifications/progress', params: {} });
        expect(sent[1]).toEqual({ jsonrpc: '2.0', id: 4, result: { ok: true } });
        expect(bridge.size).toBe(0);
    });

    it('passes through client traffic that is not an answer we are waiting for', async () => {
        expect(await bridge.deliver({ jsonrpc: '2.0', id: 1, method: 'ping' }, 'p')).toBe(false);
        expect(await bridge.deliver(reply('srv-unknown'), 'p')).toBe(false);
        expect(await bridge.deliver(reply(7), 'p')).toBe(false);
        expect(await bridge.deliver([], 'p')).toBe(false);
        expect(await bridge.deliver(undefined, 'p')).toBe(false);
    });

    it('forgets what a closed request was waiting on', async () => {
        const { transport, sent } = fakeTransport();
        const untrack = bridge.track(transport, 'p');
        await transport.send({ jsonrpc: '2.0', id: 0, method: 'elicitation/create' } as any);
        expect(bridge.size).toBe(1);

        untrack();

        expect(bridge.size).toBe(0);
        expect(await bridge.deliver(reply(sent[0].id), 'p')).toBe(false);
    });
});

// Two bridges sharing one relay stand in for two instances behind a load
// balancer: the tool call is served by one, the answer is routed to the other.
describe('ClientRequestBridge across instances', () => {
    let relay: MemoryRelay;
    let instanceA: ClientRequestBridge;
    let instanceB: ClientRequestBridge;

    beforeEach(() => {
        relay = new MemoryRelay();
        instanceA = new ClientRequestBridge(relay);
        instanceB = new ClientRequestBridge(relay);
    });

    it('delivers an answer that lands on the instance which never asked', async () => {
        const { transport, sent, delivered } = fakeTransport();
        instanceA.track(transport, 'principal-1');
        await transport.send({ jsonrpc: '2.0', id: 0, method: 'elicitation/create' } as any);

        // B has no idea this request exists.
        expect(instanceB.size).toBe(0);
        expect(await instanceB.deliver(reply(sent[0].id), 'principal-1')).toBe(true);

        expect(delivered).toHaveLength(1);
        expect(delivered[0].id).toBe(0);
        expect(delivered[0].result).toEqual({ action: 'accept' });
        expect(instanceA.size).toBe(0);
    });

    it('refuses a relayed answer from a different principal', async () => {
        const { transport, sent, delivered } = fakeTransport();
        instanceA.track(transport, 'principal-1');
        await transport.send({ jsonrpc: '2.0', id: 0, method: 'elicitation/create' } as any);

        expect(await instanceB.deliver(reply(sent[0].id), 'principal-2')).toBe(false);
        expect(delivered).toHaveLength(0);
        // Still claimable by the principal that was actually asked.
        expect(await instanceB.deliver(reply(sent[0].id), 'principal-1')).toBe(true);
    });

    it('accepts a relayed answer only once', async () => {
        const { transport, sent } = fakeTransport();
        instanceA.track(transport, 'p');
        await transport.send({ jsonrpc: '2.0', id: 0, method: 'elicitation/create' } as any);

        expect(await instanceB.deliver(reply(sent[0].id), 'p')).toBe(true);
        expect(await instanceB.deliver(reply(sent[0].id), 'p')).toBe(false);
    });

    it('withdraws the relay claim when the answer arrives locally instead', async () => {
        const { transport, sent } = fakeTransport();
        instanceA.track(transport, 'p');
        await transport.send({ jsonrpc: '2.0', id: 0, method: 'elicitation/create' } as any);

        expect(await instanceA.deliver(reply(sent[0].id), 'p')).toBe(true);
        // Nothing left for another instance to claim.
        expect(relay.size).toBe(0);
        expect(await instanceB.deliver(reply(sent[0].id), 'p')).toBe(false);
    });

    it('withdraws the relay claim when the asking request closes', async () => {
        const { transport, sent } = fakeTransport();
        const untrack = instanceA.track(transport, 'p');
        await transport.send({ jsonrpc: '2.0', id: 0, method: 'elicitation/create' } as any);
        expect(relay.size).toBe(1);

        untrack();

        expect(relay.size).toBe(0);
        expect(await instanceB.deliver(reply(sent[0].id), 'p')).toBe(false);
    });
});
