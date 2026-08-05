// Routing for server -> client requests on a stateless MCP endpoint.
//
// The problem this solves
// -----------------------
// In stateless Streamable HTTP there is no `Mcp-Session-Id`, so every POST gets
// its own transport and its own MCP Server instance. That is fine for plain
// request/response traffic, but it breaks anything the SERVER asks the CLIENT,
// which for this project means elicitation (the send-policy gate and the
// permanent-delete confirmation).
//
// The exchange looks like this:
//
//   POST #1  tools/call send_email          -> SSE stream stays open
//     (on that stream) elicitation/create id=7
//   POST #2  {"id":7,"result":{...}}        -> a *different* HTTP request
//
// POST #2 lands on a brand new transport + Server whose response table is empty,
// so the answer is dropped and POST #1 hangs until its timeout.
//
// The fix
// -------
// Keep a registry of the requests we have sent to a client and who is waiting
// for each answer. Three details make it work:
//
//   - Ids are rewritten on the way out. Each Server numbers its own requests from
//     zero, so two concurrent tool calls would both send id 0; an unguessable
//     token per outbound request removes the collision. The original id is
//     restored before the answer is handed back, because the SDK matches
//     responses on the id it generated.
//   - Answers are bound to the principal that asked. Only the connection that
//     triggered the elicitation can answer it, so one authenticated caller can
//     never approve another caller's send.
//   - Answers that land on another instance are relayed. POST #2 can be routed
//     anywhere behind a load balancer, so a token nobody here is waiting on is
//     offered to the relay, which wakes whichever instance is. See relay.ts.

import { randomUUID } from 'crypto';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { JSONRPCMessage, RequestId } from '@modelcontextprotocol/sdk/types.js';
import { MemoryRelay, type ClientRequestRelay } from './relay.js';

/** A request we are sending to the client (has both a method and an id). */
function isOutboundRequest(message: unknown): message is JSONRPCMessage & { id: RequestId; method: string } {
    if (typeof message !== 'object' || message === null) return false;
    const m = message as Record<string, unknown>;
    return typeof m.method === 'string' && m.id !== undefined && m.id !== null;
}

/** A reply from the client to one of our requests (an id plus result or error). */
function isClientReply(message: unknown): message is { id: RequestId } & Record<string, unknown> {
    if (typeof message !== 'object' || message === null) return false;
    const m = message as Record<string, unknown>;
    if (m.jsonrpc !== '2.0' || typeof m.method === 'string') return false;
    if (m.id === undefined || m.id === null) return false;
    return 'result' in m || 'error' in m;
}

interface Pending {
    /** The connection that asked, so only it can answer. */
    principalId: string;
    /** The id the SDK generated, which it will match the reply against. */
    originalId: RequestId;
    transport: Transport;
    /** Withdraws the relay's claim on this token. Safe to call more than once. */
    withdraw: () => void;
}

/**
 * Registry of in-flight server -> client requests, keyed by a token that is
 * unique across every concurrent request. Backed by a relay so an answer that
 * arrives at another instance still reaches the one that asked.
 */
export class ClientRequestBridge {
    private readonly pending = new Map<string, Pending>();
    private readonly relay: ClientRequestRelay;

    constructor(relay: ClientRequestRelay = new MemoryRelay()) {
        this.relay = relay;
    }

    /** How many answers this instance is waiting on (tests / diagnostics). */
    get size(): number {
        return this.pending.size;
    }

    /**
     * Watch a transport's outbound traffic: every request it sends to the client
     * leaves with a unique token as its id, is registered here, and is announced
     * on the relay before the question is actually sent.
     *
     * Returns a cleanup function that forgets everything this transport is still
     * waiting on. Call it when the HTTP response closes, so an unanswered
     * elicitation cannot outlive the request that started it.
     */
    track(transport: Transport, principalId: string): () => void {
        const send = transport.send.bind(transport);
        const owned = new Set<string>();

        transport.send = async (message: JSONRPCMessage, options?: Parameters<Transport['send']>[1]) => {
            if (!isOutboundRequest(message)) return send(message, options);
            const token = `srv-${randomUUID()}`;
            const pending: Pending = {
                principalId,
                originalId: message.id,
                transport,
                withdraw: () => {},
            };
            this.pending.set(token, pending);
            // Announce before sending: an answer must never be able to arrive
            // before there is somewhere for it to land. If the relay is having a
            // bad day, carry on without it rather than failing the gate outright,
            // since an answer routed back to this instance still lands.
            try {
                pending.withdraw = await this.relay.register(token, principalId, (answer) =>
                    this.deliverLocal(token, answer),
                );
            } catch (err: any) {
                console.error('Client request relay unavailable:', err?.message || err);
            }
            owned.add(token);
            return send({ ...message, id: token } as JSONRPCMessage, options);
        };

        return () => {
            for (const token of owned) {
                this.pending.get(token)?.withdraw();
                this.pending.delete(token);
            }
            owned.clear();
        };
    }

    /**
     * Hand an incoming POST body to whoever is waiting for it, here or on
     * another instance.
     *
     * Returns true when every message in the body was delivered or accepted for
     * relay, in which case the caller answers 202 and never builds an MCP server
     * for the request. Returns false for anything else (ordinary traffic, a
     * token nobody is waiting on, or an answer from a different principal) so it
     * takes the normal path.
     */
    async deliver(body: unknown, principalId: string): Promise<boolean> {
        const messages = Array.isArray(body) ? body : [body];
        if (messages.length === 0) return false;

        // Every message has to be an answer, or this is ordinary traffic.
        const replies: Array<{ token: string; message: Record<string, unknown> }> = [];
        for (const message of messages) {
            if (!isClientReply(message)) return false;
            const token = message.id;
            if (typeof token !== 'string' || !token.startsWith('srv-')) return false;
            replies.push({ token, message: message as Record<string, unknown> });
        }

        // Anything we are waiting on here is settled without touching the relay.
        // That is the common case: same instance, or a load balancer with
        // affinity. Only genuinely misrouted answers pay for the round trip.
        const results = await Promise.all(
            replies.map(async ({ token, message }) => {
                const pending = this.pending.get(token);
                if (pending) {
                    if (pending.principalId !== principalId) return false;
                    return this.deliverLocal(token, message);
                }
                try {
                    return await this.relay.publish(token, principalId, message);
                } catch (err: any) {
                    console.error('Client request relay unavailable:', err?.message || err);
                    return false;
                }
            }),
        );
        return results.every(Boolean);
    }

    /** Deliver an answer into the transport that is waiting for it, once. */
    private deliverLocal(token: string, message: unknown): boolean {
        const pending = this.pending.get(token);
        if (!pending) return false;
        this.pending.delete(token);
        // Drop the relay's claim too, so a replayed answer finds nothing anywhere.
        pending.withdraw();
        const onmessage = pending.transport.onmessage;
        if (!onmessage) return false;
        onmessage({ ...(message as Record<string, unknown>), id: pending.originalId } as JSONRPCMessage);
        return true;
    }
}
