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
// Keep a process-local registry of the requests we have sent to a client and who
// is waiting for each answer. Two details make it safe:
//
//   - Ids are rewritten on the way out. Each Server numbers its own requests from
//     zero, so two concurrent tool calls would both send id 0; an unguessable
//     token per outbound request removes the collision. The original id is
//     restored before the answer is handed back, because the SDK matches
//     responses on the id it generated.
//   - Answers are bound to the principal that asked. Only the connection that
//     triggered the elicitation can answer it, so one authenticated caller can
//     never approve another caller's send.
//
// Scope: this is per-process. A single answer must reach the instance holding the
// open stream, which is inherent to server -> client requests over HTTP and is
// unchanged from the session-based transport. Everything else in the endpoint is
// genuinely stateless.

import { randomUUID } from 'crypto';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { JSONRPCMessage, RequestId } from '@modelcontextprotocol/sdk/types.js';

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
}

/**
 * Registry of in-flight server -> client requests, keyed by a token that is
 * unique across every concurrent request this process is handling.
 */
export class ClientRequestBridge {
    private readonly pending = new Map<string, Pending>();

    /** How many answers we are currently waiting on (tests / diagnostics). */
    get size(): number {
        return this.pending.size;
    }

    /**
     * Watch a transport's outbound traffic: every request it sends to the client
     * leaves with a unique token as its id and is registered here.
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
            this.pending.set(token, { principalId, originalId: message.id, transport });
            owned.add(token);
            return send({ ...message, id: token } as JSONRPCMessage, options);
        };

        return () => {
            for (const token of owned) this.pending.delete(token);
            owned.clear();
        };
    }

    /**
     * Hand an incoming POST body to whoever is waiting for it.
     *
     * Returns true when every message in the body was delivered, in which case
     * the caller answers 202 and never builds an MCP server for the request.
     * Returns false for anything else (including a reply we do not own, or one
     * belonging to a different principal) so it takes the normal path.
     */
    deliver(body: unknown, principalId: string): boolean {
        const messages = Array.isArray(body) ? body : [body];
        if (messages.length === 0) return false;

        const matched: Array<{ message: Record<string, unknown>; token: string; pending: Pending }> = [];
        for (const message of messages) {
            if (!isClientReply(message)) return false;
            const token = message.id;
            if (typeof token !== 'string') return false;
            const pending = this.pending.get(token);
            // Not ours, already answered, or another connection's elicitation.
            if (!pending || pending.principalId !== principalId) return false;
            matched.push({ message: message as Record<string, unknown>, token, pending });
        }

        for (const { message, token, pending } of matched) {
            this.pending.delete(token);
            const onmessage = pending.transport.onmessage;
            if (!onmessage) continue;
            onmessage({ ...message, id: pending.originalId } as JSONRPCMessage);
        }
        return true;
    }
}
