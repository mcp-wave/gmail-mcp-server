// Cross-instance delivery for answers to server -> client requests.
//
// A stateless MCP endpoint holds nothing between requests, with one unavoidable
// exception: while the server is waiting on an elicitation, one instance has an
// open response stream and a promise parked on it. The client's answer arrives
// as a separate HTTP request, and behind a load balancer that request can land
// anywhere. The instance that receives it is not the instance that asked.
//
// The relay is the hand-off between them. The asking instance announces the
// token it is waiting on; whichever instance receives the answer publishes it
// against that token; the asking instance is woken and completes the call. With
// this in place the endpoint needs no session affinity at all.
//
// Two implementations, chosen the same way the store is:
//   - MemoryRelay for the file backend (one process, nothing to coordinate).
//   - FirestoreRelay for multi-instance deploys, using a document per in-flight
//     request and a snapshot listener as the wake-up.
//
// Answers are encrypted at rest with the same key as the rest of the store. They
// are the user's own choice rather than a credential, but they are user input on
// a shared backend and there is no reason to leave them in the clear.

import type { HttpConfig } from './config.js';
import { nowSec, encryptSecret, decryptSecret } from './store.js';

/**
 * How long an announced request stays claimable. Comfortably longer than the
 * elicitation window in index.ts, so the relay never expires an answer the
 * caller would still have accepted.
 */
export const RELAY_TTL_SEC = 10 * 60;

export interface ClientRequestRelay {
    /**
     * Announce that this instance is waiting for an answer to `token`, and start
     * listening for one published elsewhere. Resolves once the announcement is
     * visible to other instances, so an answer can never outrun it.
     *
     * Returns a function that stops listening and withdraws the announcement.
     */
    register(
        token: string,
        principalId: string,
        onAnswer: (message: unknown) => void,
    ): Promise<() => void>;

    /**
     * Hand an answer to whichever instance is waiting for it. False when nobody
     * is waiting, when it has already been answered, or when it comes from a
     * different principal than the one that was asked.
     */
    publish(token: string, principalId: string, message: unknown): Promise<boolean>;

    /** Drop announcements left behind by instances that went away. */
    sweep(): Promise<void>;

    /** Release any backend resources (tests). */
    close?(): Promise<void>;
}

/** Single-process relay: the wait and the answer are already in the same heap. */
export class MemoryRelay implements ClientRequestRelay {
    private readonly waiting = new Map<
        string,
        { principalId: string; onAnswer: (message: unknown) => void; expiresAtSec: number }
    >();

    constructor(private readonly ttlSec: number = RELAY_TTL_SEC) {}

    get size(): number {
        return this.waiting.size;
    }

    async register(
        token: string,
        principalId: string,
        onAnswer: (message: unknown) => void,
    ): Promise<() => void> {
        this.waiting.set(token, { principalId, onAnswer, expiresAtSec: nowSec() + this.ttlSec });
        return () => {
            this.waiting.delete(token);
        };
    }

    async publish(token: string, principalId: string, message: unknown): Promise<boolean> {
        const entry = this.waiting.get(token);
        if (!entry) return false;
        if (entry.principalId !== principalId) return false;
        if (nowSec() > entry.expiresAtSec) {
            this.waiting.delete(token);
            return false;
        }
        // Answer once: drop the claim before waking the waiter.
        this.waiting.delete(token);
        entry.onAnswer(message);
        return true;
    }

    async sweep(): Promise<void> {
        const now = nowSec();
        for (const [token, entry] of this.waiting) {
            if (now > entry.expiresAtSec) this.waiting.delete(token);
        }
    }
}

/**
 * Build the relay that matches the configured store backend. Firestore is
 * imported lazily so the file/stdio path never pulls in the client library.
 */
export async function createRelay(config: HttpConfig): Promise<ClientRequestRelay> {
    if (config.storeBackend === 'firestore') {
        const { FirestoreRelay } = await import('./firestore-relay.js');
        return new FirestoreRelay(config);
    }
    return new MemoryRelay();
}

// --- shared payload handling (used by both implementations) ----------------

export function sealAnswer(key: Buffer, message: unknown): string {
    return encryptSecret(key, JSON.stringify(message));
}

export function openAnswer(key: Buffer, sealed: string): unknown {
    return JSON.parse(decryptSecret(key, sealed));
}
