import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import { MemoryRelay, RELAY_TTL_SEC } from './relay.js';
import { FirestoreRelay } from './firestore-relay.js';
import type { HttpConfig } from './config.js';

const config = { encryptionKey: crypto.randomBytes(32) } as unknown as HttpConfig;

/** Enough of Firestore to exercise the relay: docs, snapshots, transactions. */
function fakeFirestore() {
    const docs = new Map<string, any>();
    const listeners = new Map<string, Set<(snap: any) => void>>();
    /** Everything ever written through a transaction, for at-rest assertions. */
    const writes: Array<{ key: string; patch: any }> = [];

    const snapOf = (key: string) => ({ exists: docs.has(key), data: () => docs.get(key) });
    const notify = (key: string) => {
        for (const listener of listeners.get(key) ?? []) listener(snapOf(key));
    };
    const ref = (key: string) => ({
        _key: key,
        async set(data: any) {
            docs.set(key, { ...data });
            notify(key);
        },
        async delete() {
            docs.delete(key);
            notify(key);
        },
        onSnapshot(onNext: (snap: any) => void) {
            const set = listeners.get(key) ?? new Set();
            listeners.set(key, set);
            set.add(onNext);
            queueMicrotask(() => onNext(snapOf(key)));
            return () => set.delete(onNext);
        },
    });

    const db = {
        collection: (name: string) => ({ doc: (id: string) => ref(`${name}/${id}`) }),
        async runTransaction(fn: (tx: any) => Promise<any>) {
            const touched = new Set<string>();
            const tx = {
                async get(r: any) {
                    return snapOf(r._key);
                },
                update(r: any, patch: any) {
                    writes.push({ key: r._key, patch });
                    docs.set(r._key, { ...docs.get(r._key), ...patch });
                    touched.add(r._key);
                },
            };
            const out = await fn(tx);
            for (const key of touched) notify(key);
            return out;
        },
    };

    return { db: db as any, docs, writes };
}

/** Resolves with whatever the relay hands back, or null if nothing arrives. */
function answerWaiter() {
    let resolve!: (value: unknown) => void;
    const received = new Promise<unknown>((r) => (resolve = r));
    return { onAnswer: (message: unknown) => resolve(message), received };
}

describe('MemoryRelay', () => {
    it('hands an answer to the waiter', async () => {
        const relay = new MemoryRelay();
        const waiter = answerWaiter();
        await relay.register('srv-1', 'p1', waiter.onAnswer);

        expect(await relay.publish('srv-1', 'p1', { result: { action: 'accept' } })).toBe(true);
        expect(await waiter.received).toEqual({ result: { action: 'accept' } });
        expect(relay.size).toBe(0);
    });

    it('refuses an answer from another principal', async () => {
        const relay = new MemoryRelay();
        const waiter = answerWaiter();
        await relay.register('srv-1', 'p1', waiter.onAnswer);

        expect(await relay.publish('srv-1', 'p2', { result: {} })).toBe(false);
        // Still claimable by the principal that was actually asked.
        expect(await relay.publish('srv-1', 'p1', { result: {} })).toBe(true);
    });

    it('accepts an answer only once, and only for a known token', async () => {
        const relay = new MemoryRelay();
        await relay.register('srv-1', 'p1', () => {});

        expect(await relay.publish('srv-1', 'p1', { result: {} })).toBe(true);
        expect(await relay.publish('srv-1', 'p1', { result: {} })).toBe(false);
        expect(await relay.publish('srv-never-asked', 'p1', { result: {} })).toBe(false);
    });

    it('drops a claim once withdrawn', async () => {
        const relay = new MemoryRelay();
        const withdraw = await relay.register('srv-1', 'p1', () => {});
        withdraw();
        expect(await relay.publish('srv-1', 'p1', { result: {} })).toBe(false);
    });

    it('expires claims that outlive the window', async () => {
        const relay = new MemoryRelay(-1); // already expired on arrival
        await relay.register('srv-1', 'p1', () => {});

        expect(await relay.publish('srv-1', 'p1', { result: {} })).toBe(false);
        await relay.sweep();
        expect(relay.size).toBe(0);
    });
});

describe('FirestoreRelay', () => {
    it('wakes the waiting instance when another instance publishes', async () => {
        const { db, docs } = fakeFirestore();
        const relay = new FirestoreRelay(config, db);
        const waiter = answerWaiter();
        await relay.register('srv-1', 'p1', waiter.onAnswer);

        // A second instance, sharing only the database.
        const other = new FirestoreRelay(config, db);
        expect(await other.publish('srv-1', 'p1', { result: { action: 'accept' } })).toBe(true);

        expect(await waiter.received).toEqual({ result: { action: 'accept' } });
        // Consumed documents do not linger.
        expect(docs.size).toBe(0);
    });

    it('never writes the answer in the clear', async () => {
        const { db, writes } = fakeFirestore();
        const relay = new FirestoreRelay(config, db);
        await relay.register('srv-1', 'p1', () => {});

        const other = new FirestoreRelay(config, db);
        await other.publish('srv-1', 'p1', { result: { choice: 'always' } });

        expect(writes).toHaveLength(1);
        expect(typeof writes[0].patch.answer).toBe('string');
        expect(JSON.stringify(writes[0].patch)).not.toContain('always');
    });

    it('refuses an answer from another principal', async () => {
        const { db } = fakeFirestore();
        const relay = new FirestoreRelay(config, db);
        await relay.register('srv-1', 'p1', () => {});

        expect(await relay.publish('srv-1', 'p2', { result: {} })).toBe(false);
    });

    it('accepts an answer only once, and only for a known token', async () => {
        const { db } = fakeFirestore();
        const relay = new FirestoreRelay(config, db);
        await relay.register('srv-1', 'p1', () => {});

        expect(await relay.publish('srv-1', 'p1', { result: {} })).toBe(true);
        expect(await relay.publish('srv-1', 'p1', { result: {} })).toBe(false);
        expect(await relay.publish('srv-never-asked', 'p1', { result: {} })).toBe(false);
    });

    it('drops the claim and the document once withdrawn', async () => {
        const { db, docs } = fakeFirestore();
        const relay = new FirestoreRelay(config, db);
        const withdraw = await relay.register('srv-1', 'p1', () => {});

        expect(docs.size).toBe(1);
        withdraw();
        // delete() is fire-and-forget; let it land.
        await new Promise((r) => setTimeout(r, 0));

        expect(docs.size).toBe(0);
        expect(await relay.publish('srv-1', 'p1', { result: {} })).toBe(false);
    });

    it('refuses an answer to a claim older than the window', async () => {
        const { db, docs } = fakeFirestore();
        const relay = new FirestoreRelay(config, db);
        await relay.register('srv-1', 'p1', () => {});

        const key = 'mcp_client_requests/srv-1';
        docs.set(key, { ...docs.get(key), createdAtSec: docs.get(key).createdAtSec - RELAY_TTL_SEC - 1 });

        expect(await relay.publish('srv-1', 'p1', { result: {} })).toBe(false);
    });
});
