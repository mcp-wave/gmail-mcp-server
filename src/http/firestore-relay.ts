// Firestore-backed ClientRequestRelay: lets the instance that receives an
// elicitation answer wake the instance that asked, so a multi-instance deploy
// needs no session affinity.
//
// One document per in-flight request, named by the request's token:
//
//   { principalId, createdAtSec, expireAt, answer? }
//
// The asking instance writes the document and listens on it. The receiving
// instance writes `answer` inside a transaction, which is what the listener
// fires on. The document is deleted as soon as it is consumed or withdrawn;
// anything left behind by an instance that died is reclaimed by a Firestore TTL
// policy on `expireAt`, and every read re-checks expiry so correctness never
// depends on deletion latency.

import { Firestore, Timestamp, type DocumentData } from '@google-cloud/firestore';
import type { HttpConfig } from './config.js';
import { nowSec } from './store.js';
import { RELAY_TTL_SEC, sealAnswer, openAnswer, type ClientRequestRelay } from './relay.js';

const COLLECTION = 'mcp_client_requests';

export class FirestoreRelay implements ClientRequestRelay {
    private readonly db: Firestore;
    private readonly key: Buffer;

    constructor(config: HttpConfig, db?: Firestore) {
        this.db =
            db ??
            new Firestore({
                projectId: config.gcpProject,
                databaseId: config.firestoreDatabaseId,
                ignoreUndefinedProperties: true,
            });
        this.key = config.encryptionKey;
    }

    async register(
        token: string,
        principalId: string,
        onAnswer: (message: unknown) => void,
    ): Promise<() => void> {
        const ref = this.db.collection(COLLECTION).doc(token);
        // Written before the question goes out, so an answer can never arrive
        // before there is somewhere to put it.
        await ref.set({
            principalId,
            createdAtSec: nowSec(),
            expireAt: Timestamp.fromMillis((nowSec() + RELAY_TTL_SEC) * 1000),
        });

        let settled = false;
        let unsubscribe: (() => void) | undefined;
        const release = () => {
            if (settled) return false;
            settled = true;
            unsubscribe?.();
            void ref.delete().catch(() => {});
            return true;
        };

        unsubscribe = ref.onSnapshot(
            (snap) => {
                if (settled) return;
                const sealed = (snap.data() as DocumentData | undefined)?.answer;
                if (typeof sealed !== 'string') return;
                let message: unknown;
                try {
                    message = openAnswer(this.key, sealed);
                } catch {
                    // Undecryptable payload (wrong key, tampered): drop it and
                    // let the caller's own timeout deal with the silence.
                    release();
                    return;
                }
                release();
                onAnswer(message);
            },
            () => {
                // Listener died. The caller's timeout covers it; do not throw
                // from a background stream.
            },
        );

        return () => {
            release();
        };
    }

    async publish(token: string, principalId: string, message: unknown): Promise<boolean> {
        const ref = this.db.collection(COLLECTION).doc(token);
        return this.db.runTransaction(async (tx) => {
            const snap = await tx.get(ref);
            if (!snap.exists) return false;
            const rec = snap.data() as DocumentData;
            // Only the connection that was asked may answer.
            if (rec.principalId !== principalId) return false;
            // Answer once.
            if (typeof rec.answer === 'string') return false;
            if (nowSec() - rec.createdAtSec > RELAY_TTL_SEC) return false;
            tx.update(ref, { answer: sealAnswer(this.key, message) });
            return true;
        });
    }

    async sweep(): Promise<void> {
        // No-op: consumed documents are deleted by the waiting instance, a
        // Firestore TTL policy on `expireAt` reclaims orphans, and publish
        // re-checks expiry so a stale row is never honored.
    }
}
