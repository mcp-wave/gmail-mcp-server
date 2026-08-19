/**
 * Draft edit safety for Gmail MCP Server
 *
 * `drafts.update` is documented as "Replaces a draft's content". The whole
 * message is rebuilt from whatever the caller supplies, so anything the caller
 * omits is destroyed -- including edits the human made in the Gmail UI between
 * the agent drafting the message and the agent revising it.
 *
 * This module makes that impossible:
 *
 * 1. An edit must carry a `baseToken` obtained from reading the draft. No token
 *    means the caller never looked at the draft, and the edit is refused.
 * 2. The live draft is re-read at edit time and its token compared. A mismatch
 *    means the draft changed after the caller read it, so the edit is refused
 *    and the current content handed back for the caller to fold in.
 * 3. Fields the caller does not supply are preserved from the live draft rather
 *    than dropped.
 *
 * The token is `messageId:historyId`. Two fields, because the docs pin down
 * only some of the behaviour: `Message.historyId` is "The ID of the last
 * history record that modified this message", and `Message.id` is immutable for
 * a given message but a draft edit may swap the message out entirely. Comparing
 * both is correct whether an edit mutates the message in place or replaces it,
 * so the guard does not depend on resolving which one Gmail does.
 *
 * Attachments are the one thing that cannot be preserved: they live in Gmail,
 * and rebuilding the MIME body requires local file paths this server no longer
 * has. Rather than silently dropping them, an edit to a draft with attachments
 * is refused unless the caller re-supplies them or explicitly drops them.
 */

import type { gmail_v1 } from 'googleapis';
import { parseEmailAddresses } from './email-export.js';

/** Thrown when an edit would overwrite content the caller has not seen. */
export class StaleDraftError extends Error {
    readonly currentSnapshot: DraftSnapshot;

    constructor(message: string, currentSnapshot: DraftSnapshot) {
        super(message);
        this.name = 'StaleDraftError';
        this.currentSnapshot = currentSnapshot;
    }
}

export interface DraftAttachment {
    filename: string;
    mimeType: string;
    size: number;
}

/** The live state of a draft, as read immediately before an edit. */
export interface DraftSnapshot {
    draftId: string;
    messageId: string;
    historyId: string;
    /** Opaque staleness token. Callers pass this back as `baseToken`. */
    token: string;
    to: string[];
    cc: string[];
    bcc: string[];
    subject: string;
    text: string;
    html: string;
    attachments: DraftAttachment[];
}

/** Headers already extracted from the draft's payload by the caller. */
export interface ExtractedHeaders {
    subject: string;
    to: string;
    cc: string;
    bcc: string;
}

export interface BuildSnapshotInput {
    draft: gmail_v1.Schema$Draft;
    headers: ExtractedHeaders;
    content: { text: string; html: string };
    attachments: DraftAttachment[];
}

/**
 * Build the opaque staleness token for a draft's current message.
 *
 * An absent component becomes the empty string, which no real Gmail id can be.
 * A sentinel word would collide with a message whose id happened to equal that
 * word, which is the sort of thing that makes a guard quietly stop guarding.
 * The `v1` prefix marks the format so it can change without a stored token from
 * an older shape being mistaken for a current one.
 */
export function draftToken(messageId?: string | null, historyId?: string | null): string {
    return `v1:${messageId ?? ''}:${historyId ?? ''}`;
}

/**
 * Split a recipient header into bare addresses.
 *
 * The message builder validates recipients against a plain `local@domain`
 * pattern, so display names cannot be round-tripped through it. Addresses are
 * what determine delivery, so they are preserved and the display names are not.
 */
export function headerToAddresses(header: string): string[] {
    if (!header || !header.trim()) return [];
    return parseEmailAddresses(header).map(a => a.email).filter(Boolean);
}

export function buildDraftSnapshot(input: BuildSnapshotInput): DraftSnapshot {
    const { draft, headers, content, attachments } = input;
    const message = draft.message ?? {};

    return {
        draftId: draft.id ?? '',
        messageId: message.id ?? '',
        historyId: message.historyId ?? '',
        token: draftToken(message.id, message.historyId),
        to: headerToAddresses(headers.to),
        cc: headerToAddresses(headers.cc),
        bcc: headerToAddresses(headers.bcc),
        subject: headers.subject ?? '',
        text: content.text ?? '',
        html: content.html ?? '',
        attachments,
    };
}

export interface DraftEditArgs {
    to?: string[];
    cc?: string[];
    bcc?: string[];
    subject?: string;
    body?: string;
    htmlBody?: string;
    mimeType?: string;
    from?: string;
    threadId?: string;
    inReplyTo?: string;
    attachments?: string[];
    /** Token from a prior read of this draft. Required. */
    baseToken?: string;
    /** Acknowledge that the draft's existing attachments should be discarded. */
    dropAttachments?: boolean;
}

export interface MergedDraftEdit {
    /** Args for the message builders, with unsupplied fields filled from the live draft. */
    messageArgs: Record<string, unknown>;
    /** Fields taken from the live draft because the caller did not supply them. */
    preserved: string[];
    /** Fields the caller supplied, overwriting whatever the draft held. */
    replaced: string[];
}

/**
 * Refuse an edit that has not demonstrably seen the draft's current content.
 *
 * Called before any merge so a stale or absent token stops the edit rather than
 * producing a message built on content the caller never read.
 */
export function assertFresh(current: DraftSnapshot, baseToken?: string): void {
    if (!baseToken) {
        throw new StaleDraftError(
            `Editing a draft requires the current content. Call read_draft on "${current.draftId}" first, ` +
            `then pass its baseToken back. This exists so an edit cannot discard changes the user made in Gmail.`,
            current,
        );
    }

    if (baseToken !== current.token) {
        throw new StaleDraftError(
            `This draft changed after you read it, so the edit was refused to avoid overwriting those changes. ` +
            `You based the edit on "${baseToken}" but the draft is now at "${current.token}". ` +
            `The draft's current content is included below: fold the user's changes into your edit and retry with the new baseToken.`,
            current,
        );
    }
}

/**
 * Merge an edit over the live draft.
 *
 * Every field the caller omits is carried over from the draft, so a subject-only
 * change keeps the body the user rewrote. Both body representations are carried
 * over together, because dropping one would silently change the message from
 * multipart to single-part.
 */
export function mergeDraftEdit(current: DraftSnapshot, args: DraftEditArgs): MergedDraftEdit {
    const preserved: string[] = [];
    const replaced: string[] = [];

    const take = <T>(field: string, supplied: T | undefined, existing: T): T => {
        if (supplied === undefined) {
            preserved.push(field);
            return existing;
        }
        replaced.push(field);
        return supplied;
    };

    const messageArgs: Record<string, unknown> = {
        to: take('to', args.to, current.to),
        subject: take('subject', args.subject, current.subject),
    };

    const cc = take('cc', args.cc, current.cc);
    if (cc.length > 0) messageArgs.cc = cc;
    const bcc = take('bcc', args.bcc, current.bcc);
    if (bcc.length > 0) messageArgs.bcc = bcc;

    // The body is a pair. Supplying either half replaces the body wholesale;
    // supplying neither carries both halves over unchanged.
    if (args.body === undefined && args.htmlBody === undefined) {
        preserved.push('body');
        messageArgs.body = current.text;
        if (current.html) messageArgs.htmlBody = current.html;
    } else {
        replaced.push('body');
        messageArgs.body = args.body ?? current.text;
        if (args.htmlBody !== undefined) messageArgs.htmlBody = args.htmlBody;
    }

    if (args.mimeType !== undefined) messageArgs.mimeType = args.mimeType;
    if (args.from !== undefined) messageArgs.from = args.from;
    if (args.threadId !== undefined) messageArgs.threadId = args.threadId;
    if (args.inReplyTo !== undefined) messageArgs.inReplyTo = args.inReplyTo;
    if (args.attachments !== undefined) messageArgs.attachments = args.attachments;

    if ((messageArgs.to as string[]).length === 0) {
        throw new Error('The draft would be left with no recipients. Supply "to", or leave it out to keep the draft\'s existing recipients.');
    }

    return { messageArgs, preserved, replaced };
}

/**
 * Refuse an edit that would silently discard the draft's attachments.
 *
 * Gmail holds the attachment bytes; rebuilding the message needs local file
 * paths, which this server does not retain between calls. So an edit either
 * re-supplies them or says out loud that they should go.
 *
 * An empty array is not a re-supply. LLM clients routinely emit `[]` for an
 * omitted optional array, and treating that as "the caller provided the files"
 * would strip the attachments through the very guard meant to prevent it.
 * Removing them always requires saying so.
 */
export function assertAttachmentsSafe(current: DraftSnapshot, args: DraftEditArgs): void {
    if (current.attachments.length === 0) return;
    if (args.dropAttachments) return;
    if (args.attachments !== undefined && args.attachments.length > 0) return;

    const names = current.attachments.map(a => a.filename).join(', ');
    throw new Error(
        `This draft has ${current.attachments.length} attachment(s) (${names}) that an edit cannot preserve: ` +
        `Gmail holds the bytes and rebuilding the message needs local file paths. ` +
        `Re-supply them with "attachments", or pass "dropAttachments": true to remove them deliberately.`,
    );
}

/** One-line summary of what an edit kept and what it overwrote. */
export function describeMerge(merged: MergedDraftEdit): string {
    const parts: string[] = [];
    if (merged.replaced.length > 0) parts.push(`replaced ${merged.replaced.join(', ')}`);
    if (merged.preserved.length > 0) parts.push(`kept the draft's existing ${merged.preserved.join(', ')}`);
    return parts.join('; ') || 'no changes';
}
