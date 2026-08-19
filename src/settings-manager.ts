/**
 * Settings Manager for Gmail MCP Server
 *
 * Wraps `users.settings.*` for the mailbox settings an agent is plausibly asked
 * to read or change: the send-as signature, send-as identity fields, and the
 * vacation responder. Reads cover the wider surface, including the forwarding
 * and delegation config that matters for an "is anything siphoning my mail?"
 * audit.
 *
 * Two API shapes drive the design here:
 *
 * 1. `updateVacation` is a PUT over the whole VacationSettings resource, and
 *    `sendAs.patch` is a partial update over a resource whose other fields we
 *    must not disturb. Every write below therefore reads current state, merges
 *    the caller's fields, and writes the merged result. Never write a bare
 *    partial into a PUT endpoint.
 * 2. Several reads are documented as available only to domain-wide delegated
 *    service accounts (`delegates.list`) and will 403 under this server's
 *    per-user OAuth. A failed read is reported as a failed read. It is never
 *    rendered as an empty list or a disabled setting, because "no delegates"
 *    and "not allowed to ask about delegates" are different answers and only
 *    one of them is safe to act on.
 */

import type { gmail_v1 } from 'googleapis';
import { markdownToHtml } from './markdown.js';

/** The Gmail client surface this module needs. */
type GmailClient = gmail_v1.Gmail;

export type SendAsAlias = gmail_v1.Schema$SendAs;
export type VacationSettings = gmail_v1.Schema$VacationSettings;
export type AutoForwarding = gmail_v1.Schema$AutoForwarding;
export type ForwardingAddress = gmail_v1.Schema$ForwardingAddress;
export type Delegate = gmail_v1.Schema$Delegate;
export type ImapSettings = gmail_v1.Schema$ImapSettings;
export type PopSettings = gmail_v1.Schema$PopSettings;
export type LanguageSettings = gmail_v1.Schema$LanguageSettings;

/**
 * The outcome of one section of an aggregate settings read.
 *
 * `ok` carries a value the caller may act on. `failed` carries the reason the
 * value is unknown. There is deliberately no third state that looks like data:
 * a caller cannot mistake a denied read for a configured-off setting.
 */
export type SectionResult<T> =
    | { status: 'ok'; value: T }
    | { status: 'failed'; reason: string };

export interface SettingsSnapshot {
    sendAs: SectionResult<SendAsAlias[]>;
    vacation: SectionResult<VacationSettings>;
    autoForwarding: SectionResult<AutoForwarding>;
    forwardingAddresses: SectionResult<ForwardingAddress[]>;
    delegates: SectionResult<Delegate[]>;
    imap: SectionResult<ImapSettings>;
    pop: SectionResult<PopSettings>;
    language: SectionResult<LanguageSettings>;
}

/** Read `code`/`status` and a message off an unknown thrown value. */
function describeError(error: unknown): { status?: number; message: string } {
    if (!error || typeof error !== 'object') {
        return { message: String(error ?? 'unknown error') };
    }
    let status: number | undefined;
    if ('code' in error && typeof error.code === 'number') status = error.code;
    else if ('status' in error && typeof error.status === 'number') status = error.status;

    let message: string | undefined;
    if ('errors' in error && Array.isArray(error.errors)) {
        const first: unknown = error.errors[0];
        if (first && typeof first === 'object' && 'message' in first && typeof first.message === 'string') {
            message = first.message;
        }
    }
    if (!message && 'message' in error && typeof error.message === 'string') message = error.message;

    return { status, message: message || 'unknown error' };
}

/** Human-readable reason for a failed API read, preferring Google's own message. */
export function failureReason(error: unknown): string {
    const { status, message } = describeError(error);
    if (status === 403) return `not permitted (403): ${message}`;
    if (status === 401) return `not authenticated (401): ${message}`;
    return status ? `error ${status}: ${message}` : `error: ${message}`;
}

/** Run one section read, capturing failure rather than letting it become an absent value. */
async function section<T>(read: () => Promise<T>): Promise<SectionResult<T>> {
    try {
        return { status: 'ok', value: await read() };
    } catch (error: unknown) {
        return { status: 'failed', reason: failureReason(error) };
    }
}

/**
 * Read every settings section, independently.
 *
 * Sections are read concurrently and each one settles on its own, so a denied
 * `delegates.list` cannot suppress the vacation responder or make the caller
 * believe forwarding is off.
 */
export async function readAllSettings(gmail: GmailClient): Promise<SettingsSnapshot> {
    const [
        sendAs,
        vacation,
        autoForwarding,
        forwardingAddresses,
        delegates,
        imap,
        pop,
        language,
    ] = await Promise.all([
        section(async () => {
            const r = await gmail.users.settings.sendAs.list({ userId: 'me' });
            return r.data.sendAs ?? [];
        }),
        section(async () => {
            const r = await gmail.users.settings.getVacation({ userId: 'me' });
            return r.data ?? {};
        }),
        section(async () => {
            const r = await gmail.users.settings.getAutoForwarding({ userId: 'me' });
            return r.data ?? {};
        }),
        section(async () => {
            const r = await gmail.users.settings.forwardingAddresses.list({ userId: 'me' });
            return r.data.forwardingAddresses ?? [];
        }),
        section(async () => {
            const r = await gmail.users.settings.delegates.list({ userId: 'me' });
            return r.data.delegates ?? [];
        }),
        section(async () => {
            const r = await gmail.users.settings.getImap({ userId: 'me' });
            return r.data ?? {};
        }),
        section(async () => {
            const r = await gmail.users.settings.getPop({ userId: 'me' });
            return r.data ?? {};
        }),
        section(async () => {
            const r = await gmail.users.settings.getLanguage({ userId: 'me' });
            return r.data ?? {};
        }),
    ]);

    return { sendAs, vacation, autoForwarding, forwardingAddresses, delegates, imap, pop, language };
}

/** Epoch-millisecond string to a readable UTC timestamp, or a marker if unparseable. */
function formatEpochMillis(value?: string | null): string {
    if (!value) return '(none)';
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return `(unrecognized: ${value})`;
    return new Date(parsed).toISOString();
}

/** Strip HTML tags for a compact one-line preview of a stored HTML value. */
function preview(html: string, limit = 120): string {
    const text = html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
    if (text.length <= limit) return text;
    return `${text.slice(0, limit)}...`;
}

/**
 * Render a settings snapshot as text for the MCP client.
 *
 * A failed section prints why it could not be read. Nothing here converts a
 * failure into a value, so "no delegates" only ever appears when the delegates
 * read actually succeeded and returned none.
 */
export function formatSettingsSnapshot(snapshot: SettingsSnapshot): string {
    const lines: string[] = [];

    const unreadable = (reason: string) => lines.push(`Could not read this section: ${reason}`);

    lines.push('', '## Send-as addresses');
    if (snapshot.sendAs.status === 'failed') {
        unreadable(snapshot.sendAs.reason);
    } else if (snapshot.sendAs.value.length === 0) {
        lines.push('None configured.');
    } else {
        for (const alias of snapshot.sendAs.value) {
            const tags = [
                alias.isPrimary ? 'primary' : null,
                alias.isDefault ? 'default' : null,
                alias.treatAsAlias ? 'treated as alias' : null,
                alias.verificationStatus && alias.verificationStatus !== 'accepted'
                    ? `verification: ${alias.verificationStatus}`
                    : null,
            ].filter(Boolean).join(', ');
            lines.push(`- ${alias.sendAsEmail}${tags ? ` (${tags})` : ''}`);
            if (alias.displayName) lines.push(`    display name: ${alias.displayName}`);
            if (alias.replyToAddress) lines.push(`    reply-to: ${alias.replyToAddress}`);
            lines.push(alias.signature
                ? `    signature: ${preview(alias.signature)}`
                : '    signature: (none)');
        }
    }

    lines.push('', '## Vacation responder');
    if (snapshot.vacation.status === 'failed') {
        unreadable(snapshot.vacation.reason);
    } else {
        const v = snapshot.vacation.value;
        lines.push(`enabled: ${v.enableAutoReply ? 'yes' : 'no'}`);
        lines.push(`subject: ${v.responseSubject || '(none)'}`);
        const body = v.responseBodyHtml || v.responseBodyPlainText || '';
        lines.push(`body: ${body ? preview(body) : '(none)'}`);
        lines.push(`start: ${formatEpochMillis(v.startTime)}`);
        lines.push(`end: ${formatEpochMillis(v.endTime)}`);
        lines.push(`restricted to contacts: ${v.restrictToContacts ? 'yes' : 'no'}`);
        lines.push(`restricted to domain: ${v.restrictToDomain ? 'yes' : 'no'}`);
    }

    lines.push('', '## Auto-forwarding');
    if (snapshot.autoForwarding.status === 'failed') {
        unreadable(snapshot.autoForwarding.reason);
    } else {
        const f = snapshot.autoForwarding.value;
        lines.push(`enabled: ${f.enabled ? 'yes' : 'no'}`);
        if (f.enabled) {
            lines.push(`forwarding to: ${f.emailAddress || '(not reported)'}`);
            lines.push(`disposition: ${f.disposition || '(not reported)'}`);
        }
    }

    lines.push('', '## Forwarding addresses');
    if (snapshot.forwardingAddresses.status === 'failed') {
        unreadable(snapshot.forwardingAddresses.reason);
    } else if (snapshot.forwardingAddresses.value.length === 0) {
        lines.push('None configured.');
    } else {
        for (const a of snapshot.forwardingAddresses.value) {
            lines.push(`- ${a.forwardingEmail} (${a.verificationStatus || 'status not reported'})`);
        }
    }

    lines.push('', '## Delegates');
    if (snapshot.delegates.status === 'failed') {
        unreadable(snapshot.delegates.reason);
    } else if (snapshot.delegates.value.length === 0) {
        lines.push('None configured.');
    } else {
        for (const d of snapshot.delegates.value) {
            lines.push(`- ${d.delegateEmail} (${d.verificationStatus || 'status not reported'})`);
        }
    }

    lines.push('', '## IMAP');
    if (snapshot.imap.status === 'failed') {
        unreadable(snapshot.imap.reason);
    } else {
        const i = snapshot.imap.value;
        lines.push(`enabled: ${i.enabled ? 'yes' : 'no'}`);
        if (i.expungeBehavior) lines.push(`expunge behavior: ${i.expungeBehavior}`);
        if (i.maxFolderSize) lines.push(`max folder size: ${i.maxFolderSize}`);
    }

    lines.push('', '## POP');
    if (snapshot.pop.status === 'failed') {
        unreadable(snapshot.pop.reason);
    } else {
        const p = snapshot.pop.value;
        lines.push(`access window: ${p.accessWindow || '(none)'}`);
        lines.push(`disposition: ${p.disposition || '(none)'}`);
    }

    lines.push('', '## Display language');
    if (snapshot.language.status === 'failed') {
        unreadable(snapshot.language.reason);
    } else {
        lines.push(snapshot.language.value.displayLanguage || '(not set)');
    }

    return `Mailbox settings${lines.join('\n')}`;
}

/**
 * Resolve which send-as address a write targets.
 *
 * An explicit address must actually exist on the account, so a typo fails here
 * rather than silently patching nothing. With no address, the account's default
 * "From:" address is used, falling back to the primary login address.
 */
export async function resolveSendAsAddress(gmail: GmailClient, requested?: string): Promise<string> {
    const response = await gmail.users.settings.sendAs.list({ userId: 'me' });
    const aliases = response.data.sendAs ?? [];
    if (aliases.length === 0) {
        throw new Error('This account has no send-as addresses.');
    }

    if (requested) {
        const wanted = requested.trim().toLowerCase();
        const match = aliases.find(a => (a.sendAsEmail ?? '').toLowerCase() === wanted);
        if (!match?.sendAsEmail) {
            const known = aliases.map(a => a.sendAsEmail).filter(Boolean).join(', ');
            throw new Error(`"${requested}" is not a send-as address on this account. Available: ${known}`);
        }
        return match.sendAsEmail;
    }

    const chosen = aliases.find(a => a.isDefault) ?? aliases.find(a => a.isPrimary) ?? aliases[0];
    if (!chosen.sendAsEmail) {
        throw new Error('Could not determine a send-as address for this account.');
    }
    return chosen.sendAsEmail;
}

export interface SetSignatureArgs {
    /** Signature source in Markdown. Rendered to HTML unless `signatureHtml` is given. */
    signature?: string;
    /** Explicit HTML signature, used verbatim. */
    signatureHtml?: string;
    /** Which send-as address to change. Defaults to the account's default From address. */
    sendAsEmail?: string;
}

export interface SetSignatureResult {
    sendAsEmail: string;
    /** What we sent to Gmail. */
    signature: string;
    /** What Gmail reports storing, after its own HTML sanitization. */
    storedSignature: string;
    /** True when Gmail stored something other than what we sent. */
    alteredByGmail: boolean;
}

/**
 * Set the Gmail signature on a send-as address.
 *
 * The signature is Markdown by default, matching how message bodies work in this
 * server. Gmail sanitizes signature HTML server-side, so the stored value is read
 * back from the response and reported when it differs from what we sent.
 */
export async function setSignature(gmail: GmailClient, args: SetSignatureArgs): Promise<SetSignatureResult> {
    if (args.signature === undefined && args.signatureHtml === undefined) {
        throw new Error('Provide "signature" (Markdown) or "signatureHtml". To clear the signature, pass an empty string.');
    }

    const html = args.signatureHtml ?? markdownToHtml(args.signature ?? '');
    const sendAsEmail = await resolveSendAsAddress(gmail, args.sendAsEmail);

    const response = await gmail.users.settings.sendAs.patch({
        userId: 'me',
        sendAsEmail,
        requestBody: { signature: html },
    });

    const stored = response.data?.signature ?? '';
    return {
        sendAsEmail,
        signature: html,
        storedSignature: stored,
        alteredByGmail: stored !== html,
    };
}

export interface UpdateSendAsArgs {
    sendAsEmail?: string;
    displayName?: string;
    replyToAddress?: string;
    treatAsAlias?: boolean;
    /** Make this the default "From:" address. Gmail only accepts `true` here. */
    makeDefault?: boolean;
}

export interface UpdateSendAsResult {
    sendAsEmail: string;
    applied: Record<string, string | boolean>;
    /**
     * Fields Gmail accepted the request for but did not actually change. Gmail
     * documents that display-name updates "silently fail" when an admin has
     * disabled name changes, so the result is read back and compared.
     */
    ignored: string[];
    current: SendAsAlias;
}

/**
 * Update the identity fields of a send-as address (not the signature).
 *
 * Uses `sendAs.patch` so untouched fields survive, then verifies the response
 * reflects what was asked for. A request Gmail accepted but ignored is reported
 * as ignored rather than as success.
 */
export async function updateSendAs(gmail: GmailClient, args: UpdateSendAsArgs): Promise<UpdateSendAsResult> {
    const requestBody: Record<string, string | boolean> = {};
    if (args.displayName !== undefined) requestBody.displayName = args.displayName;
    if (args.replyToAddress !== undefined) requestBody.replyToAddress = args.replyToAddress;
    if (args.treatAsAlias !== undefined) requestBody.treatAsAlias = args.treatAsAlias;
    if (args.makeDefault !== undefined) {
        if (args.makeDefault !== true) {
            throw new Error('makeDefault only accepts true: Gmail always has exactly one default send-as address, so it is changed by promoting another address.');
        }
        requestBody.isDefault = true;
    }

    if (Object.keys(requestBody).length === 0) {
        throw new Error('Nothing to update. Provide at least one of: displayName, replyToAddress, treatAsAlias, makeDefault.');
    }

    const sendAsEmail = await resolveSendAsAddress(gmail, args.sendAsEmail);
    const response = await gmail.users.settings.sendAs.patch({
        userId: 'me',
        sendAsEmail,
        requestBody,
    });

    const current: SendAsAlias = response.data ?? { sendAsEmail };
    const ignored = ignoredFields(requestBody, current);

    return { sendAsEmail, applied: requestBody, ignored, current };
}

/**
 * Compare a patch request against the resource Gmail returned.
 *
 * Gmail omits empty strings and false booleans from responses, so an absent
 * field counts as equal to a falsy request rather than as a mismatch.
 */
export function ignoredFields(
    requestBody: Record<string, string | boolean>,
    current: SendAsAlias,
): string[] {
    const ignored: string[] = [];
    const record: Record<string, unknown> = { ...current };
    for (const [field, requested] of Object.entries(requestBody)) {
        const actual = record[field];
        const normalized = actual === undefined || actual === null
            ? (typeof requested === 'boolean' ? false : '')
            : actual;
        if (normalized !== requested) ignored.push(field);
    }
    return ignored;
}

export interface SetVacationArgs {
    enabled: boolean;
    subject?: string;
    /** Response body in Markdown. Rendered to HTML unless `bodyHtml` is given. */
    body?: string;
    /** Explicit HTML response body, used verbatim. */
    bodyHtml?: string;
    /** ISO date or datetime. A bare date is interpreted as UTC midnight. */
    startTime?: string;
    endTime?: string;
    restrictToContacts?: boolean;
    restrictToDomain?: boolean;
}

/** Convert an ISO date or datetime to the epoch-millisecond string the API expects. */
export function toEpochMillis(value: string, field: string): string {
    const parsed = Date.parse(value);
    if (Number.isNaN(parsed)) {
        throw new Error(`${field} is not a valid date: "${value}". Use an ISO date (2026-08-20) or datetime (2026-08-20T09:00:00-07:00).`);
    }
    return String(parsed);
}

/**
 * Build the merged VacationSettings that will be PUT to Gmail.
 *
 * Split out from the API call so the merge and validation rules are testable
 * without a Gmail client.
 */
export function buildVacationSettings(current: VacationSettings, args: SetVacationArgs): VacationSettings {
    const merged: VacationSettings = { ...current, enableAutoReply: args.enabled };

    if (args.subject !== undefined) merged.responseSubject = args.subject;
    if (args.restrictToContacts !== undefined) merged.restrictToContacts = args.restrictToContacts;
    if (args.restrictToDomain !== undefined) merged.restrictToDomain = args.restrictToDomain;

    if (args.bodyHtml !== undefined) {
        merged.responseBodyHtml = args.bodyHtml;
    } else if (args.body !== undefined) {
        // Gmail prefers responseBodyHtml when both are present, so set both: the
        // HTML for rendering clients and the Markdown source as the text part.
        merged.responseBodyHtml = markdownToHtml(args.body);
        merged.responseBodyPlainText = args.body;
    }

    if (args.startTime !== undefined) merged.startTime = toEpochMillis(args.startTime, 'startTime');
    if (args.endTime !== undefined) merged.endTime = toEpochMillis(args.endTime, 'endTime');

    if (merged.startTime && merged.endTime && Number(merged.startTime) >= Number(merged.endTime)) {
        throw new Error('startTime must precede endTime.');
    }

    if (args.enabled) {
        const hasSubject = !!merged.responseSubject?.trim();
        const hasBody = !!(merged.responseBodyHtml?.trim() || merged.responseBodyPlainText?.trim());
        if (!hasSubject && !hasBody) {
            throw new Error('Gmail requires a nonempty subject or body to enable the vacation responder. Provide "subject" or "body".');
        }
    }

    return merged;
}

/**
 * Turn the vacation responder on or off.
 *
 * `updateVacation` replaces the whole resource, so current settings are read
 * first and the caller's fields merged over them. Gmail requires a nonempty
 * subject or body to enable auto-replies, which is checked against the merged
 * result rather than the request, so enabling against an existing body works.
 */
export async function setVacationResponder(gmail: GmailClient, args: SetVacationArgs): Promise<VacationSettings> {
    const currentResponse = await gmail.users.settings.getVacation({ userId: 'me' });
    const merged = buildVacationSettings(currentResponse.data ?? {}, args);

    const response = await gmail.users.settings.updateVacation({
        userId: 'me',
        requestBody: merged,
    });

    return response.data ?? merged;
}
