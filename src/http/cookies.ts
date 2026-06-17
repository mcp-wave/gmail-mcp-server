// Minimal cookie helpers for the first-party session used by the manage flow.
// (Avoids adding a cookie-parser dependency.)

import type { IncomingMessage } from 'node:http';

export const SESSION_COOKIE = 'mcp_session';

export function parseCookies(header: string | undefined | null): Record<string, string> {
    const out: Record<string, string> = {};
    if (!header) return out;
    for (const part of header.split(';')) {
        const i = part.indexOf('=');
        if (i < 0) continue;
        const k = part.slice(0, i).trim();
        const v = part.slice(i + 1).trim();
        if (k) out[k] = decodeURIComponent(v);
    }
    return out;
}

/** Read the session id from a request's Cookie header (undefined if absent). */
export function readSessionCookie(req: IncomingMessage | undefined): string | undefined {
    if (!req) return undefined;
    return parseCookies(req.headers?.cookie)[SESSION_COOKIE];
}
