// Per-account outbound send-policy evaluation.
//
// Sending to the account's OWN address is always allowed. Otherwise a recipient
// must match the allowlist — an exact address (`a@b.com`), a domain prefixed with
// `@` (`@b.com`), or a bare domain (`b.com`, which also matches subdomains) —
// unless `dangerouslyAllowAll` is set. A missing policy (e.g. stdio/local
// single-user) allows everything.

import type { SendPolicy } from './session.js';

export type SendContext = {
    ownEmail: string;
    policy?: SendPolicy;
    // Persist newly-approved recipients to this account's allowlist (hosted only).
    persistAllow?: (entries: string[]) => Promise<void>;
};

/** Extract the bare lowercase address from a "Name <a@b.com>" or "a@b.com" value. */
export function emailAddressOf(value: string): string {
    const m = String(value).match(/<([^>]+)>/);
    return (m ? m[1] : String(value)).trim().toLowerCase();
}

export function recipientAllowed(recipient: string, ownEmail: string, policy?: SendPolicy): boolean {
    if (!policy) return true; // no policy configured => unrestricted (local mode)
    if (policy.dangerouslyAllowAll) return true;
    const r = emailAddressOf(recipient);
    if (!r) return true;
    if (ownEmail && r === ownEmail.toLowerCase()) return true; // always allow self
    for (const raw of policy.allowlist || []) {
        const e = raw.trim().toLowerCase();
        if (!e) continue;
        if (e.startsWith('@')) {
            if (r.endsWith(e)) return true; // @domain.com
        } else if (e.includes('@')) {
            if (r === e) return true; // exact address
        } else if (r.endsWith('@' + e) || r.endsWith('.' + e)) {
            return true; // bare domain.com (incl. subdomains)
        }
    }
    return false;
}

/** Returns the recipients NOT permitted by the policy (empty => send allowed). */
export function disallowedRecipients(
    recipients: Array<string | undefined>,
    ownEmail: string,
    policy?: SendPolicy,
): string[] {
    return recipients
        .filter((x): x is string => !!x)
        .filter((rcpt) => !recipientAllowed(rcpt, ownEmail, policy));
}
