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

// Public / free email providers: allowing the WHOLE domain would let the agent
// email anyone there, so these are forbidden as domain-level allowlist entries.
// (Specific addresses like alice@gmail.com are still allowable.)
export const PUBLIC_EMAIL_DOMAINS = new Set<string>([
    'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'yahoo.co.in', 'ymail.com',
    'rocketmail.com', 'outlook.com', 'outlook.co.uk', 'hotmail.com', 'hotmail.co.uk',
    'live.com', 'msn.com', 'icloud.com', 'me.com', 'mac.com', 'aol.com', 'aim.com',
    'proton.me', 'protonmail.com', 'pm.me', 'gmx.com', 'gmx.net', 'mail.com', 'zoho.com',
    'yandex.com', 'yandex.ru', 'fastmail.com', 'hey.com', 'qq.com', '163.com', '126.com',
    'tutanota.com', 'tuta.io',
]);

/** Is `entry` a domain-level allowlist entry (@domain or bare domain) rather than an exact address? */
export function isDomainEntry(entry: string): boolean {
    const e = entry.trim().toLowerCase();
    return e.startsWith('@') || !e.includes('@');
}

export function isPublicEmailDomain(domain: string): boolean {
    return PUBLIC_EMAIL_DOMAINS.has(domain.trim().toLowerCase().replace(/^@/, ''));
}

/**
 * Returns a rejection reason if this allowlist entry is not permitted (a
 * domain-level entry for a public email provider), else null.
 */
export function rejectedAllowlistEntry(entry: string): string | null {
    const e = entry.trim().toLowerCase();
    if (isDomainEntry(e) && isPublicEmailDomain(e)) {
        const d = e.replace(/^@/, '');
        return `"${d}" is a public email provider — allowing the whole domain would let the agent email anyone there. Allow a specific address (e.g. someone@${d}) instead.`;
    }
    return null;
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
