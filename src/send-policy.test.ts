import { describe, it, expect } from 'vitest';
import { recipientAllowed, disallowedRecipients, emailAddressOf } from './send-policy.js';
import type { SendPolicy } from './session.js';

const OWN = 'me@example.com';

describe('emailAddressOf', () => {
    it('extracts the bare address', () => {
        expect(emailAddressOf('Jane Doe <jane@acme.com>')).toBe('jane@acme.com');
        expect(emailAddressOf('  BOB@Acme.com ')).toBe('bob@acme.com');
    });
});

describe('recipientAllowed', () => {
    it('allows everything when no policy is set (local mode)', () => {
        expect(recipientAllowed('anyone@anywhere.com', OWN, undefined)).toBe(true);
    });

    it('always allows the account\'s own address', () => {
        const p: SendPolicy = { allowlist: [], dangerouslyAllowAll: false };
        expect(recipientAllowed('me@example.com', OWN, p)).toBe(true);
        expect(recipientAllowed('Me <ME@EXAMPLE.COM>', OWN, p)).toBe(true);
    });

    it('blocks non-allowlisted recipients by default', () => {
        const p: SendPolicy = { allowlist: [], dangerouslyAllowAll: false };
        expect(recipientAllowed('stranger@evil.com', OWN, p)).toBe(false);
    });

    it('matches an exact allowlisted address', () => {
        const p: SendPolicy = { allowlist: ['boss@acme.com'], dangerouslyAllowAll: false };
        expect(recipientAllowed('boss@acme.com', OWN, p)).toBe(true);
        expect(recipientAllowed('other@acme.com', OWN, p)).toBe(false);
    });

    it('matches a bare domain (and subdomains)', () => {
        const p: SendPolicy = { allowlist: ['acme.com'], dangerouslyAllowAll: false };
        expect(recipientAllowed('anyone@acme.com', OWN, p)).toBe(true);
        expect(recipientAllowed('x@mail.acme.com', OWN, p)).toBe(true);
        expect(recipientAllowed('x@notacme.com', OWN, p)).toBe(false);
        expect(recipientAllowed('x@acme.com.evil.com', OWN, p)).toBe(false);
    });

    it('matches an @domain entry', () => {
        const p: SendPolicy = { allowlist: ['@acme.com'], dangerouslyAllowAll: false };
        expect(recipientAllowed('a@acme.com', OWN, p)).toBe(true);
        expect(recipientAllowed('a@evil.com', OWN, p)).toBe(false);
    });

    it('dangerouslyAllowAll permits anyone', () => {
        const p: SendPolicy = { allowlist: [], dangerouslyAllowAll: true };
        expect(recipientAllowed('anyone@anywhere.com', OWN, p)).toBe(true);
    });
});

describe('disallowedRecipients', () => {
    it('returns only the blocked recipients', () => {
        const p: SendPolicy = { allowlist: ['acme.com'], dangerouslyAllowAll: false };
        const blocked = disallowedRecipients(
            ['me@example.com', 'ok@acme.com', 'no@evil.com', undefined, 'also@bad.org'],
            OWN,
            p,
        );
        expect(blocked).toEqual(['no@evil.com', 'also@bad.org']);
    });

    it('returns empty when all allowed', () => {
        expect(disallowedRecipients(['me@example.com'], OWN, { allowlist: [], dangerouslyAllowAll: false })).toEqual([]);
    });
});
