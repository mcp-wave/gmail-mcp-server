/**
 * Tests for signature resolution, HTML-to-text conversion, and caching.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
 wrapSignatureHtml,
 signatureHtmlToText,
 resolveSignature,
 invalidateSignatureCache,
 SIGNATURE_MARKER,
} from './signature.js';

/** A Gmail API error shaped the way googleapis surfaces one. */
function apiError(code: number, message: string) {
 return Object.assign(new Error(message), { code, errors: [{ message }] });
}

interface StubOptions {
 sendAs?: unknown[];
 failure?: Error;
 calls?: { listCalls: number };
}

/**
 * Minimal stand-in for the Gmail client covering users.settings.sendAs.list.
 */
function stubGmail(options: StubOptions = {}) {
 return {
  users: {
   settings: {
    sendAs: {
     list: async () => {
      if (options.calls) {
       options.calls.listCalls += 1;
      }
      if (options.failure) {
       throw options.failure;
      }
      return { data: { sendAs: options.sendAs ?? [] } };
     },
    },
   },
  },
 } as unknown as Parameters<typeof resolveSignature>[0];
}

describe('wrapSignatureHtml', () => {
 it('wraps the HTML fragment in Gmail canonical signature container', () => {
  const wrapped = wrapSignatureHtml('<p>Best regards,<br>Alice</p>');
  expect(wrapped).toBe(
   `<div class="${SIGNATURE_MARKER}" data-smartmail="${SIGNATURE_MARKER}"><p>Best regards,<br>Alice</p></div>`,
  );
 });
});

describe('signatureHtmlToText', () => {
 it('converts a realistic multi-line signature with links and line breaks', () => {
  const html = [
   '<div><b>Jane Doe</b></div>',
   '<div>Lead Systems Architect, Acme Cloud</div>',
   '<div><a href="https://example.com">https://example.com</a><br><a href="mailto:jane@example.com">Contact Me</a></div>',
  ].join('');

  const text = signatureHtmlToText(html);
  expect(text).toBe([
   'Jane Doe',
   'Lead Systems Architect, Acme Cloud',
   'https://example.com',
   'Contact Me (mailto:jane@example.com)',
  ].join('\n'));
 });

 it('drops style and script elements with their contents', () => {
  const html = '<style>div { color: red; }</style><div>Alice</div><script>console.log(1);</script>';
  expect(signatureHtmlToText(html)).toBe('Alice');
 });

 it('drops img tags completely without emitting alt text', () => {
  const html = '<div><img src="logo.png" alt="Acme Logo">Acme Corp</div>';
  expect(signatureHtmlToText(html)).toBe('Acme Corp');
 });

 it('converts br tags to newlines', () => {
  const html = 'Line 1<br>Line 2<br/>Line 3<br />Line 4';
  expect(signatureHtmlToText(html)).toBe('Line 1\nLine 2\nLine 3\nLine 4');
 });

 it('places list items on separate lines without running together', () => {
  const html = '<ul><li>First item</li><li>Second item</li><li>Third item</li></ul>';
  expect(signatureHtmlToText(html)).toBe('First item\nSecond item\nThird item');
 });

 it('applies the anchor URL rule: keeps text when URL is already present in text', () => {
  const html1 = '<a href="https://example.com">https://example.com</a>';
  expect(signatureHtmlToText(html1)).toBe('https://example.com');

  const html2 = '<a href="https://example.com">Visit https://example.com today</a>';
  expect(signatureHtmlToText(html2)).toBe('Visit https://example.com today');
 });

 it('applies the anchor URL rule: keeps text for mailto and tel links matching text', () => {
  const mailHtml = '<a href="mailto:alice@example.com">alice@example.com</a>';
  expect(signatureHtmlToText(mailHtml)).toBe('alice@example.com');

  const telHtml = '<a href="tel:+15551234567">+15551234567</a>';
  expect(signatureHtmlToText(telHtml)).toBe('+15551234567');
 });

 it('applies the anchor URL rule: appends URL in parentheses when destination differs', () => {
  const linkHtml = '<a href="https://example.com/docs">Documentation Portal</a>';
  expect(signatureHtmlToText(linkHtml)).toBe('Documentation Portal (https://example.com/docs)');

  const mailHtml = '<a href="mailto:alice@example.com">Email Me</a>';
  expect(signatureHtmlToText(mailHtml)).toBe('Email Me (mailto:alice@example.com)');

  const telHtml = '<a href="tel:+15551234567">Call Desk</a>';
  expect(signatureHtmlToText(telHtml)).toBe('Call Desk (tel:+15551234567)');
 });

 it('decodes named and numeric HTML entities correctly', () => {
  const html = 'Alice&nbsp;&amp;&nbsp;Bob &lt;team&gt; &quot;quoted&quot; &#39;single&#39; &apos;apostrophe&apos; &#65;&#x42;';
  expect(signatureHtmlToText(html)).toBe('Alice & Bob <team> "quoted" \'single\' \'apostrophe\' AB');
 });

 it('strips trailing whitespace per line and collapses three or more newlines to two', () => {
  const html = '<p>Line 1   </p><br><br><br><br><p>Line 2   </p>';
  expect(signatureHtmlToText(html)).toBe('Line 1\n\nLine 2');
 });
});

describe('resolveSignature', () => {
 beforeEach(() => {
  invalidateSignatureCache();
 });

 const defaultAlias = {
  sendAsEmail: 'default@example.com',
  signature: '<div>Default Signature</div>',
  isDefault: true,
  isPrimary: true,
 };

 const secondaryAlias = {
  sendAsEmail: 'sales@example.com',
  signature: '<div>Sales Team Signature</div>',
  isDefault: false,
  isPrimary: false,
 };

 const emptySigAlias = {
  sendAsEmail: 'nosig@example.com',
  signature: '   ',
  isDefault: false,
  isPrimary: false,
 };

 it('picks the signature of an explicitly requested alias rather than the default', async () => {
  const gmail = stubGmail({ sendAs: [defaultAlias, secondaryAlias] });
  const res = await resolveSignature(gmail, 'acct-1', 'sales@example.com');

  expect(res).toEqual({
   status: 'ok',
   sendAsEmail: 'sales@example.com',
   parts: {
    html: '<div>Sales Team Signature</div>',
    text: 'Sales Team Signature',
   },
  });
 });

 it('reduces full name-and-address From values to match aliases', async () => {
  const gmail = stubGmail({ sendAs: [defaultAlias, secondaryAlias] });
  const res = await resolveSignature(gmail, 'acct-1', 'Sales Rep <sales@example.com>');

  expect(res).toEqual({
   status: 'ok',
   sendAsEmail: 'sales@example.com',
   parts: {
    html: '<div>Sales Team Signature</div>',
    text: 'Sales Team Signature',
   },
  });
 });

 it('falls back to the default alias when from is absent', async () => {
  const gmail = stubGmail({ sendAs: [defaultAlias, secondaryAlias] });
  const res = await resolveSignature(gmail, 'acct-1');

  expect(res).toEqual({
   status: 'ok',
   sendAsEmail: 'default@example.com',
   parts: {
    html: '<div>Default Signature</div>',
    text: 'Default Signature',
   },
  });
 });

 it('falls back to the default alias when from is me', async () => {
  const gmail = stubGmail({ sendAs: [defaultAlias, secondaryAlias] });
  const res = await resolveSignature(gmail, 'acct-1', 'me');

  expect(res).toEqual({
   status: 'ok',
   sendAsEmail: 'default@example.com',
   parts: {
    html: '<div>Default Signature</div>',
    text: 'Default Signature',
   },
  });
 });

 it('returns unavailable and does not fall back to default when explicit from is unknown', async () => {
  const gmail = stubGmail({ sendAs: [defaultAlias, secondaryAlias] });
  const res = await resolveSignature(gmail, 'acct-1', 'unknown@example.com');

  expect(res.status).toBe('unavailable');
  if (res.status === 'unavailable') {
   expect(res.reason).toContain('"unknown@example.com" is not a send-as address on this account');
   expect(res.reason).toContain('default@example.com');
   expect(res.reason).toContain('sales@example.com');
  }
 });

 it('returns unavailable with failureReason when API rejects without throwing', async () => {
  const gmail = stubGmail({ failure: apiError(403, 'Delegated access denied') });
  const res = await resolveSignature(gmail, 'acct-err');

  expect(res.status).toBe('unavailable');
  if (res.status === 'unavailable') {
   expect(res.reason).toContain('not permitted (403): Delegated access denied');
  }
 });

 it('returns parts: null when the alias signature is absent or whitespace-only', async () => {
  const gmail = stubGmail({ sendAs: [emptySigAlias, defaultAlias] });
  const res = await resolveSignature(gmail, 'acct-1', 'nosig@example.com');

  expect(res).toEqual({
   status: 'ok',
   sendAsEmail: 'nosig@example.com',
   parts: null,
  });
 });

 it('serves subsequent calls from cache without extra API calls, and refetches after cache invalidation', async () => {
  const calls = { listCalls: 0 };
  const gmail = stubGmail({ sendAs: [defaultAlias], calls });

  const res1 = await resolveSignature(gmail, 'acct-cache');
  expect(res1.status).toBe('ok');
  expect(calls.listCalls).toBe(1);

  // Second call for the same accountKey should hit the cache
  const res2 = await resolveSignature(gmail, 'acct-cache');
  expect(res2.status).toBe('ok');
  expect(calls.listCalls).toBe(1);

  // Invalidate single account cache entry
  invalidateSignatureCache('acct-cache');

  // Third call must trigger a fresh API list call
  const res3 = await resolveSignature(gmail, 'acct-cache');
  expect(res3.status).toBe('ok');
  expect(calls.listCalls).toBe(2);

  // Invalidate entire cache
  invalidateSignatureCache();

  // Fourth call must trigger another fresh API list call
  const res4 = await resolveSignature(gmail, 'acct-cache');
  expect(res4.status).toBe('ok');
  expect(calls.listCalls).toBe(3);
 });

 it('returns unavailable when the account has no send-as aliases', async () => {
  const gmail = stubGmail({ sendAs: [] });
  const res = await resolveSignature(gmail, 'acct-empty');

  expect(res).toEqual({
   status: 'unavailable',
   reason: 'This account has no send-as addresses.',
  });
 });
});
