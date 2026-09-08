/**
 * Tests for email message construction in utl.ts
 *
 * Threading headers (issue #66):
 * 1. createEmailMessage uses separate `references` field when provided
 * 2. createEmailMessage falls back to `inReplyTo` for References when no `references` field
 * 3. No References/In-Reply-To headers on new emails
 * 4. Source verification: createEmailWithNodemailer uses references field
 * 5. Source verification: handleEmailAction auto-resolves threading headers
 * 6. Source verification: read_email returns Message-ID
 *
 * HTML by default:
 * 7. A Markdown `body` alone yields multipart/alternative with rendered HTML
 * 8. `mimeType: 'text/plain'` is the plain-text opt-out
 * 9. A supplied `htmlBody` is used verbatim
 * 10. resolveBodyParts implements the same rules
 */

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createEmailMessage, resolveBodyParts } from './utl.js';
import type { SignatureParts } from './signature.js';
import { SIGNATURE_MARKER } from './signature.js';

// Resolve src directory
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const srcDir = __dirname;

// Helper: extract a header value from a raw MIME message string
function getHeader(raw: string, headerName: string): string | null {
 const regex = new RegExp(`^${headerName}:\\s*(.+)$`, 'mi');
 const match = raw.match(regex);
 return match ? match[1].trim() : null;
}

describe('Email threading headers', () => {
 it('uses separate references field when provided', () => {
  const args = {
   to: ['test@example.com'],
   subject: 'Re: Thread test',
   body: 'Reply body',
   inReplyTo: '<msg3@example.com>',
   references: '<msg1@example.com> <msg2@example.com> <msg3@example.com>',
  };
  const raw = createEmailMessage(args);

  expect(getHeader(raw, 'References')).toBe(
   '<msg1@example.com> <msg2@example.com> <msg3@example.com>'
  );
  expect(getHeader(raw, 'In-Reply-To')).toBe('<msg3@example.com>');
 });

 it('falls back to inReplyTo when references is absent', () => {
  const args = {
   to: ['test@example.com'],
   subject: 'Re: Fallback test',
   body: 'Reply body',
   inReplyTo: '<single@example.com>',
  };
  const raw = createEmailMessage(args);

  expect(getHeader(raw, 'References')).toBe('<single@example.com>');
 });

 it('has no threading headers on new emails', () => {
  const args = {
   to: ['test@example.com'],
   subject: 'New email',
   body: 'Fresh email body',
  };
  const raw = createEmailMessage(args);

  expect(getHeader(raw, 'References')).toBeNull();
  expect(getHeader(raw, 'In-Reply-To')).toBeNull();
 });
});

describe('HTML by default', () => {
 const baseArgs = {
  to: ['a@example.com'],
  subject: 'S',
  body: 'Hi **there**\n\n- one\n- two',
 };

 it('renders Markdown to a multipart/alternative message when only body is given', () => {
  const raw = createEmailMessage({ ...baseArgs });

  expect(getHeader(raw, 'Content-Type')).toMatch(/^multipart\/alternative; boundary=/);
  expect(raw).toContain('Content-Type: text/plain; charset=UTF-8');
  expect(raw).toContain('Content-Type: text/html; charset=UTF-8');
  expect(raw).toContain('<strong>there</strong>');
  expect(raw).toContain('<ul>');
  // The text part keeps the raw Markdown source
  expect(raw).toContain('Hi **there**');
 });

 it('sends plain text only when mimeType is text/plain', () => {
  const raw = createEmailMessage({ ...baseArgs, mimeType: 'text/plain' });

  expect(getHeader(raw, 'Content-Type')).toBe('text/plain; charset=UTF-8');
  expect(raw).not.toContain('text/html');
  expect(raw).toContain('Hi **there**');
 });

 it('uses a supplied htmlBody verbatim instead of rendering the Markdown', () => {
  const raw = createEmailMessage({ ...baseArgs, htmlBody: '<p>hand written</p>' });

  expect(getHeader(raw, 'Content-Type')).toMatch(/^multipart\/alternative; boundary=/);
  expect(raw).toContain('<p>hand written</p>');
  expect(raw).not.toContain('<strong>');
 });

 it('sends HTML only when mimeType is text/html', () => {
  const raw = createEmailMessage({ ...baseArgs, mimeType: 'text/html' });

  expect(getHeader(raw, 'Content-Type')).toBe('text/html; charset=UTF-8');
  expect(raw).toContain('<strong>there</strong>');
  expect(raw).not.toContain('boundary=');
 });

 it('falls back to a single plain part when the body is blank', () => {
  const raw = createEmailMessage({ ...baseArgs, body: '   ' });

  expect(getHeader(raw, 'Content-Type')).toBe('text/plain; charset=UTF-8');
  expect(raw).not.toContain('text/html');
 });
});

describe('resolveBodyParts', () => {
 const body = 'Hi **there**\n\n- one\n- two';

 it('defaults to multipart/alternative with rendered HTML', () => {
  const resolved = resolveBodyParts({ body });

  expect(resolved.mimeType).toBe('multipart/alternative');
  expect(resolved.text).toBe(body);
  expect(resolved.html).toContain('<strong>there</strong>');
 });

 it('returns text only for mimeType text/plain', () => {
  const resolved = resolveBodyParts({ body, mimeType: 'text/plain' });

  expect(resolved).toEqual({ mimeType: 'text/plain', text: body });
 });

 it('prefers a supplied htmlBody over rendered Markdown', () => {
  const resolved = resolveBodyParts({ body, htmlBody: '<p>hand written</p>' });

  expect(resolved.mimeType).toBe('multipart/alternative');
  expect(resolved.html).toBe('<p>hand written</p>');
 });

 it('returns html only for mimeType text/html', () => {
  const resolved = resolveBodyParts({ body, mimeType: 'text/html' });

  expect(resolved.mimeType).toBe('text/html');
  expect(resolved.text).toBeUndefined();
  expect(resolved.html).toContain('<strong>there</strong>');
 });

 it('degrades to a single plain part for a blank body', () => {
  const resolved = resolveBodyParts({ body: '   ' });

  expect(resolved).toEqual({ mimeType: 'text/plain', text: '   ' });
 });
});
describe('Email signatures', () => {
 const signature: SignatureParts = {
  text: '-- \nJane Doe\nAcme Corp',
  html: '<p>-- <br><b>Jane Doe</b><br>Acme Corp</p>',
 };

 it('carries the signature in both text and HTML parts of a default multipart message', () => {
  const raw = createEmailMessage(
   { to: ['a@example.com'], subject: 'S', body: 'Hello world' },
   signature,
  );

  expect(getHeader(raw, 'Content-Type')).toMatch(/^multipart\/alternative; boundary=/);
  expect(raw).toContain('Content-Type: text/plain; charset=UTF-8');
  expect(raw).toContain('Content-Type: text/html; charset=UTF-8');
  expect(raw).toContain('Hello world\n\n-- \nJane Doe\nAcme Corp');
  expect(raw).toContain(`<div class="${SIGNATURE_MARKER}" data-smartmail="${SIGNATURE_MARKER}"><p>-- <br><b>Jane Doe</b><br>Acme Corp</p></div>`);
  expect(raw).toContain('<div><br></div>');
 });

 it('omitting the signature argument produces exactly the unsigned message', () => {
  // The multipart boundary is randomised per call, so it has to be normalised
  // away before two builds of the same message can be compared.
  const stripBoundary = (raw: string) => raw.replace(/----=_NextPart_[a-z0-9]+/g, 'BOUNDARY');
  const args = { to: ['a@example.com'], subject: 'Test Subject', body: 'Hello world' };
  const rawWithoutArg = createEmailMessage(args);
  const rawWithNull = createEmailMessage(args, null);
  const rawWithUndefined = createEmailMessage(args, undefined);

  expect(rawWithoutArg).not.toContain(SIGNATURE_MARKER);
  expect(rawWithoutArg).toContain('Hello world');
  expect(rawWithoutArg).not.toContain('<div><br></div>');
  expect(stripBoundary(rawWithNull)).toBe(stripBoundary(rawWithoutArg));
  expect(stripBoundary(rawWithUndefined)).toBe(stripBoundary(rawWithoutArg));

  const resolved = resolveBodyParts({ body: 'Hello world' });
  expect(resolved.text).toBe('Hello world');
  expect(resolved.html).not.toContain(SIGNATURE_MARKER);
 });

 it('does not sign twice when body already ends with the signature text', () => {
  const bodyWithSig = 'Hello world\n\n-- \nJane Doe\nAcme Corp';
  const resolved = resolveBodyParts({ body: bodyWithSig }, signature);

  expect(resolved.text).toBe(bodyWithSig);

  // Normalisation handles CRLF and trailing spaces
  const bodyWithCrlfSig = 'Hello world\r\n\r\n--   \r\nJane Doe  \r\nAcme Corp\r\n';
  const resolvedCrlf = resolveBodyParts({ body: bodyWithCrlfSig }, signature);
  expect(resolvedCrlf.text).toBe(bodyWithCrlfSig);
 });

 it('leaves body HTML alone when it already contains a gmail_signature block', () => {
  const existingHtml = `<p>Hello</p><div class="${SIGNATURE_MARKER}">Old Signature</div>`;
  const resolved = resolveBodyParts(
   { body: 'Hello', htmlBody: existingHtml, mimeType: 'text/html' },
   signature,
  );

  expect(resolved.html).toBe(existingHtml);
  expect(resolved.html).not.toContain('<b>Jane Doe</b>');
 });

 it('does not duplicate signature when htmlBody already ends with raw signature HTML', () => {
  const rawSigHtml = '<p>Hello</p>\n<p>-- <br><b>Jane Doe</b><br>Acme Corp</p>';
  const resolved = resolveBodyParts(
   { htmlBody: rawSigHtml, mimeType: 'text/html' },
   signature,
  );

  expect(resolved.html).toBe(rawSigHtml);
 });

 it('appends text signature and emits no HTML part when mimeType is text/plain', () => {
  const resolved = resolveBodyParts({ body: 'Hello', mimeType: 'text/plain' }, signature);

  expect(resolved.mimeType).toBe('text/plain');
  expect(resolved.text).toBe('Hello\n\n-- \nJane Doe\nAcme Corp');
  expect(resolved.html).toBeUndefined();

  const raw = createEmailMessage({ to: ['a@example.com'], subject: 'S', body: 'Hello', mimeType: 'text/plain' }, signature);
  expect(getHeader(raw, 'Content-Type')).toBe('text/plain; charset=UTF-8');
  expect(raw).not.toContain('text/html');
  expect(raw).not.toContain(SIGNATURE_MARKER);
  expect(raw).toContain('Hello\n\n-- \nJane Doe\nAcme Corp');
 });

 it('appends signature to hand-authored htmlBody when mimeType is text/html', () => {
  const handAuthoredHtml = '<h1>Custom Header</h1><p>Custom content</p>';
  const resolved = resolveBodyParts(
   { htmlBody: handAuthoredHtml, mimeType: 'text/html' },
   signature,
  );

  expect(resolved.mimeType).toBe('text/html');
  expect(resolved.text).toBeUndefined();
  expect(resolved.html).toBe(
   `${handAuthoredHtml}\n<div><br></div>\n<div class="${SIGNATURE_MARKER}" data-smartmail="${SIGNATURE_MARKER}">${signature.html}</div>`,
  );
 });

 it('yields both parts for an empty body with signature rather than collapsing to text/plain', () => {
  const resolved = resolveBodyParts({ body: '' }, signature);

  expect(resolved.mimeType).toBe('multipart/alternative');
  expect(resolved.text).toBe(signature.text);
  expect(resolved.html).toBe(
   `<div class="${SIGNATURE_MARKER}" data-smartmail="${SIGNATURE_MARKER}">${signature.html}</div>`,
  );

  const raw = createEmailMessage({ to: ['a@example.com'], subject: 'S', body: '' }, signature);
  expect(getHeader(raw, 'Content-Type')).toMatch(/^multipart\/alternative; boundary=/);
  expect(raw).toContain('Content-Type: text/plain; charset=UTF-8');
  expect(raw).toContain('Content-Type: text/html; charset=UTF-8');
 });

 it('changes nothing when signature parts are empty strings', () => {
  const emptySignature: SignatureParts = { text: '', html: '' };
  const baseArgs = { body: 'Hello world' };
  const resolved = resolveBodyParts(baseArgs, emptySignature);
  const unsigned = resolveBodyParts(baseArgs);

  expect(resolved).toEqual(unsigned);

  const rawEmpty = createEmailMessage({ to: ['a@example.com'], subject: 'S', body: 'Hello world' }, emptySignature);
  const rawUnsigned = createEmailMessage({ to: ['a@example.com'], subject: 'S', body: 'Hello world' });
  const stripBoundary = (s: string) => s.replace(/----=_NextPart_[a-z0-9]+/g, 'BOUNDARY');
  expect(stripBoundary(rawEmpty)).toBe(stripBoundary(rawUnsigned));
 });
});

describe('Source verification', () => {
 it('createEmailWithNodemailer uses references field with inReplyTo fallback', () => {
  const source = fs.readFileSync(path.join(srcDir, 'utl.ts'), 'utf-8');
  expect(source).toContain('references: validatedArgs.references || validatedArgs.inReplyTo');
 });

 it('handleEmailAction auto-resolves threading headers', () => {
  const source = fs.readFileSync(path.join(srcDir, 'index.ts'), 'utf-8');
  expect(source).toContain('validatedArgs.threadId && !validatedArgs.inReplyTo');
  expect(source).toContain('gmail.users.threads.get');
  expect(source).toContain('validatedArgs.inReplyTo = lastMessageId');
  expect(source).toContain("validatedArgs.references = allMessageIds.join(' ')");
 });

 it('read_email returns Message-ID', () => {
  const source = fs.readFileSync(path.join(srcDir, 'index.ts'), 'utf-8');
  expect(source).toContain('message-id');
  expect(source).toContain('rfcMessageId');
  expect(source).toContain('Message-ID: ${rfcMessageId}');
 });
});
