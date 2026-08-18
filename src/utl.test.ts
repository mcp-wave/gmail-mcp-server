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
