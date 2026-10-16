/**
 * Tests for attachment input handling.
 *
 * The server is deployed as a remote HTTP endpoint, so a caller has no path on
 * this machine to name. Attachments therefore accept the bytes inline, and the
 * path form remains only for a local stdio deployment.
 */

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { resolveAttachments, createEmailWithNodemailer } from './utl.js';
import { SendEmailSchema, UpdateDraftSchema, ReplyAllSchema } from './tools.js';
import { assertAttachmentsSafe, type DraftSnapshot } from './draft-manager.js';

const HELLO_B64 = Buffer.from('hello world').toString('base64');

describe('resolveAttachments', () => {
 it('accepts inline base64 and decodes it to the original bytes', () => {
  const [attachment] = resolveAttachments([
   { filename: 'note.txt', content: HELLO_B64 },
  ]);

  expect(attachment.filename).toBe('note.txt');
  expect('content' in attachment && attachment.content.toString('utf-8')).toBe('hello world');
 });

 it('infers the content type from the filename when mimeType is omitted', () => {
  const [attachment] = resolveAttachments([{ filename: 'report.pdf', content: HELLO_B64 }]);
  expect('contentType' in attachment && attachment.contentType).toBe('application/pdf');
 });

 it('honours an explicit mimeType over the inferred one', () => {
  const [attachment] = resolveAttachments([
   { filename: 'report.pdf', content: HELLO_B64, mimeType: 'application/octet-stream' },
  ]);
  expect('contentType' in attachment && attachment.contentType).toBe('application/octet-stream');
 });

 it('falls back to application/octet-stream for an unrecognised extension', () => {
  const [attachment] = resolveAttachments([{ filename: 'blob.zzz', content: HELLO_B64 }]);
  expect('contentType' in attachment && attachment.contentType).toBe('application/octet-stream');
 });

 it('tolerates the line breaks base64 encoders emit', () => {
  const wrapped = HELLO_B64.slice(0, 4) + '\n' + HELLO_B64.slice(4);
  const [attachment] = resolveAttachments([{ filename: 'note.txt', content: wrapped }]);
  expect('content' in attachment && attachment.content.toString('utf-8')).toBe('hello world');
 });

 // Buffer.from silently drops what it cannot decode, so an unvalidated
 // payload would reach the recipient truncated or empty rather than failing
 // where the caller can see it.
 it('rejects content that is not valid base64', () => {
  expect(() => resolveAttachments([{ filename: 'note.txt', content: 'not base64!!' }]))
   .toThrow(/not valid base64/);
 });

 it('rejects empty content', () => {
  expect(() => resolveAttachments([{ filename: 'note.txt', content: '' }]))
   .toThrow(/empty content/);
 });

 it('rejects an inline attachment with no filename', () => {
  expect(() => resolveAttachments([{ filename: '', content: HELLO_B64 }]))
   .toThrow(/no filename/);
 });

 it('names the missing file and points at the inline form when a path does not exist', () => {
  expect(() => resolveAttachments(['/nonexistent/report.pdf']))
   .toThrow(/\/nonexistent\/report\.pdf.*inline/s);
 });

 it('still accepts a path that exists on this machine', () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'attach-')), 'local.txt');
  fs.writeFileSync(file, 'on disk');

  const [attachment] = resolveAttachments([file]);
  expect(attachment.filename).toBe('local.txt');
  expect('path' in attachment && attachment.path).toBe(file);
 });

 it('treats no attachments as none', () => {
  expect(resolveAttachments()).toEqual([]);
  expect(resolveAttachments([])).toEqual([]);
 });
});

describe('createEmailWithNodemailer with inline attachments', () => {
 it('embeds the decoded bytes in the MIME message', async () => {
  const raw = await createEmailWithNodemailer({
   to: ['someone@example.com'],
   subject: 'With a file',
   body: 'See attached.',
   attachments: [{ filename: 'note.txt', content: HELLO_B64 }],
  });

  expect(raw).toMatch(/Content-Disposition: attachment; filename="?note\.txt"?/);
  // The part carries the same bytes, however nodemailer chose to encode it.
  const parts = raw.split(/\r?\n\r?\n/);
  const decoded = parts.map(p => Buffer.from(p.replace(/\s+/g, ''), 'base64').toString('utf-8'));
  expect(decoded.some(d => d.includes('hello world'))).toBe(true);
 });
});

describe('attachment schemas', () => {
 const base = { to: ['a@example.com'], subject: 'S', body: 'B' };

 for (const [name, schema] of [
  ['send_email', SendEmailSchema],
  ['reply_all', ReplyAllSchema],
 ] as const) {
  it(`${name} accepts both the inline and the path form`, () => {
   const args = {
    ...base,
    messageId: 'm1',
    attachments: [{ filename: 'a.txt', content: HELLO_B64 }, '/tmp/b.txt'],
   };
   expect(schema.parse(args).attachments).toHaveLength(2);
  });
 }

 it('update_draft accepts the inline form', () => {
  const parsed = UpdateDraftSchema.parse({
   draftId: 'd1',
   baseToken: 'v1:m:h',
   attachments: [{ filename: 'a.txt', content: HELLO_B64 }],
  });
  expect(parsed.attachments).toHaveLength(1);
 });

 it('rejects an inline attachment missing its content', () => {
  expect(() => SendEmailSchema.parse({ ...base, attachments: [{ filename: 'a.txt' }] })).toThrow();
 });
});

describe('draft attachment guard with inline re-supply', () => {
 const withAttachment = {
  draftId: 'd1',
  messageId: 'm1',
  historyId: 'h1',
  token: 'v1:m1:h1',
  threadId: null,
  to: ['a@example.com'],
  cc: [],
  bcc: [],
  subject: 'S',
  text: 'b',
  html: '<p>b</p>',
  attachments: [{ filename: 'contract.pdf', mimeType: 'application/pdf', size: 2048 }],
 } as unknown as DraftSnapshot;

 it('accepts inline bytes as a re-supply', () => {
  expect(() => assertAttachmentsSafe(withAttachment, {
   attachments: [{ filename: 'contract.pdf', content: HELLO_B64 }],
  })).not.toThrow();
 });

 it('tells the caller the inline form exists when refusing', () => {
  expect(() => assertAttachmentsSafe(withAttachment, { subject: 'x' }))
   .toThrow(/inline base64/);
 });
});
