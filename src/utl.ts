import fs from 'fs';
import path from 'path';
import { lookup as mimeLookup } from 'mime-types';
import nodemailer from 'nodemailer';
import { markdownToHtml } from './markdown.js';

/**
 * Helper function to encode email headers containing non-ASCII characters
 * according to RFC 2047 MIME specification
 */
function encodeEmailHeader(text: string): string {
 // Only encode if the text contains non-ASCII characters
 if (/[^\x00-\x7F]/.test(text)) {
  // Use MIME Words encoding (RFC 2047)
  return '=?UTF-8?B?' + Buffer.from(text).toString('base64') + '?=';
 }
 return text;
}

export const validateEmail = (email: string): boolean => {
 const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
 return emailRegex.test(email);
};

/**
 * Sanitize a value destined for an email header to prevent CRLF injection.
 * Strips \r, \n, and \0 characters that could inject additional headers.
 */
function sanitizeHeaderValue(value: string): string {
 return value.replace(/[\r\n\0]/g, '');
}

export type EmailMimeType = 'text/plain' | 'text/html' | 'multipart/alternative';

export interface ResolvedBody {
 mimeType: EmailMimeType;
 text?: string;
 html?: string;
}

/**
 * Resolve the body parts of a message from the caller's `body` (Markdown),
 * optional `htmlBody` (verbatim HTML) and optional `mimeType` override.
 *
 * With no `mimeType`, the default is `multipart/alternative`: the raw Markdown
 * source as the text part and its rendered HTML as the HTML part.
 */
export function resolveBodyParts(args: { body?: string; htmlBody?: string; mimeType?: string }): ResolvedBody {
 const text = args.body ?? '';

 if (args.mimeType === 'text/plain') {
  return { mimeType: 'text/plain', text };
 }

 const html = args.htmlBody ?? markdownToHtml(text);

 if (args.mimeType === 'text/html') {
  return { mimeType: 'text/html', html };
 }

 // Default (mimeType omitted, or 'multipart/alternative'): both parts.
 // A blank body with no htmlBody yields no HTML at all -- send a single plain part
 // rather than a multipart message with an empty HTML half.
 if (html === '') {
  return { mimeType: 'text/plain', text };
 }
 return { mimeType: 'multipart/alternative', text, html };
}

export function createEmailMessage(validatedArgs: any): string {
 const encodedSubject = encodeEmailHeader(sanitizeHeaderValue(validatedArgs.subject));
 // Resolve the body parts: Markdown-rendered HTML by default (see resolveBodyParts)
 const resolved = resolveBodyParts(validatedArgs);
 const mimeType = resolved.mimeType;

 // Generate a random boundary string for multipart messages
 const boundary = `----=_NextPart_${Math.random().toString(36).substring(2)}`;

 // Validate email addresses
 (validatedArgs.to as string[]).forEach(email => {
  if (!validateEmail(email)) {
   throw new Error(`Recipient email address is invalid: ${email}`);
  }
 });

 // Sanitize all user-supplied header values to prevent CRLF injection
 const from = sanitizeHeaderValue(validatedArgs.from || 'me');
 const to = (validatedArgs.to as string[]).map(sanitizeHeaderValue).join(', ');
 const cc = validatedArgs.cc ? (validatedArgs.cc as string[]).map(sanitizeHeaderValue).join(', ') : '';
 const bcc = validatedArgs.bcc ? (validatedArgs.bcc as string[]).map(sanitizeHeaderValue).join(', ') : '';
 const inReplyTo = validatedArgs.inReplyTo ? sanitizeHeaderValue(validatedArgs.inReplyTo) : '';
 const references = validatedArgs.references
  ? sanitizeHeaderValue(validatedArgs.references)
  : validatedArgs.inReplyTo ? sanitizeHeaderValue(validatedArgs.inReplyTo) : '';

 // Common email headers
 const emailParts = [
  `From: ${from}`,
  `To: ${to}`,
  cc ? `Cc: ${cc}` : '',
  bcc ? `Bcc: ${bcc}` : '',
  `Subject: ${encodedSubject}`,
  inReplyTo ? `In-Reply-To: ${inReplyTo}` : '',
  references ? `References: ${references}` : '',
  'MIME-Version: 1.0',
 ].filter(Boolean);

 // Construct the email based on the content type
 if (mimeType === 'multipart/alternative') {
  // Multipart email with both plain text and HTML
  emailParts.push(`Content-Type: multipart/alternative; boundary="${boundary}"`);
  emailParts.push('');

  // Plain text part
  emailParts.push(`--${boundary}`);
  emailParts.push('Content-Type: text/plain; charset=UTF-8');
  emailParts.push('Content-Transfer-Encoding: 7bit');
  emailParts.push('');
  emailParts.push(resolved.text ?? '');
  emailParts.push('');

  // HTML part
  emailParts.push(`--${boundary}`);
  emailParts.push('Content-Type: text/html; charset=UTF-8');
  emailParts.push('Content-Transfer-Encoding: 7bit');
  emailParts.push('');
  emailParts.push(resolved.html ?? '');
  emailParts.push('');

  // Close the boundary
  emailParts.push(`--${boundary}--`);
 } else if (mimeType === 'text/html') {
  // HTML-only email
  emailParts.push('Content-Type: text/html; charset=UTF-8');
  emailParts.push('Content-Transfer-Encoding: 7bit');
  emailParts.push('');
  emailParts.push(resolved.html ?? '');
 } else {
  // Plain-text-only email (explicit mimeType: 'text/plain', or an empty body)
  emailParts.push('Content-Type: text/plain; charset=UTF-8');
  emailParts.push('Content-Transfer-Encoding: 7bit');
  emailParts.push('');
  emailParts.push(resolved.text ?? '');
 }

 return emailParts.join('\r\n');
}


/**
 * An attachment as a caller supplies it: a path on this machine, or the bytes
 * inline. Remote callers have no path on this machine to name, so inline is
 * the only form available to them.
 */
export type AttachmentInput = string | { filename: string; content: string; mimeType?: string };

/** What nodemailer needs: a path to read, or a buffer to embed. */
type NodemailerAttachment =
 | { filename: string; path: string }
 | { filename: string; content: Buffer; contentType: string };

/**
 * Turn caller-supplied attachments into nodemailer attachments.
 *
 * Base64 is validated rather than handed straight to Buffer.from, which
 * silently discards anything it cannot decode: a mangled payload would
 * otherwise become a truncated or empty file the recipient discovers, instead
 * of an error the caller does.
 */
export function resolveAttachments(inputs: AttachmentInput[] = []): NodemailerAttachment[] {
 return inputs.map((input, index) => {
  if (typeof input === 'string') {
   if (!fs.existsSync(input)) {
    throw new Error(
     `File does not exist: ${input}. A file path is only resolvable when this server runs on the same machine as the caller; ` +
     `otherwise supply the bytes inline as {"filename": ..., "content": <base64>}.`,
    );
   }
   return { filename: path.basename(input), path: input };
  }

  if (!input.filename) throw new Error(`Attachment ${index + 1} has no filename.`);
  const label = `"${input.filename}"`;

  const base64 = (input.content ?? '').replace(/\s+/g, '');
  if (!base64) throw new Error(`Attachment ${label} has empty content.`);
  if (base64.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(base64)) {
   throw new Error(`Attachment ${label} has content that is not valid base64.`);
  }

  const content = Buffer.from(base64, 'base64');
  if (content.length === 0) throw new Error(`Attachment ${label} decodes to zero bytes.`);

  return {
   filename: input.filename,
   content,
   contentType: input.mimeType || mimeLookup(input.filename) || 'application/octet-stream',
  };
 });
}

export async function createEmailWithNodemailer(validatedArgs: any): Promise<string> {
 // Validate email addresses
 (validatedArgs.to as string[]).forEach(email => {
  if (!validateEmail(email)) {
   throw new Error(`Recipient email address is invalid: ${email}`);
  }
 });

 // Create a nodemailer transporter (we won't actually send, just generate the message)
 const transporter = nodemailer.createTransport({
  streamTransport: true,
  newline: 'unix',
  buffer: true
 });

 const attachments = resolveAttachments(validatedArgs.attachments);

 // Resolve the body parts: Markdown-rendered HTML by default (see resolveBodyParts).
 // nodemailer omits a part entirely when its field is undefined, which is how
 // text/plain-only and text/html-only stay single-part here.
 const resolved = resolveBodyParts(validatedArgs);

 const mailOptions = {
  from: validatedArgs.from || 'me', // Gmail API uses default send-as if 'me', or specified alias
  to: validatedArgs.to.join(', '),
  cc: validatedArgs.cc?.join(', '),
  bcc: validatedArgs.bcc?.join(', '),
  subject: validatedArgs.subject,
  text: resolved.text,
  html: resolved.html,
  attachments: attachments,
  inReplyTo: validatedArgs.inReplyTo,
  references: validatedArgs.references || validatedArgs.inReplyTo
 };

 // Generate the raw message
 const info = await transporter.sendMail(mailOptions);
 const rawMessage = info.message.toString();

 return rawMessage;
}

