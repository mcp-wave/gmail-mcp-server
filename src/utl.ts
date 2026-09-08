import fs from 'fs';
import path from 'path';
import { lookup as mimeLookup } from 'mime-types';
import nodemailer from 'nodemailer';
import { markdownToHtml } from './markdown.js';
import type { SignatureParts } from './signature.js';
import { wrapSignatureHtml, SIGNATURE_MARKER } from './signature.js';

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
 * Normalise a text or HTML block for tolerant suffix comparison.
 *
 * Replaces CRLF line endings with LF, strips trailing spaces from every
 * line, and trims leading and trailing whitespace from the whole string.
 */
function normalizeForComparison(str: string): string {
 return str
  .replace(/\r\n/g, '\n')
  .replace(/\r/g, '\n')
  .split('\n')
  .map(line => line.replace(/[ \t]+$/, ''))
  .join('\n')
  .trim();
}

/**
 * Append the text signature to an email body if not already present.
 *
 * Drafts read back from Gmail via read_draft contain whatever signature was
 * previously appended. If an agent modifies that draft and calls update_draft,
 * an unconditional append would duplicate the signature on every save.
 * Comparing the normalised suffix guarantees idempotence across the
 * read-modify-write cycle.
 */
function appendTextSignature(body: string, signature?: SignatureParts | null): string {
 if (!signature || !signature.text) {
  return body;
 }

 const normBody = normalizeForComparison(body);
 const normSig = normalizeForComparison(signature.text);

 if (normSig !== '' && normBody.endsWith(normSig)) {
  return body;
 }

 if (body.trim() === '') {
  return signature.text;
 }

 return `${body}\n\n${signature.text}`;
}

/**
 * Append the HTML signature to an email body if not already present.
 *
 * Checks for the signature marker class first, which catches any message
 * previously signed by this server or composed in Gmail's web UI. A fallback
 * suffix check catches raw HTML signatures inlined without the wrapper.
 */
function appendHtmlSignature(html: string, signature?: SignatureParts | null): string {
 if (!signature || !signature.html) {
  return html;
 }

 if (html.includes(SIGNATURE_MARKER)) {
  return html;
 }

 const normHtml = normalizeForComparison(html);
 const normSig = normalizeForComparison(signature.html);

 if (normSig !== '' && normHtml.endsWith(normSig)) {
  return html;
 }

 const wrapped = wrapSignatureHtml(signature.html);
 if (html.trim() === '') {
  return wrapped;
 }

 // Intervening div provides the visual gap Gmail's composer emits between body and signature
 return `${html}\n<div><br></div>\n${wrapped}`;
}

/**
 * Resolve the body parts of a message from the caller's `body` (Markdown),
 * optional `htmlBody` (verbatim HTML) and optional `mimeType` override.
 *
 * With no `mimeType`, the default is `multipart/alternative`: the raw Markdown
 * source as the text part and its rendered HTML as the HTML part.
 *
 * When an optional signature is provided, it is appended to the respective
 * parts before mimeType resolution.
 */
export function resolveBodyParts(
 args: { body?: string; htmlBody?: string; mimeType?: string },
 signature?: SignatureParts | null,
): ResolvedBody {
 const baseText = args.body ?? '';

 if (args.mimeType === 'text/plain') {
  return { mimeType: 'text/plain', text: appendTextSignature(baseText, signature) };
 }

 const baseHtml = args.htmlBody ?? markdownToHtml(baseText);

 if (args.mimeType === 'text/html') {
  return { mimeType: 'text/html', html: appendHtmlSignature(baseHtml, signature) };
 }

 // Default (mimeType omitted, or 'multipart/alternative'): both parts.
 const text = appendTextSignature(baseText, signature);
 const html = appendHtmlSignature(baseHtml, signature);

 // The mimeType decision happens after appending so an empty body with a
 // configured signature still gets an HTML part instead of collapsing to text/plain.
 if (html === '') {
  return { mimeType: 'text/plain', text };
 }
 return { mimeType: 'multipart/alternative', text, html };
}

export function createEmailMessage(validatedArgs: any, signature?: SignatureParts | null): string {
 const encodedSubject = encodeEmailHeader(sanitizeHeaderValue(validatedArgs.subject));
 // Resolve the body parts: Markdown-rendered HTML by default (see resolveBodyParts)
 const resolved = resolveBodyParts(validatedArgs, signature);
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


export async function createEmailWithNodemailer(validatedArgs: any, signature?: SignatureParts | null): Promise<string> {
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

 // Prepare attachments for nodemailer
 const attachments = [];
 for (const filePath of validatedArgs.attachments) {
  if (!fs.existsSync(filePath)) {
   throw new Error(`File does not exist: ${filePath}`);
  }

  const fileName = path.basename(filePath);

  attachments.push({
   filename: fileName,
   path: filePath
  });
 }

 // Resolve the body parts: Markdown-rendered HTML by default (see resolveBodyParts).
 // nodemailer omits a part entirely when its field is undefined, which is how
 // text/plain-only and text/html-only stay single-part here.
 const resolved = resolveBodyParts(validatedArgs, signature);

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

