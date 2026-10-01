// How download_attachment and download_email hand a file to the caller.
//
// The hosted server never touches its own filesystem on a caller's behalf: a
// path it writes is a path the caller cannot read, and every such write leaves
// someone's mail on the instance. So the bytes travel in the tool result:
// images as an MCP image block a client can look at, everything else as an
// embedded resource. Writing to disk survives only in the local stdio server,
// where the server's filesystem is the caller's own.

import fs from 'fs';
import path from 'path';
import type { GmailClient } from './session.js';

/**
 * Largest file returned inline, in bytes (before base64).
 *
 * Measured, not assumed: the deployed service answers over a chunked
 * text/event-stream, so Cloud Run's 32 MiB cap on non-streamed HTTP/1
 * responses does not apply. What binds is the 512 MiB instance: serving a file
 * holds Gmail's base64url text, the decoded bytes, the base64 copy and the
 * serialized JSON-RPC frame at once. See README "Downloading attachments and
 * emails" for the measurement.
 */
export const MAX_INLINE_BYTES = 25 * 1024 * 1024;

/**
 * Raster formats that MCP clients render as images. Anything else under
 * image/* (SVG, TIFF, HEIC, ...) is returned as a resource, because a client
 * handed an image block it cannot decode fails the whole result.
 */
const IMAGE_BLOCK_MIME_TYPES: Record<string, true> = {
 'image/png': true,
 'image/jpeg': true,
 'image/gif': true,
 'image/webp': true,
};

/**
 * Largest base64 image sent as an image block. Model APIs reject larger
 * images outright (Anthropic: 5 MB), which breaks the caller's conversation
 * rather than just this result, so a bigger image goes back as a resource.
 */
const MAX_IMAGE_BLOCK_BASE64 = 5 * 1024 * 1024;

export type DeliveryContext = {
 /** Mailbox the file came from, as shown to the caller. */
 account: string;
 /** True only for the local stdio server. */
 localFilesystem: boolean;
};

export type TextBlock = { type: 'text'; text: string };
export type ImageBlock = { type: 'image'; data: string; mimeType: string };
export type ResourceBlock = {
 type: 'resource';
 resource: { uri: string; mimeType: string; blob: string } | { uri: string; mimeType: string; text: string };
};
export type ToolResult = { content: Array<TextBlock | ImageBlock | ResourceBlock>; isError?: boolean };

/** The slice of a Gmail MessagePart this module reads. */
export type MessagePart = {
 partId?: string | null;
 filename?: string | null;
 mimeType?: string | null;
 body?: { attachmentId?: string | null; size?: number | null } | null;
 parts?: MessagePart[] | null;
};

function messageOf(error: unknown): string {
 return error instanceof Error ? error.message : String(error);
}

/** A file-bearing MIME part, as the message itself describes it. */
export type AttachmentPart = {
 partId: string;
 filename: string;
 mimeType: string;
 size: number;
 attachmentId: string;
};

function errorResult(text: string): ToolResult {
 return { content: [{ type: 'text', text }], isError: true };
}

function tooLarge(what: string, size: number): ToolResult {
 return errorResult(
  `${what} is ${size} bytes, over the ${MAX_INLINE_BYTES}-byte limit for files this server returns inline. ` +
  `It was not returned. Open it in Gmail instead.`,
 );
}

/** Every part of a message that carries an attachment body. */
export function listAttachmentParts(payload: MessagePart | null | undefined): AttachmentPart[] {
 const parts: AttachmentPart[] = [];
 const walk = (part: MessagePart | null | undefined) => {
  if (!part) return;
  if (part.body?.attachmentId) {
   parts.push({
    partId: part.partId ?? '',
    filename: part.filename || `attachment-${part.partId ?? 'unknown'}`,
    mimeType: (part.mimeType || 'application/octet-stream').toLowerCase(),
    size: part.body.size ?? 0,
    attachmentId: part.body.attachmentId,
   });
  }
  for (const sub of part.parts ?? []) walk(sub);
 };
 walk(payload);
 return parts;
}

async function fetchAttachmentBytes(gmail: GmailClient, messageId: string, attachmentId: string): Promise<Buffer> {
 const res = await gmail.users.messages.attachments.get({ userId: 'me', messageId, id: attachmentId });
 if (!res.data?.data) throw new Error('No attachment data received');
 return Buffer.from(res.data.data, 'base64url');
}

/**
 * Find the part an attachment id refers to.
 *
 * Gmail mints a fresh attachmentId every time it serves a message, so the id a
 * caller got from read_email rarely matches the one on a later fetch. An exact
 * match is used when there is one; otherwise the part is the one whose size
 * matches the downloaded bytes, and when several parts share that size the
 * bytes themselves decide.
 */
export async function locateAttachmentPart(
 gmail: GmailClient,
 messageId: string,
 attachmentId: string,
 bytes: Buffer,
): Promise<AttachmentPart> {
 const message = await gmail.users.messages.get({ userId: 'me', id: messageId, format: 'full' });
 const parts = listAttachmentParts(message.data?.payload);

 const exact = parts.find(p => p.attachmentId === attachmentId);
 if (exact) return exact;

 const sameSize = parts.filter(p => p.size === bytes.length);
 if (sameSize.length === 1) return sameSize[0];
 for (const candidate of sameSize) {
  const candidateBytes = await fetchAttachmentBytes(gmail, messageId, candidate.attachmentId);
  if (candidateBytes.equals(bytes)) return candidate;
 }
 throw new Error(`Attachment ${attachmentId} does not belong to any part of message ${messageId}`);
}

function attachmentUri(account: string, messageId: string, part: AttachmentPart): string {
 return `gmail://${encodeURIComponent(account)}/messages/${encodeURIComponent(messageId)}` +
  `/attachments/${encodeURIComponent(part.partId)}/${encodeURIComponent(part.filename)}`;
}

/** The content block that carries a file: an image block when a client can render it, otherwise an embedded resource. */
export function fileBlock(bytes: Buffer, mimeType: string, uri: string): ImageBlock | ResourceBlock {
 const data = bytes.toString('base64');
 if (IMAGE_BLOCK_MIME_TYPES[mimeType] && data.length <= MAX_IMAGE_BLOCK_BASE64) {
  return { type: 'image', data, mimeType };
 }
 return { type: 'resource', resource: { uri, mimeType, blob: data } };
}

/** Write to the local caller's own disk (stdio only), keeping the file inside `dir`. */
function writeLocal(dir: string, filename: string, bytes: Buffer): string {
 const safeName = path.basename(filename);
 const resolvedDir = path.resolve(dir);
 const fullPath = path.resolve(resolvedDir, safeName);
 if (!fullPath.startsWith(resolvedDir + path.sep)) throw new Error('Invalid filename: path traversal detected');
 fs.mkdirSync(resolvedDir, { recursive: true });
 fs.writeFileSync(fullPath, bytes);
 return fullPath;
}

export type DownloadAttachmentArgs = {
 messageId: string;
 attachmentId: string;
 filename?: string;
 savePath?: string;
};

export async function downloadAttachment(
 gmail: GmailClient,
 args: DownloadAttachmentArgs,
 ctx: DeliveryContext,
): Promise<ToolResult> {
 let bytes: Buffer;
 let part: AttachmentPart;
 try {
  bytes = await fetchAttachmentBytes(gmail, args.messageId, args.attachmentId);
  part = await locateAttachmentPart(gmail, args.messageId, args.attachmentId, bytes);
 } catch (error) {
  return errorResult(`Failed to download attachment: ${messageOf(error)}`);
 }

 if (ctx.localFilesystem && args.savePath) {
  try {
   const fullPath = writeLocal(args.savePath, args.filename || part.filename, bytes);
   return {
    content: [{
     type: 'text',
     text: `Saved ${part.filename} (${bytes.length} bytes, ${part.mimeType}) to ${fullPath}`,
    }],
   };
  } catch (error) {
   return errorResult(`Failed to save attachment: ${messageOf(error)}`);
  }
 }

 if (bytes.length > MAX_INLINE_BYTES) return tooLarge(`Attachment "${part.filename}"`, bytes.length);

 const notes = [
  part.filename,
  `${bytes.length} bytes, ${part.mimeType}`,
  `Account: ${ctx.account}`,
 ];
 if (!ctx.localFilesystem && args.savePath) {
  notes.push('savePath ignored: the hosted server never writes files; the attachment is in this result.');
 }
 return {
  content: [
   { type: 'text', text: notes.join('\n') },
   fileBlock(bytes, part.mimeType, attachmentUri(ctx.account, args.messageId, part)),
  ],
 };
}

const EMAIL_FORMAT_MIME: Record<string, string> = {
 json: 'application/json',
 eml: 'message/rfc822',
 txt: 'text/plain',
 html: 'text/html',
};

export type EmailExport = {
 messageId: string;
 format: 'json' | 'eml' | 'txt' | 'html';
 /** The exported file. eml is the raw RFC 822 bytes; the others are UTF-8 text. */
 bytes: Buffer;
 /** Subject, sender, date and attachment list, reported alongside the file. */
 metadata: Record<string, unknown>;
};

export function deliverEmailExport(exp: EmailExport, ctx: DeliveryContext, savePath?: string): ToolResult {
 const filename = `${exp.messageId}.${exp.format}`;
 const mimeType = EMAIL_FORMAT_MIME[exp.format];

 if (ctx.localFilesystem && savePath) {
  try {
   const fullPath = writeLocal(savePath, filename, exp.bytes);
   const summary = { status: 'saved', path: fullPath, size: exp.bytes.length, ...exp.metadata };
   return { content: [{ type: 'text', text: JSON.stringify(summary, null, 2) }] };
  } catch (error) {
   return errorResult(`Failed to save email: ${messageOf(error)}`);
  }
 }

 if (exp.bytes.length > MAX_INLINE_BYTES) return tooLarge(`Email ${filename}`, exp.bytes.length);

 const summary: Record<string, unknown> = {
  filename,
  size: exp.bytes.length,
  mimeType,
  account: ctx.account,
  ...exp.metadata,
 };
 if (!ctx.localFilesystem && savePath) {
  summary.note = 'savePath ignored: the hosted server never writes files; the email is in this result.';
 }
 const uri = `gmail://${encodeURIComponent(ctx.account)}/messages/${encodeURIComponent(exp.messageId)}/export.${exp.format}`;
 // eml stays bytes: it can carry 8-bit parts that are not valid UTF-8.
 const resource = exp.format === 'eml'
  ? { uri, mimeType, blob: exp.bytes.toString('base64') }
  : { uri, mimeType, text: exp.bytes.toString('utf-8') };
 return {
  content: [
   { type: 'text', text: JSON.stringify(summary, null, 2) },
   { type: 'resource', resource },
  ],
 };
}
