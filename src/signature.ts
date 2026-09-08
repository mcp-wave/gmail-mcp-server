/**
 * Signature resolution and HTML-to-text conversion for outgoing mail.
 *
 * Gmail stores signatures on per-user send-as aliases (users.settings.sendAs)
 * as HTML fragments. When an email is composed or updated, the signature
 * must be appended to both HTML and plain-text body representations.
 *
 * This module provides:
 * 1. resolveSignature: fetches and caches alias signatures for an account,
 *    selecting the right alias based on the From address.
 * 2. signatureHtmlToText: converts the stored HTML signature into a clean,
 *    readable plain-text version for text/plain parts.
 * 3. wrapSignatureHtml: wraps HTML in Gmail's canonical signature container.
 * 4. invalidateSignatureCache: clears cached alias signatures on updates.
 */

import type { gmail_v1 } from 'googleapis';
import { failureReason } from './settings-manager.js';
import { emailAddressOf } from './send-policy.js';

/** A signature in both representations an email body needs. */
export interface SignatureParts {
 /** The HTML fragment Gmail has stored on the send-as alias. */
 html: string;
 /** A plain-text rendering of that HTML, for the text/plain part. */
 text: string;
}

export type SignatureResolution =
 | { status: 'ok'; sendAsEmail: string; parts: SignatureParts | null }
 | { status: 'unavailable'; reason: string };

/** Gmail's own composer class, so mail clients recognise and collapse the block. */
export const SIGNATURE_MARKER = 'gmail_signature';

/**
 * Wraps an HTML signature fragment in Gmail's canonical signature container.
 * Gmail web uses this class and attribute so the recipient's webmail can
 * identify, style, or collapse the signature block automatically.
 */
export function wrapSignatureHtml(html: string): string {
 return `<div class="${SIGNATURE_MARKER}" data-smartmail="${SIGNATURE_MARKER}">${html}</div>`;
}

/**
 * Decodes standard HTML entities and numeric character references.
 *
 * Handles named entities (&nbsp;, &amp;, &lt;, &gt;, &quot;, &apos;),
 * decimal references (&#NN; including &#39;), and hex references (&#xNN;).
 * Uses a single regular expression to avoid double-decoding risks.
 */
function decodeHtmlEntities(text: string): string {
 return text.replace(/&(?:(nbsp|amp|lt|gt|quot|apos)|#([0-9]+)|#x([0-9a-f]+));/gi, (match, named, dec, hex) => {
  if (named) {
   switch (named.toLowerCase()) {
    case 'nbsp': return ' ';
    case 'amp': return '&';
    case 'lt': return '<';
    case 'gt': return '>';
    case 'quot': return '"';
    case 'apos': return "'";
   }
  }
  if (dec) {
   try {
    const code = parseInt(dec, 10);
    return code === 160 ? ' ' : String.fromCodePoint(code);
   } catch {
    return match;
   }
  }
  if (hex) {
   try {
    const code = parseInt(hex, 16);
    return code === 160 ? ' ' : String.fromCodePoint(code);
   } catch {
    return match;
   }
  }
  return match;
 });
}

/**
 * Converts a Gmail HTML signature fragment into readable plain text.
 *
 * Preserves essential structure (paragraphs, line breaks, list separation)
 * while dropping non-text elements (scripts, styles, images) and formatting
 * hyperlinks so the reader retains the target destination.
 */
export function signatureHtmlToText(html: string): string {
 if (!html) return '';

 let text = html;

 // 1. Drop style and script elements completely, including contents.
 text = text.replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, '');
 text = text.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '');

 // 2. Drop img tags completely without emitting alt text.
 text = text.replace(/<img\b[^>]*>/gi, '');

 // 3. Replace <br>, <br/>, <br /> with a single newline.
 text = text.replace(/<br\s*\/?>/gi, '\n');

 // 4. Closing block tags become a newline: p, div, li, ul, ol, tr, table, blockquote, h1-h6.
 text = text.replace(/<\/(?:p|div|li|ul|ol|tr|table|blockquote|h[1-6])>/gi, '\n');

 // 5. Transform anchor tags: <a href="URL">TEXT</a>
 // If TEXT already contains the URL, or href is mailto:/tel: matching TEXT, keep TEXT.
 // Otherwise append the URL in parentheses so text readers do not lose the link target.
 text = text.replace(/<a\b([^>]*)>([\s\S]*?)<\/a>/gi, (_match, attrs, inner) => {
  const hrefMatch = attrs.match(/\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
  const href = (hrefMatch ? (hrefMatch[1] ?? hrefMatch[2] ?? hrefMatch[3] ?? '') : '').trim();
  if (!href) {
   return inner;
  }

  const cleanHref = href.trim();
  const textOnly = inner.replace(/<[^>]+>/g, '').trim();

  let target: string | null = null;
  if (cleanHref.toLowerCase().startsWith('mailto:')) {
   const raw = cleanHref.slice(7).trim();
   const q = raw.indexOf('?');
   target = q >= 0 ? raw.slice(0, q).trim() : raw;
  } else if (cleanHref.toLowerCase().startsWith('tel:')) {
   target = cleanHref.slice(4).trim();
  }

  const targetEqualsText = target !== null && (
   target.toLowerCase() === textOnly.toLowerCase() ||
   target.toLowerCase() === inner.trim().toLowerCase()
  );

  const textContainsUrl = inner.includes(cleanHref) || textOnly.includes(cleanHref);

  if (textContainsUrl || targetEqualsText) {
   return inner;
  }

  return `${inner} (${cleanHref})`;
 });

 // 6. Strip all remaining HTML tags.
 text = text.replace(/<[^>]+>/g, '');

 // 7. Decode HTML entities and numeric references.
 text = decodeHtmlEntities(text);

 // 8. Strip trailing whitespace per line, collapse 3+ newlines to 2, and trim.
 return text
  .split('\n')
  .map(line => line.trimEnd())
  .join('\n')
  .replace(/\n{3,}/g, '\n\n')
  .trim();
}

/** Reduced alias row cached in memory. */
interface CachedSendAs {
 sendAsEmail: string;
 signature: string | null;
 isDefault: boolean;
 isPrimary: boolean;
}

interface CacheEntry {
 expiresAt: number;
 aliases: CachedSendAs[];
}

/** In-memory cache of send-as aliases per account key, with a 5 minute TTL. */
const signatureCache = new Map<string, CacheEntry>();
const CACHE_TTL_MS = 5 * 60 * 1000;

/**
 * Invalidates the cached send-as alias signatures.
 * Pass accountKey to invalidate a single account, or omit to clear the entire cache.
 */
export function invalidateSignatureCache(accountKey?: string): void {
 if (accountKey) {
  signatureCache.delete(accountKey);
 } else {
  signatureCache.clear();
 }
}

/**
 * Resolves the signature configured for an account's sending identity.
 *
 * Looks up the account's send-as aliases via users.settings.sendAs.list,
 * caching results for 5 minutes per accountKey. If from is specified,
 * selects the matching alias; otherwise picks the default alias.
 *
 * Never throws for API failures: returns status 'unavailable' instead,
 * so outgoing mail can still proceed unsigned if the settings read fails.
 */
export async function resolveSignature(
 gmail: gmail_v1.Gmail,
 accountKey: string,
 from?: string,
): Promise<SignatureResolution> {
 const now = Date.now();
 const cached = signatureCache.get(accountKey);
 let aliases: CachedSendAs[];

 if (cached && cached.expiresAt > now) {
  aliases = cached.aliases;
 } else {
  try {
   const response = await gmail.users.settings.sendAs.list({ userId: 'me' });
   const rawList = response.data.sendAs ?? [];
   aliases = rawList.map(a => ({
    sendAsEmail: a.sendAsEmail ?? '',
    signature: a.signature ?? null,
    isDefault: Boolean(a.isDefault),
    isPrimary: Boolean(a.isPrimary),
   }));
   signatureCache.set(accountKey, {
    expiresAt: now + CACHE_TTL_MS,
    aliases,
   });
  } catch (error: unknown) {
   return { status: 'unavailable', reason: failureReason(error) };
  }
 }

 if (aliases.length === 0) {
  return { status: 'unavailable', reason: 'This account has no send-as addresses.' };
 }

 const reducedFrom = from ? emailAddressOf(from) : '';
 const isFromSpecified = Boolean(reducedFrom && reducedFrom.includes('@'));

 let chosen: CachedSendAs | undefined;

 if (isFromSpecified) {
  chosen = aliases.find(a => a.sendAsEmail.toLowerCase() === reducedFrom);
  if (!chosen) {
   const known = aliases.map(a => a.sendAsEmail).filter(Boolean).join(', ');
   return {
    status: 'unavailable',
    reason: `"${from}" is not a send-as address on this account. Available: ${known}`,
   };
  }
 } else {
  // Precedence: default alias, then primary, then first in list
  chosen = aliases.find(a => a.isDefault) ?? aliases.find(a => a.isPrimary) ?? aliases[0];
  if (!chosen || !chosen.sendAsEmail) {
   return { status: 'unavailable', reason: 'Could not determine a send-as address for this account.' };
  }
 }

 const rawSig = chosen.signature;
 if (!rawSig || rawSig.trim() === '') {
  return {
   status: 'ok',
   sendAsEmail: chosen.sendAsEmail,
   parts: null,
  };
 }

 return {
  status: 'ok',
  sendAsEmail: chosen.sendAsEmail,
  parts: {
   html: rawSig,
   text: signatureHtmlToText(rawSig),
  },
 };
}
