/**
 * Tests for the mailbox settings tools (users.settings.*)
 *
 * The load-bearing property is in `readAllSettings` / `formatSettingsSnapshot`:
 * a section this account cannot read must never render as an empty list or a
 * disabled setting. "No delegates" and "not allowed to ask about delegates" are
 * different answers and only one of them is safe to act on.
 */

import { describe, it, expect } from 'vitest';
import {
 readAllSettings,
 formatSettingsSnapshot,
 resolveSendAsAddress,
 setSignature,
 updateSendAs,
 setVacationResponder,
 buildVacationSettings,
 ignoredFields,
 toEpochMillis,
 failureReason,
} from './settings-manager.js';
import { toolDefinitions, getToolByName } from './tools.js';
import { hasScope } from './scopes.js';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const srcDir = path.dirname(fileURLToPath(import.meta.url));

/** A Gmail API error shaped the way googleapis surfaces one. */
function apiError(code: number, message: string) {
 return Object.assign(new Error(message), { code, errors: [{ message }] });
}

interface StubOptions {
 sendAs?: unknown[];
 vacation?: Record<string, unknown>;
 autoForwarding?: Record<string, unknown>;
 forwardingAddresses?: unknown[];
 delegates?: unknown[];
 imap?: Record<string, unknown>;
 pop?: Record<string, unknown>;
 language?: Record<string, unknown>;
 /** Section name to reject, mapped to the error it throws. */
 failures?: Record<string, Error>;
 /** Captures patch/update request bodies. */
 calls?: Record<string, unknown>;
 /** Overrides what sendAs.patch echoes back. */
 patchResponse?: Record<string, unknown>;
}

/**
 * Minimal stand-in for the Gmail client covering only `users.settings`.
 * Typed as the real client at the call site, so drift in the methods under test
 * still fails the typecheck.
 */
function stubGmail(options: StubOptions = {}) {
 const fail = (key: string) => {
  const error = options.failures?.[key];
  if (error) throw error;
 };
 const calls = options.calls ?? {};

 return {
  users: {
   settings: {
    sendAs: {
     list: async () => {
      fail('sendAs');
      return { data: { sendAs: options.sendAs ?? [] } };
     },
     patch: async (params: { sendAsEmail: string; requestBody: Record<string, unknown> }) => {
      fail('patch');
      calls.patch = params;
      return {
       data: options.patchResponse ?? {
        sendAsEmail: params.sendAsEmail,
        ...params.requestBody,
       },
      };
     },
    },
    getVacation: async () => {
     fail('vacation');
     return { data: options.vacation ?? {} };
    },
    updateVacation: async (params: { requestBody: Record<string, unknown> }) => {
     calls.updateVacation = params;
     return { data: params.requestBody };
    },
    getAutoForwarding: async () => {
     fail('autoForwarding');
     return { data: options.autoForwarding ?? {} };
    },
    forwardingAddresses: {
     list: async () => {
      fail('forwardingAddresses');
      return { data: { forwardingAddresses: options.forwardingAddresses ?? [] } };
     },
    },
    delegates: {
     list: async () => {
      fail('delegates');
      return { data: { delegates: options.delegates ?? [] } };
     },
    },
    getImap: async () => {
     fail('imap');
     return { data: options.imap ?? {} };
    },
    getPop: async () => {
     fail('pop');
     return { data: options.pop ?? {} };
    },
    getLanguage: async () => {
     fail('language');
     return { data: options.language ?? {} };
    },
   },
  },
 } as unknown as Parameters<typeof readAllSettings>[0];
}

const primary = { sendAsEmail: 'me@example.com', isPrimary: true, isDefault: true };
const alias = { sendAsEmail: 'alias@example.com', isPrimary: false, isDefault: false };

describe('readAllSettings section isolation', () => {
 it('reports a denied section as failed instead of empty', async () => {
  const snapshot = await readAllSettings(stubGmail({
   failures: { delegates: apiError(403, 'Delegation is not supported for this account.') },
  }));

  expect(snapshot.delegates.status).toBe('failed');
  if (snapshot.delegates.status === 'failed') {
   expect(snapshot.delegates.reason).toContain('not permitted (403)');
  }
 });

 it('keeps other sections readable when one fails', async () => {
  const snapshot = await readAllSettings(stubGmail({
   vacation: { enableAutoReply: true, responseSubject: 'Away' },
   failures: { delegates: apiError(403, 'nope') },
  }));

  expect(snapshot.vacation.status).toBe('ok');
  expect(snapshot.delegates.status).toBe('failed');
 });

 it('distinguishes a genuinely empty section from a failed one', async () => {
  const snapshot = await readAllSettings(stubGmail({ delegates: [] }));

  expect(snapshot.delegates.status).toBe('ok');
  if (snapshot.delegates.status === 'ok') {
   expect(snapshot.delegates.value).toEqual([]);
  }
 });

 it('survives every section failing at once', async () => {
  const boom = apiError(500, 'backend error');
  const snapshot = await readAllSettings(stubGmail({
   failures: {
    sendAs: boom, vacation: boom, autoForwarding: boom, forwardingAddresses: boom,
    delegates: boom, imap: boom, pop: boom, language: boom,
   },
  }));

  for (const value of Object.values(snapshot)) {
   expect(value.status).toBe('failed');
  }
 });
});

describe('formatSettingsSnapshot never fabricates a value', () => {
 it('says a denied delegates read is unreadable, not "none"', async () => {
  const snapshot = await readAllSettings(stubGmail({
   failures: { delegates: apiError(403, 'Delegation is not supported.') },
  }));
  const text = formatSettingsSnapshot(snapshot);

  const delegatesSection = text.split('## Delegates')[1];
  expect(delegatesSection).toContain('Could not read this section');
  expect(delegatesSection).not.toContain('None configured');
 });

 it('does not claim forwarding is off when the read failed', async () => {
  const snapshot = await readAllSettings(stubGmail({
   failures: { autoForwarding: apiError(403, 'denied') },
  }));
  const text = formatSettingsSnapshot(snapshot);

  const section = text.split('## Auto-forwarding')[1].split('##')[0];
  expect(section).toContain('Could not read this section');
  expect(section).not.toContain('enabled: no');
 });

 it('reports forwarding that is genuinely enabled, with its destination', async () => {
  const snapshot = await readAllSettings(stubGmail({
   autoForwarding: { enabled: true, emailAddress: 'elsewhere@example.com', disposition: 'archive' },
  }));
  const text = formatSettingsSnapshot(snapshot);

  expect(text).toContain('enabled: yes');
  expect(text).toContain('elsewhere@example.com');
 });

 it('says "None configured" only when the read actually succeeded', async () => {
  const snapshot = await readAllSettings(stubGmail({ delegates: [] }));
  const delegatesSection = formatSettingsSnapshot(snapshot).split('## Delegates')[1];

  expect(delegatesSection).toContain('None configured');
 });

 it('emits the full signature html, not just a truncated preview', async () => {
  // Longer than the 120-char preview limit. set_signature overwrites, so
  // anything the reader cannot see is content it would destroy unseen.
  // This is the read half of read-before-write.
  const long =
   '<div>Jason Waldrip<br>Director of Technology<br>Phoneware, Inc.<br>' +
   '1506 W. Whispering Wind Drive, #130<br>Phoenix, AZ 85085<br>' +
   '<a href="https://phoneware.us">phoneware.us</a><br>f: 602-000-0000</div>';
  const snapshot = await readAllSettings(stubGmail({
   sendAs: [{ ...primary, signature: long }],
  }));
  const text = formatSettingsSnapshot(snapshot);

  expect(long.length).toBeGreaterThan(120);
  // The tail must survive: it is exactly what a preview cuts off.
  expect(text).toContain('f: 602-000-0000');
  expect(text).toContain('1506 W. Whispering Wind Drive');
  expect(text).toContain(long);
  expect(text).toContain('signature html:');
 });

 it('still reports an empty signature as (none) with no html block', async () => {
  const snapshot = await readAllSettings(stubGmail({ sendAs: [primary] }));
  const text = formatSettingsSnapshot(snapshot);

  expect(text).toContain('signature: (none)');
  expect(text).not.toContain('signature html:');
 });

 it('renders vacation times as readable timestamps', async () => {
  const snapshot = await readAllSettings(stubGmail({
   vacation: { enableAutoReply: true, responseSubject: 'Away', startTime: '1755000000000' },
  }));
  const text = formatSettingsSnapshot(snapshot);

  expect(text).toContain(new Date(1755000000000).toISOString());
 });

 it('strips markup from the preview line while keeping it in the html block', async () => {
  const snapshot = await readAllSettings(stubGmail({
   sendAs: [{ ...primary, signature: '<p>Jason <strong>Waldrip</strong></p>' }],
  }));
  const text = formatSettingsSnapshot(snapshot);
  const previewLine = text.split('\n').find(l => l.trim().startsWith('signature:'))!;

  // The skim line stays tag-free...
  expect(previewLine).toContain('Jason Waldrip');
  expect(previewLine).not.toContain('<strong>');
  // ...but the verbatim markup is available to a caller about to replace it.
  expect(text).toContain('<p>Jason <strong>Waldrip</strong></p>');
 });
});

describe('failureReason', () => {
 it('labels 403 as not permitted', () => {
  expect(failureReason(apiError(403, 'denied'))).toBe('not permitted (403): denied');
 });

 it('labels 401 as not authenticated', () => {
  expect(failureReason(apiError(401, 'expired'))).toBe('not authenticated (401): expired');
 });

 it('handles a thrown non-error without crashing', () => {
  expect(failureReason('something odd')).toBe('error: something odd');
 });
});

describe('resolveSendAsAddress', () => {
 it('defaults to the default From address', async () => {
  const gmail = stubGmail({ sendAs: [alias, primary] });
  expect(await resolveSendAsAddress(gmail)).toBe('me@example.com');
 });

 it('falls back to the primary address when none is marked default', async () => {
  const gmail = stubGmail({ sendAs: [alias, { ...primary, isDefault: false }] });
  expect(await resolveSendAsAddress(gmail)).toBe('me@example.com');
 });

 it('accepts an explicit address case-insensitively', async () => {
  const gmail = stubGmail({ sendAs: [primary, alias] });
  expect(await resolveSendAsAddress(gmail, 'ALIAS@example.com')).toBe('alias@example.com');
 });

 it('rejects an address that is not on the account', async () => {
  const gmail = stubGmail({ sendAs: [primary] });
  await expect(resolveSendAsAddress(gmail, 'typo@example.com')).rejects.toThrow(/not a send-as address/);
 });
});

describe('setSignature', () => {
 it('renders Markdown to HTML and patches the default address', async () => {
  const calls: Record<string, unknown> = {};
  const gmail = stubGmail({ sendAs: [primary], calls });

  const result = await setSignature(gmail, { signature: 'Jason **Waldrip**' });

  expect(result.sendAsEmail).toBe('me@example.com');
  expect(result.signature).toContain('<strong>Waldrip</strong>');
  const patch = calls.patch as { sendAsEmail: string; requestBody: { signature: string } };
  expect(patch.sendAsEmail).toBe('me@example.com');
  expect(patch.requestBody.signature).toContain('<strong>Waldrip</strong>');
 });

 it('uses an explicit signatureHtml verbatim', async () => {
  const gmail = stubGmail({ sendAs: [primary] });
  const result = await setSignature(gmail, { signatureHtml: '<p>hand written</p>' });

  expect(result.signature).toBe('<p>hand written</p>');
  expect(result.signature).not.toContain('<strong>');
 });

 it('patches only the signature, so other alias fields survive', async () => {
  const calls: Record<string, unknown> = {};
  const gmail = stubGmail({ sendAs: [primary], calls });
  await setSignature(gmail, { signature: 'sig' });

  const patch = calls.patch as { requestBody: Record<string, unknown> };
  expect(Object.keys(patch.requestBody)).toEqual(['signature']);
 });

 it('reports when Gmail sanitized the HTML it stored', async () => {
  const gmail = stubGmail({
   sendAs: [primary],
   patchResponse: { sendAsEmail: 'me@example.com', signature: '<p>cleaned</p>' },
  });
  const result = await setSignature(gmail, { signatureHtml: '<p onclick="x()">cleaned</p>' });

  expect(result.alteredByGmail).toBe(true);
  expect(result.storedSignature).toBe('<p>cleaned</p>');
 });

 it('clears the signature when given an empty string', async () => {
  const calls: Record<string, unknown> = {};
  const gmail = stubGmail({ sendAs: [primary], calls });
  await setSignature(gmail, { signature: '' });

  const patch = calls.patch as { requestBody: { signature: string } };
  expect(patch.requestBody.signature).toBe('');
 });

 it('refuses when neither signature nor signatureHtml is given', async () => {
  const gmail = stubGmail({ sendAs: [primary] });
  await expect(setSignature(gmail, {})).rejects.toThrow(/Provide "signature"/);
 });
});

describe('updateSendAs', () => {
 it('sends only the provided fields', async () => {
  const calls: Record<string, unknown> = {};
  const gmail = stubGmail({ sendAs: [primary], calls });
  await updateSendAs(gmail, { displayName: 'Jason' });

  const patch = calls.patch as { requestBody: Record<string, unknown> };
  expect(patch.requestBody).toEqual({ displayName: 'Jason' });
 });

 it('reports a field Gmail accepted but ignored', async () => {
  const gmail = stubGmail({
   sendAs: [primary],
   // Gmail echoes the resource unchanged when an admin blocks name changes.
   patchResponse: { sendAsEmail: 'me@example.com', displayName: 'Old Name' },
  });
  const result = await updateSendAs(gmail, { displayName: 'New Name' });

  expect(result.ignored).toEqual(['displayName']);
 });

 it('reports nothing ignored when Gmail applied the change', async () => {
  const gmail = stubGmail({ sendAs: [primary] });
  const result = await updateSendAs(gmail, { displayName: 'Jason' });

  expect(result.ignored).toEqual([]);
 });

 it('rejects makeDefault: false, which Gmail cannot express', async () => {
  const gmail = stubGmail({ sendAs: [primary] });
  await expect(
   updateSendAs(gmail, { makeDefault: false as unknown as true }),
  ).rejects.toThrow(/only accepts true/);
 });

 it('refuses an empty update', async () => {
  const gmail = stubGmail({ sendAs: [primary] });
  await expect(updateSendAs(gmail, {})).rejects.toThrow(/Nothing to update/);
 });
});

describe('ignoredFields', () => {
 it('treats an omitted field as a falsy value rather than a mismatch', () => {
  expect(ignoredFields({ displayName: '' }, { sendAsEmail: 'me@example.com' })).toEqual([]);
  expect(ignoredFields({ treatAsAlias: false }, { sendAsEmail: 'me@example.com' })).toEqual([]);
 });

 it('flags a value Gmail reports differently from the request', () => {
  expect(ignoredFields({ displayName: 'New' }, { displayName: 'Old' })).toEqual(['displayName']);
 });
});

describe('buildVacationSettings', () => {
 const base = { responseSubject: 'Existing', responseBodyHtml: '<p>existing</p>' };

 it('preserves existing fields it was not asked to change', () => {
  const merged = buildVacationSettings(base, { enabled: true });

  expect(merged.responseSubject).toBe('Existing');
  expect(merged.responseBodyHtml).toBe('<p>existing</p>');
  expect(merged.enableAutoReply).toBe(true);
 });

 it('renders a Markdown body to HTML and keeps the source as plain text', () => {
  const merged = buildVacationSettings({}, { enabled: true, body: 'Back **Monday**' });

  expect(merged.responseBodyHtml).toContain('<strong>Monday</strong>');
  expect(merged.responseBodyPlainText).toBe('Back **Monday**');
 });

 it('uses an explicit bodyHtml verbatim', () => {
  const merged = buildVacationSettings({}, { enabled: true, bodyHtml: '<p>raw</p>' });

  expect(merged.responseBodyHtml).toBe('<p>raw</p>');
 });

 it('converts ISO dates to epoch milliseconds', () => {
  const merged = buildVacationSettings(base, {
   enabled: true,
   startTime: '2026-08-20T00:00:00Z',
   endTime: '2026-08-27T00:00:00Z',
  });

  expect(merged.startTime).toBe(String(Date.parse('2026-08-20T00:00:00Z')));
  expect(merged.endTime).toBe(String(Date.parse('2026-08-27T00:00:00Z')));
 });

 it('rejects an end before the start', () => {
  expect(() => buildVacationSettings(base, {
   enabled: true,
   startTime: '2026-08-27T00:00:00Z',
   endTime: '2026-08-20T00:00:00Z',
  })).toThrow(/must precede/);
 });

 it('rejects enabling with no subject and no body', () => {
  expect(() => buildVacationSettings({}, { enabled: true })).toThrow(/nonempty subject or body/);
 });

 it('allows enabling against a body that already exists', () => {
  expect(() => buildVacationSettings(base, { enabled: true })).not.toThrow();
 });

 it('allows disabling with no subject or body', () => {
  expect(() => buildVacationSettings({}, { enabled: false })).not.toThrow();
 });
});

describe('toEpochMillis', () => {
 it('accepts a bare ISO date as UTC midnight', () => {
  expect(toEpochMillis('2026-08-20', 'startTime')).toBe(String(Date.parse('2026-08-20T00:00:00Z')));
 });

 it('honours an explicit offset', () => {
  expect(toEpochMillis('2026-08-20T09:00:00-07:00', 'startTime'))
   .toBe(String(Date.parse('2026-08-20T16:00:00Z')));
 });

 it('rejects nonsense with a message naming the field', () => {
  expect(() => toEpochMillis('next tuesday', 'endTime')).toThrow(/endTime is not a valid date/);
 });
});

describe('setVacationResponder', () => {
 it('PUTs the merged resource, not the bare request', async () => {
  const calls: Record<string, unknown> = {};
  const gmail = stubGmail({
   vacation: { responseSubject: 'Keep me', responseBodyHtml: '<p>keep</p>' },
   calls,
  });

  await setVacationResponder(gmail, { enabled: true, subject: 'New subject' });

  const put = calls.updateVacation as { requestBody: Record<string, unknown> };
  expect(put.requestBody.responseSubject).toBe('New subject');
  // The existing body must survive a subject-only change.
  expect(put.requestBody.responseBodyHtml).toBe('<p>keep</p>');
  expect(put.requestBody.enableAutoReply).toBe(true);
 });

 it('turns the responder off without discarding the stored message', async () => {
  const calls: Record<string, unknown> = {};
  const gmail = stubGmail({
   vacation: { responseSubject: 'Away', responseBodyHtml: '<p>away</p>' },
   calls,
  });

  await setVacationResponder(gmail, { enabled: false });

  const put = calls.updateVacation as { requestBody: Record<string, unknown> };
  expect(put.requestBody.enableAutoReply).toBe(false);
  expect(put.requestBody.responseSubject).toBe('Away');
 });
});

describe('settings tool definitions', () => {
 const names = ['get_settings', 'set_signature', 'update_send_as', 'set_vacation_responder'];

 it('registers all four settings tools', () => {
  for (const name of names) {
   expect(getToolByName(name), name).toBeDefined();
  }
  expect(toolDefinitions.filter(t => names.includes(t.name))).toHaveLength(4);
 });

 it('marks get_settings read-only and the rest not', () => {
  expect(getToolByName('get_settings')!.annotations.readOnlyHint).toBe(true);
  for (const name of names.slice(1)) {
   expect(getToolByName(name)!.annotations.readOnlyHint, name).toBeUndefined();
  }
 });

 it('exposes get_settings to a read-only scope', () => {
  const tool = getToolByName('get_settings')!;
  expect(hasScope(['gmail.readonly'], tool.scopes)).toBe(true);
 });

 it('gates the writes behind a settings scope', () => {
  for (const name of names.slice(1)) {
   const tool = getToolByName(name)!;
   expect(hasScope(['gmail.settings.basic'], tool.scopes), name).toBe(true);
   expect(hasScope(['gmail.readonly'], tool.scopes), name).toBe(false);
  }
 });

 it('warns in set_signature that the signature is not applied to sent mail', () => {
  expect(getToolByName('set_signature')!.description).toMatch(/not added to mail sent through/i);
 });
});

/**
 * Guards the multi-account write boundary in index.ts.
 *
 * `WRITE_TOOLS` is what forces a mutating tool to name an account when several
 * are linked. A tool missing from that set falls through to the read path, which
 * fans out and runs the handler once per linked mailbox: one set_signature call
 * would rewrite the signature on every account. The set is asserted from source
 * text because importing index.ts would start the server.
 */
describe('WRITE_TOOLS covers every mutating tool', () => {
 const source = fs.readFileSync(path.join(srcDir, 'index.ts'), 'utf-8');
 const declared = source.match(/const WRITE_TOOLS = new Set\(\[([\s\S]*?)\]\);/);
 const registered = new Set(
  [...(declared?.[1] ?? '').matchAll(/'([a-z_]+)'/g)].map(m => m[1]),
 );

 it('finds the WRITE_TOOLS declaration', () => {
  expect(declared, 'WRITE_TOOLS declaration not found in index.ts').not.toBeNull();
  expect(registered.size).toBeGreaterThan(20);
 });

 it('registers every tool that is not marked read-only', () => {
  const mutating = toolDefinitions
   .filter(t => !t.annotations.readOnlyHint)
   .map(t => t.name);
  const missing = mutating.filter(name => !registered.has(name));

  expect(missing, `these mutating tools would fan out across every linked account: ${missing.join(', ')}`).toEqual([]);
 });

 it('does not register read-only tools, so audits still fan out', () => {
  const readOnly = toolDefinitions
   .filter(t => t.annotations.readOnlyHint)
   .map(t => t.name);
  const wronglyRegistered = readOnly.filter(name => registered.has(name));

  expect(wronglyRegistered).toEqual([]);
 });
});
