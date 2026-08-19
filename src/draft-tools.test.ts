/**
 * Tests for draft edit safety
 *
 * `drafts.update` replaces a draft's whole content, so the danger is an agent
 * revising a draft the user has since edited in Gmail and silently discarding
 * their words. Three properties defend against that and each is asserted here:
 *
 * 1. An edit without a baseToken is refused: the caller never read the draft.
 * 2. An edit whose baseToken no longer matches is refused, and the refusal
 *    carries the draft's current content so the caller can fold it in.
 * 3. Fields the caller omits are preserved from the live draft, so changing the
 *    subject cannot wipe out a body the user rewrote.
 */

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
    buildDraftSnapshot,
    mergeDraftEdit,
    assertFresh,
    assertAttachmentsSafe,
    describeMerge,
    draftToken,
    headerToAddresses,
    StaleDraftError,
    type DraftSnapshot,
} from './draft-manager.js';
import { toolDefinitions, getToolByName, UpdateDraftSchema } from './tools.js';

const srcDir = path.dirname(fileURLToPath(import.meta.url));

function snapshot(overrides: Partial<DraftSnapshot> = {}): DraftSnapshot {
    return {
        draftId: 'r-1',
        messageId: 'm-1',
        historyId: 'h-1',
        token: draftToken('m-1', 'h-1'),
        to: ['recipient@example.com'],
        cc: [],
        bcc: [],
        subject: 'Original subject',
        text: 'The body the user rewrote.',
        html: '<p>The body the user rewrote.</p>',
        attachments: [],
        ...overrides,
    };
}

describe('draftToken', () => {
    it('changes when the message is modified in place', () => {
        expect(draftToken('m-1', 'h-1')).not.toBe(draftToken('m-1', 'h-2'));
    });

    it('changes when the message is replaced', () => {
        expect(draftToken('m-1', 'h-1')).not.toBe(draftToken('m-2', 'h-1'));
    });

    it('does not let a missing component collide with a literal id', () => {
        // Absent and empty are deliberately the same: Gmail never returns an
        // empty id, so both mean "no historyId". What must not collide is absent
        // versus a real id that happens to look like a sentinel.
        expect(draftToken('m-1', undefined)).not.toBe(draftToken('m-1', 'none'));
        expect(draftToken(undefined, 'h-1')).not.toBe(draftToken('none', 'h-1'));
    });

    it('is versioned so a stored older-format token cannot pass as current', () => {
        expect(draftToken('m-1', 'h-1')).toMatch(/^v1:/);
        expect(draftToken('m-1', 'h-1')).not.toBe('m-1:h-1');
    });
});

describe('buildDraftSnapshot', () => {
    it('derives the token from the draft message', () => {
        const built = buildDraftSnapshot({
            draft: { id: 'r-9', message: { id: 'm-9', historyId: 'h-9' } },
            headers: { subject: 'Hi', to: 'a@example.com', cc: '', bcc: '' },
            content: { text: 'body', html: '<p>body</p>' },
            attachments: [],
        });

        expect(built.token).toBe('v1:m-9:h-9');
        expect(built.draftId).toBe('r-9');
        expect(built.subject).toBe('Hi');
        expect(built.to).toEqual(['a@example.com']);
    });

    it('survives a draft with no message payload', () => {
        const built = buildDraftSnapshot({
            draft: { id: 'r-9' },
            headers: { subject: '', to: '', cc: '', bcc: '' },
            content: { text: '', html: '' },
            attachments: [],
        });

        expect(built.token).toBe('v1::');
        expect(built.to).toEqual([]);
    });
});

describe('headerToAddresses', () => {
    it('strips display names so the message builder accepts the addresses', () => {
        expect(headerToAddresses('Jason Waldrip <jason@example.com>')).toEqual(['jason@example.com']);
    });

    it('splits a multi-recipient header', () => {
        expect(headerToAddresses('a@example.com, B <b@example.com>')).toEqual(['a@example.com', 'b@example.com']);
    });

    it('returns nothing for an absent header', () => {
        expect(headerToAddresses('')).toEqual([]);
        expect(headerToAddresses('   ')).toEqual([]);
    });
});

describe('assertFresh refuses edits built on unseen content', () => {
    it('refuses an edit with no baseToken at all', () => {
        const current = snapshot();
        expect(() => assertFresh(current, undefined)).toThrow(StaleDraftError);
        expect(() => assertFresh(current, undefined)).toThrow(/Call read_draft/);
    });

    it('refuses an edit whose token is stale', () => {
        const current = snapshot({ token: draftToken('m-2', 'h-2') });
        expect(() => assertFresh(current, draftToken('m-1', 'h-1'))).toThrow(/changed after you read it/);
    });

    it('attaches the current content to a stale refusal', () => {
        const current = snapshot({ token: draftToken('m-2', 'h-2'), text: 'What the user actually wrote' });
        try {
            assertFresh(current, draftToken('m-1', 'h-1'));
            expect.unreachable('should have thrown');
        } catch (error) {
            expect(error).toBeInstanceOf(StaleDraftError);
            expect((error as StaleDraftError).currentSnapshot.text).toBe('What the user actually wrote');
        }
    });

    it('allows an edit whose token matches', () => {
        const current = snapshot();
        expect(() => assertFresh(current, current.token)).not.toThrow();
    });
});

describe('mergeDraftEdit preserves what the caller did not touch', () => {
    it('keeps the body when only the subject changes', () => {
        const current = snapshot();
        const merged = mergeDraftEdit(current, { subject: 'New subject' });

        expect(merged.messageArgs.subject).toBe('New subject');
        expect(merged.messageArgs.body).toBe('The body the user rewrote.');
        expect(merged.messageArgs.htmlBody).toBe('<p>The body the user rewrote.</p>');
        expect(merged.preserved).toContain('body');
        expect(merged.replaced).toContain('subject');
    });

    it('keeps the subject and recipients when only the body changes', () => {
        const current = snapshot();
        const merged = mergeDraftEdit(current, { body: 'Rewritten by the agent' });

        expect(merged.messageArgs.subject).toBe('Original subject');
        expect(merged.messageArgs.to).toEqual(['recipient@example.com']);
        expect(merged.messageArgs.body).toBe('Rewritten by the agent');
        expect(merged.replaced).toContain('body');
    });

    it('carries both body halves over together', () => {
        const merged = mergeDraftEdit(snapshot(), { subject: 'x' });

        // Dropping one half would silently turn a multipart draft single-part.
        expect(merged.messageArgs.body).toBeDefined();
        expect(merged.messageArgs.htmlBody).toBeDefined();
    });

    it('replaces the body wholesale when the caller supplies one', () => {
        const merged = mergeDraftEdit(snapshot(), { body: 'new text' });

        // The stale HTML half must not survive alongside a new text body.
        expect(merged.messageArgs.body).toBe('new text');
        expect(merged.messageArgs.htmlBody).toBeUndefined();
    });

    it('keeps cc and bcc when untouched', () => {
        const current = snapshot({ cc: ['cc@example.com'], bcc: ['bcc@example.com'] });
        const merged = mergeDraftEdit(current, { subject: 'x' });

        expect(merged.messageArgs.cc).toEqual(['cc@example.com']);
        expect(merged.messageArgs.bcc).toEqual(['bcc@example.com']);
    });

    it('allows clearing cc with an explicit empty list', () => {
        const current = snapshot({ cc: ['cc@example.com'] });
        const merged = mergeDraftEdit(current, { cc: [] });

        expect(merged.messageArgs.cc).toBeUndefined();
        expect(merged.replaced).toContain('cc');
    });

    it('refuses to leave the draft with no recipients', () => {
        const current = snapshot({ to: [] });
        expect(() => mergeDraftEdit(current, { subject: 'x' })).toThrow(/no recipients/);
    });

    it('passes threading and sender fields through when supplied', () => {
        const merged = mergeDraftEdit(snapshot(), {
            subject: 'x',
            from: 'alias@example.com',
            threadId: 't-1',
            inReplyTo: '<msg@example.com>',
            mimeType: 'text/plain',
        });

        expect(merged.messageArgs.from).toBe('alias@example.com');
        expect(merged.messageArgs.threadId).toBe('t-1');
        expect(merged.messageArgs.inReplyTo).toBe('<msg@example.com>');
        expect(merged.messageArgs.mimeType).toBe('text/plain');
    });
});

describe('assertAttachmentsSafe', () => {
    const withAttachment = snapshot({
        attachments: [{ filename: 'contract.pdf', mimeType: 'application/pdf', size: 2048 }],
    });

    it('refuses an edit that would silently drop existing attachments', () => {
        expect(() => assertAttachmentsSafe(withAttachment, { subject: 'x' }))
            .toThrow(/contract\.pdf/);
    });

    it('allows the edit when attachments are re-supplied', () => {
        expect(() => assertAttachmentsSafe(withAttachment, { attachments: ['/tmp/contract.pdf'] }))
            .not.toThrow();
    });

    it('refuses an empty attachments array, which is not a re-supply', () => {
        // LLM clients routinely emit [] for an omitted optional array, so treating
        // it as "the caller re-supplied the files" would silently strip them
        // through the very guard that exists to stop that.
        expect(() => assertAttachmentsSafe(withAttachment, { attachments: [] }))
            .toThrow(/contract\.pdf/);
    });

    it('allows an empty attachments array when the drop is explicit', () => {
        expect(() => assertAttachmentsSafe(withAttachment, { attachments: [], dropAttachments: true }))
            .not.toThrow();
    });

    it('allows the edit when the drop is explicit', () => {
        expect(() => assertAttachmentsSafe(withAttachment, { dropAttachments: true })).not.toThrow();
    });

    it('does nothing for a draft with no attachments', () => {
        expect(() => assertAttachmentsSafe(snapshot(), { subject: 'x' })).not.toThrow();
    });
});

describe('describeMerge', () => {
    it('names what was replaced and what was kept', () => {
        const merged = mergeDraftEdit(snapshot(), { subject: 'New' });
        const description = describeMerge(merged);

        expect(description).toContain('replaced subject');
        expect(description).toContain("kept the draft's existing");
    });
});

describe('UpdateDraftSchema', () => {
    it('requires a baseToken', () => {
        const result = UpdateDraftSchema.safeParse({ draftId: 'r-1', subject: 'x' });
        expect(result.success).toBe(false);
    });

    it('accepts an edit that changes only the subject', () => {
        const result = UpdateDraftSchema.safeParse({ draftId: 'r-1', baseToken: 'm:h', subject: 'x' });
        expect(result.success).toBe(true);
    });

    it('no longer requires to, subject and body, so omissions can be preserved', () => {
        const result = UpdateDraftSchema.safeParse({ draftId: 'r-1', baseToken: 'm:h' });
        expect(result.success).toBe(true);
    });
});

describe('draft tool definitions', () => {
    it('registers read_draft and list_drafts as read-only', () => {
        for (const name of ['read_draft', 'list_drafts']) {
            const tool = getToolByName(name);
            expect(tool, name).toBeDefined();
            expect(tool!.annotations.readOnlyHint, name).toBe(true);
        }
    });

    it('keeps update_draft a write', () => {
        expect(getToolByName('update_draft')!.annotations.readOnlyHint).toBeUndefined();
    });

    it('tells the caller in read_draft why it must be called first', () => {
        expect(getToolByName('read_draft')!.description).toMatch(/before update_draft/i);
    });

    it('tells the caller in update_draft that omitted fields are preserved', () => {
        expect(getToolByName('update_draft')!.description).toMatch(/omit keep their current values/i);
    });

    it('registers every draft tool exactly once', () => {
        const names = ['draft_email', 'read_draft', 'list_drafts', 'update_draft', 'send_draft', 'delete_draft'];
        for (const name of names) {
            expect(toolDefinitions.filter(t => t.name === name), name).toHaveLength(1);
        }
    });
});

describe('update_draft handler wiring', () => {
    const source = fs.readFileSync(path.join(srcDir, 'index.ts'), 'utf-8');
    const handler = source.split('case "update_draft": {')[1].split('case "list_email_labels"')[0];

    it('reads the live draft before building the replacement', () => {
        const readAt = handler.indexOf('loadDraftSnapshot');
        const buildAt = handler.indexOf('createEmailMessage');
        expect(readAt).toBeGreaterThan(-1);
        expect(buildAt).toBeGreaterThan(-1);
        expect(readAt).toBeLessThan(buildAt);
    });

    it('checks freshness before building the replacement', () => {
        expect(handler.indexOf('assertFresh')).toBeLessThan(handler.indexOf('createEmailMessage'));
    });

    it('checks attachment safety before building the replacement', () => {
        expect(handler.indexOf('assertAttachmentsSafe')).toBeLessThan(handler.indexOf('createEmailMessage'));
    });

    it('feeds the merged args to the builder, not the raw request', () => {
        expect(handler).toContain('mergeDraftEdit(current');
        expect(handler).toContain('const messageArgs = merged.messageArgs');
    });

    it('returns a fresh token so consecutive edits do not need another read', () => {
        expect(handler).toContain('New baseToken for further edits');
    });

    it('is still gated as a multi-account write', () => {
        const writeTools = source.match(/const WRITE_TOOLS = new Set\(\[([\s\S]*?)\]\);/)?.[1] ?? '';
        expect(writeTools).toContain("'update_draft'");
    });
});
