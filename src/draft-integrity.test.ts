/**
 * Tests for draft integrity: the DRAFT+TRASH state
 *
 * A message holding both labels looks deleted in Gmail's web UI and still looks
 * like a draft in every IMAP client. `trash_email` used to create that state;
 * it now refuses to. `repair_drafts` resolves messages already in it, in either
 * direction, without deleting anything.
 */

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
 partitionDraftsFromTrashable,
 draftTrashRefusal,
 findZombieDrafts,
 repairZombieDrafts,
 formatRepair,
} from './draft-integrity.js';
import { toolDefinitions, getToolByName, RepairDraftsSchema } from './tools.js';

const srcDir = path.dirname(fileURLToPath(import.meta.url));

/**
 * Minimal stand-in for the Gmail client's users.messages surface, typed as the
 * real client at the call site so method drift still fails the typecheck.
 */
function stubGmail(labelsByMessage: Record<string, string[]> = {}, subjectByMessage: Record<string, string> = {}) {
 const calls: Record<string, { removeLabelIds?: string[]; addLabelIds?: string[] }[]> = {};
 const trashCalls: string[] = [];
 const client = {
  users: {
   messages: {
    get: async (params: { id: string; format?: string }) => {
     const labels = labelsByMessage[params.id];
     if (!labels) {
      throw Object.assign(new Error(`Requested entity was not found: ${params.id}`), {
       code: 404,
       errors: [{ message: 'Requested entity was not found' }],
      });
     }
     return {
      data: {
       id: params.id,
       threadId: `thread-${params.id}`,
       labelIds: labels,
       payload: { headers: [{ name: 'Subject', value: subjectByMessage[params.id] ?? `(id ${params.id})` }] },
      },
     };
    },
    list: async (params: { q?: string }) => ({
     data: {
      messages: params.q === 'in:trash label:draft'
       ? Object.keys(labelsByMessage).map(id => ({ id }))
       : [],
     },
    }),
    modify: async (params: { id: string; requestBody: { removeLabelIds?: string[] } }) => {
     (calls.modify ??= []).push(params.requestBody);
     labelsByMessage[params.id] = (labelsByMessage[params.id] ?? []).filter(
      l => !params.requestBody.removeLabelIds?.includes(l),
     );
    },
    trash: async (params: { id: string }) => {
     trashCalls.push(params.id);
    },
   },
  },
 };
 return { client, calls, trashCalls, labelsOf: (id: string) => labelsByMessage[id] ?? [] };
}

/** The `users.messages` surface the stub implements; one named contract for all uses. */
export interface StubMessagesClient {
 users: {
  messages: {
   get(params: { id: string; format?: string }): Promise<{ data: { id: string; threadId: string; labelIds: string[]; payload: { headers: { name: string; value: string }[] } } }>;
   list(params: { q?: string }): Promise<{ data: { messages: { id: string }[] } }>;
   modify(params: { id: string; requestBody: { removeLabelIds?: string[]; addLabelIds?: string[] } }): Promise<unknown>;
   trash(params: { id: string }): Promise<unknown>;
  };
 };
}

interface StubGmail {
 client: StubMessagesClient;
 labelsOf(id: string): string[];
 calls: Record<string, { removeLabelIds?: string[]; addLabelIds?: string[] }[]>;
 trashCalls: string[];
}

const asGmail = (client: StubMessagesClient) => client as unknown as Parameters<typeof partitionDraftsFromTrashable>[0];

describe('partitionDraftsFromTrashable', () => {
 it('separates drafts from ordinary messages', async () => {
  const { client } = stubGmail({
   'plain-1': ['INBOX'],
   'draft-1': ['DRAFT'],
   'plain-2': ['INBOX', 'UNREAD'],
  });

  const result = await partitionDraftsFromTrashable(asGmail(client), ['plain-1', 'draft-1', 'plain-2']);

  expect(result.trashable.sort()).toEqual(['plain-1', 'plain-2']);
  expect(result.drafts).toEqual(['draft-1']);
  expect(result.unreadable).toEqual([]);
 });

 it('treats a DRAFT+TRASH message as a draft, so it cannot be double-trashed', async () => {
  const { client } = stubGmail({ 'zombie': ['DRAFT', 'TRASH'] });

  const result = await partitionDraftsFromTrashable(asGmail(client), ['zombie']);

  expect(result.drafts).toEqual(['zombie']);
 });

 it('reports an unreadable message rather than letting it be trashed blind', async () => {
  const { client } = stubGmail({ 'ok': ['INBOX'] });

  const result = await partitionDraftsFromTrashable(asGmail(client), ['ok', 'gone']);

  expect(result.trashable).toEqual(['ok']);
  expect(result.drafts).toEqual([]);
  expect(result.unreadable).toHaveLength(1);
  expect(result.unreadable[0].messageId).toBe('gone');
  expect(result.unreadable[0].reason).toMatch(/not found/i);
 });

 it('treats a missing label list as trashable', async () => {
  const { client } = stubGmail({ 'weird': [] });

  const result = await partitionDraftsFromTrashable(asGmail(client), ['weird']);

  expect(result.trashable).toEqual(['weird']);
 });
});

describe('draftTrashRefusal', () => {
 it('names the ids, the state it prevents, and both correct remedies', () => {
  const text = draftTrashRefusal(['a-1', 'a-2']);

  expect(text).toContain('a-1, a-2');
  expect(text).toContain('delete_draft');
  expect(text).toContain('repair_drafts');
  expect(text).toMatch(/Apple Mail/);
 });
});

describe('findZombieDrafts', () => {
 it('returns only messages holding both labels', async () => {
  const { client } = stubGmail(
   { 'z-1': ['DRAFT', 'TRASH'], 'z-2': ['DRAFT'], 'z-3': ['TRASH'] },
   { 'z-1': 'Event Wifi inquiry', 'z-2': 'plain draft', 'z-3': 'plain trash' },
  );

  const zombies = await findZombieDrafts(asGmail(client));

  expect(zombies.map(z => z.messageId)).toEqual(['z-1']);
  expect(zombies[0].subject).toBe('Event Wifi inquiry');
 });
});



describe('repairZombieDrafts', () => {
 const zombie = { messageId: 'z-1', threadId: 't-1', subject: 'Event Wifi inquiry', labelIds: ['DRAFT', 'TRASH'] };

 it('restore removes TRASH and keeps DRAFT, so both clients see a draft', async () => {
  const { client, calls, labelsOf } = stubGmail({ 'z-1': ['DRAFT', 'TRASH'] });

  const outcomes = await repairZombieDrafts(asGmail(client), [zombie], 'restore');

  expect(outcomes).toHaveLength(1);
  expect(outcomes[0].status).toBe('restored');
  expect(calls.modify?.[0]?.removeLabelIds).toEqual(['TRASH']);
  // The live label set afterwards is DRAFT alone.
  expect(labelsOf('z-1')).toEqual(['DRAFT']);
 });

 it('discard removes DRAFT and keeps TRASH, so IMAP clients stop listing it', async () => {
  const { client, calls, labelsOf } = stubGmail({ 'z-1': ['DRAFT', 'TRASH'] });

  const outcomes = await repairZombieDrafts(asGmail(client), [zombie], 'discard');

  expect(outcomes[0].status).toBe('discarded');
  expect(calls.modify?.[0]?.removeLabelIds).toEqual(['DRAFT']);
  expect(labelsOf('z-1')).toEqual(['TRASH']);
 });

 it('reports a failed repair with its reason instead of hiding it', async () => {
  const failing: StubMessagesClient = {
   users: {
    messages: {
     modify: async () => {
      throw Object.assign(new Error('Requested entity was not found: z-1'), { code: 404 });
     },
    },
   },
  };
  const outcomes = await repairZombieDrafts(asGmail(failing), [zombie], 'restore');

  expect(outcomes[0].status).toBe('failed');
  expect(outcomes[0].detail).toMatch(/not found/i);
 });

 it('never deletes: neither mode calls the trash or delete endpoint', async () => {
  const { client, trashCalls } = stubGmail({ 'z-1': ['DRAFT', 'TRASH'] });

  await repairZombieDrafts(asGmail(client), [zombie], 'restore');
  await repairZombieDrafts(asGmail(client), [zombie], 'discard');

  expect(trashCalls).toEqual([]);
 });
});

describe('formatRepair', () => {
 it('names every message and its outcome', () => {
  const text = formatRepair([
   { messageId: 'z-1', subject: 'A', status: 'restored' },
   { messageId: 'z-2', subject: 'B', status: 'failed', detail: 'boom' },
  ], 'restore');

  expect(text).toContain('1/2');
  expect(text).toContain('z-1: A');
  expect(text).toContain('FAILED z-2 (B): boom');
 });

 it('says so when there was nothing to repair', () => {
  expect(formatRepair([], 'discard')).toMatch(/nothing to repair/i);
 });
});

describe('RepairDraftsSchema', () => {
 it('requires a known mode', () => {
  expect(RepairDraftsSchema.safeParse({ mode: 'restore' }).success).toBe(true);
  expect(RepairDraftsSchema.safeParse({ mode: 'explode' }).success).toBe(false);
  expect(RepairDraftsSchema.safeParse({}).success).toBe(false);
 });

 it('allows targeting specific messages', () => {
  const result = RepairDraftsSchema.safeParse({ mode: 'discard', messageIds: ['a', 'b'] });
  expect(result.success).toBe(true);
 });
});

describe('draft integrity tool definitions', () => {
 it('registers find_stranded_drafts as a read and repair_drafts as a write', () => {
  expect(getToolByName('find_stranded_drafts')!.annotations.readOnlyHint).toBe(true);
  expect(getToolByName('repair_drafts')!.annotations.readOnlyHint).toBeUndefined();
 });

 it('gives the repair tool modify scope only', () => {
  const tool = getToolByName('repair_drafts')!;
  expect(tool.scopes).toEqual(['gmail.modify']);
 });

 it('registers each new tool exactly once', () => {
  for (const name of ['find_stranded_drafts', 'repair_drafts']) {
   expect(toolDefinitions.filter(t => t.name === name), name).toHaveLength(1);
  }
 });

 it('warns in trash_email that drafts are refused', () => {
  expect(getToolByName('trash_email')!.description).toMatch(/Refuses to trash a draft/);
 });
});

describe('trash handler wiring', () => {
 const source = fs.readFileSync(path.join(srcDir, 'index.ts'), 'utf-8');
 const trashHandler = source.split('case "trash_email": {')[1].split('case "batch_trash_emails"')[0];
 const batchHandler = source.split('case "batch_trash_emails": {')[1].split('case "find_stranded_drafts"')[0];

 it('checks labels before trashing in the single-message path', () => {
  const checkAt = trashHandler.indexOf('readLabels');
  const trashAt = trashHandler.indexOf('messages.trash');
  expect(checkAt).toBeGreaterThan(-1);
  expect(trashAt).toBeGreaterThan(-1);
  expect(checkAt).toBeLessThan(trashAt);
 });

 it('refuses on DRAFT in the single-message path', () => {
  expect(trashHandler).toContain("labels.includes('DRAFT')");
  expect(trashHandler).toContain('draftTrashRefusal');
 });
});

describe('modify-sink guards (audit finding Z-1)', () => {
 const source = fs.readFileSync(path.join(srcDir, 'index.ts'), 'utf-8');

 it('modify_email refuses addLabelIds TRASH on a draft before the modify call', () => {
  const handler = source.split('case "modify_email": {')[1].split('case "trash_email"')[0];
  const guardAt = handler.indexOf("addLabelIds?.includes('TRASH')");
  const modifyAt = handler.indexOf('messages.modify');
  expect(guardAt).toBeGreaterThan(-1);
  expect(modifyAt).toBeGreaterThan(-1);
  expect(guardAt).toBeLessThan(modifyAt);
  expect(handler).toContain('draftTrashRefusal');
  // Exact condition, not a substring: a disabled guard (e.g. `false &&`) must fail.
  expect(handler).toContain("if (requestBody.addLabelIds?.includes('TRASH')) {");
 });

 it('batch_modify_emails refuses TRASH adds naming the drafts', () => {
  const handler = source.split('case "batch_modify_emails": {')[1].split('case "')[0];
  expect(handler).toContain("if (requestBody.addLabelIds?.includes('TRASH')) {");
  expect(handler).toContain('No labels were changed');
 });

 it('modify_thread guards TRASH adds against every message in the thread', () => {
  const handler = source.split('case "modify_thread": {')[1].split('default:')[0];
  expect(handler).toContain("if (modifyRequestBody.addLabelIds?.includes('TRASH')) {");
  expect(handler).toContain('threads.get');
  expect(handler).toContain('partitionDraftsFromTrashable');
  expect(handler.indexOf("addLabelIds?.includes('TRASH')")).toBeLessThan(handler.indexOf('gmail.users.threads.modify'));
 });
});
describe('batch trash wiring', () => {
 const source = fs.readFileSync(path.join(srcDir, 'index.ts'), 'utf-8');
 const batchHandler = source.split('case "batch_trash_emails": {')[1].split('case "find_stranded_drafts"')[0];

 it('partitions the whole batch before trashing any of it', () => {
  const partitionAt = batchHandler.indexOf('partitionDraftsFromTrashable');
  const trashAt = batchHandler.indexOf('messages.trash');
  expect(partitionAt).toBeGreaterThan(-1);
  expect(partitionAt).toBeLessThan(trashAt);
  expect(batchHandler).toContain('Nothing was trashed');
 });

 it('repair_drafts is gated as a multi-account write', () => {
  const writeTools = source.match(/const WRITE_TOOLS = new Set\(\[([\s\S]*?)\]\);/)?.[1] ?? '';
  expect(writeTools).toContain("'repair_drafts'");
  expect(writeTools).not.toContain("'find_stranded_drafts'");
 });
});
