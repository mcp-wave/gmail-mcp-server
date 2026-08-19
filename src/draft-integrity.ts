/**
 * Draft integrity for Gmail MCP Server
 *
 * Gmail labels are not exclusive, so a message can hold `DRAFT` and `TRASH` at
 * the same time. The two client families then disagree about what it is:
 *
 * - Gmail's web UI honours `TRASH` and collapses the message into the
 *   "N deleted messages in this conversation" affordance. The draft is gone.
 * - IMAP clients (Apple Mail, Outlook, Thunderbird) map labels onto folders, so
 *   `DRAFT` still present means the message keeps showing up in the Drafts
 *   folder, indefinitely, as something the user can open and try to edit.
 *
 * `messages.trash` is what creates that state. It adds `TRASH` and has no idea
 * it is looking at a draft, so `DRAFT` stays on. The correct way to discard a
 * draft is `drafts.delete`, which removes the draft outright and leaves no
 * half-alive message behind.
 *
 * This module refuses to create the state in the first place, and can repair
 * messages already in it.
 */

import type { gmail_v1 } from 'googleapis';

type GmailClient = gmail_v1.Gmail;

/** A message that is both a draft and trashed, so clients disagree about it. */
export interface ZombieDraft {
 messageId: string;
 threadId: string;
 subject: string;
 labelIds: string[];
}

/** Read the labels on a message without pulling its body. */
export async function readLabels(gmail: GmailClient, messageId: string): Promise<string[]> {
 const response = await gmail.users.messages.get({
  userId: 'me',
  id: messageId,
  format: 'minimal',
 });
 return response.data.labelIds ?? [];
}

/**
 * Partition message ids by whether trashing them would strand a draft.
 *
 * Labels are read up front rather than per-trash so a batch reports every
 * offending id at once instead of failing on the first one.
 */
export async function partitionDraftsFromTrashable(
 gmail: GmailClient,
 messageIds: string[],
): Promise<{ trashable: string[]; drafts: string[]; unreadable: { messageId: string; reason: string }[] }> {
 const trashable: string[] = [];
 const drafts: string[] = [];
 const unreadable: { messageId: string; reason: string }[] = [];

 await Promise.all(messageIds.map(async (messageId) => {
  try {
   const labels = await readLabels(gmail, messageId);
   if (labels.includes('DRAFT')) drafts.push(messageId);
   else trashable.push(messageId);
  } catch (error: unknown) {
   // An unreadable label set is not permission to trash blind: a draft
   // we could not identify is exactly the case this guard exists for.
   const message = error instanceof Error ? error.message : String(error);
   unreadable.push({ messageId, reason: message });
  }
 }));

 return { trashable, drafts, unreadable };
}

/** The refusal text shown when a caller tries to trash a draft. */
export function draftTrashRefusal(draftMessageIds: string[]): string {
 const list = draftMessageIds.join(', ');
 return (
  `Refusing to trash ${draftMessageIds.length} draft message(s) (${list}). ` +
  `Trashing a draft adds the TRASH label but leaves DRAFT on it, which makes Gmail hide it as a ` +
  `deleted message while IMAP clients such as Apple Mail keep listing it in Drafts forever. ` +
  `To discard a draft, use delete_draft with its draft ID (find it with list_drafts). ` +
  `To keep the draft but take it out of Trash, use repair_drafts.`
 );
}

/**
 * Find messages stuck in the DRAFT+TRASH state.
 *
 * Searched through `in:trash` because that is the only place the state can
 * exist, then filtered on the DRAFT label rather than on a search operator,
 * since `is:draft` matches the label and cannot express the intersection.
 */
export async function findZombieDrafts(gmail: GmailClient, maxResults = 100): Promise<ZombieDraft[]> {
 const listed = await gmail.users.messages.list({
  userId: 'me',
  q: 'in:trash label:draft',
  maxResults,
 });

 const messages = listed.data.messages ?? [];
 const found: ZombieDraft[] = [];

 await Promise.all(messages.map(async (m) => {
  if (!m.id) return;
  const detail = await gmail.users.messages.get({
   userId: 'me',
   id: m.id,
   format: 'metadata',
   metadataHeaders: ['Subject'],
  });
  const labelIds = detail.data.labelIds ?? [];
  if (!labelIds.includes('DRAFT') || !labelIds.includes('TRASH')) return;
  const subject = detail.data.payload?.headers?.find(
   h => (h.name ?? '').toLowerCase() === 'subject',
  )?.value ?? '(no subject)';
  found.push({
   messageId: m.id,
   threadId: detail.data.threadId ?? '',
   subject,
   labelIds,
  });
 }));

 return found;
}

export type RepairMode = 'restore' | 'discard';

export interface RepairOutcome {
 messageId: string;
 subject: string;
 status: 'restored' | 'discarded' | 'failed';
 detail?: string;
}

/**
 * Resolve DRAFT+TRASH messages into a single consistent state.
 *
 * `restore` removes `TRASH`, so the message is a live draft again and both Gmail
 * and IMAP clients agree it is one. `discard` removes `DRAFT` instead, leaving an
 * ordinary trashed message that Gmail purges on its own schedule and that stops
 * appearing in IMAP Drafts folders.
 *
 * Neither mode deletes anything. The content stays in the mailbox either way, so
 * a wrong call here is recoverable.
 */
export async function repairZombieDrafts(
 gmail: GmailClient,
 zombies: ZombieDraft[],
 mode: RepairMode,
): Promise<RepairOutcome[]> {
 const removeLabelIds = mode === 'restore' ? ['TRASH'] : ['DRAFT'];

 return Promise.all(zombies.map(async (z): Promise<RepairOutcome> => {
  try {
   await gmail.users.messages.modify({
    userId: 'me',
    id: z.messageId,
    requestBody: { removeLabelIds },
   });
   return {
    messageId: z.messageId,
    subject: z.subject,
    status: mode === 'restore' ? 'restored' : 'discarded',
   };
  } catch (error: unknown) {
   return {
    messageId: z.messageId,
    subject: z.subject,
    status: 'failed',
    detail: error instanceof Error ? error.message : String(error),
   };
  }
 }));
}

/** Render a repair run, naming every message and its outcome. */
export function formatRepair(outcomes: RepairOutcome[], mode: RepairMode): string {
 if (outcomes.length === 0) {
  return 'No messages were stuck in the DRAFT+TRASH state, so there was nothing to repair.';
 }

 const verb = mode === 'restore'
  ? 'Removed TRASH, so these are live drafts again in Gmail and in IMAP clients'
  : 'Removed DRAFT, so these are ordinary trashed messages and will stop appearing in IMAP Drafts folders';

 const lines = outcomes.map(o => o.status === 'failed'
  ? `- FAILED ${o.messageId} (${o.subject}): ${o.detail}`
  : `- ${o.messageId}: ${o.subject}`);

 const failed = outcomes.filter(o => o.status === 'failed').length;
 const summary = `${verb}: ${outcomes.length - failed}/${outcomes.length}.`;
 return `${summary}\n${lines.join('\n')}`;
}
