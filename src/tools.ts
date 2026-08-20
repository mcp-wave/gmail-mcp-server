import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";

// Schema definitions
export const SendEmailSchema = z.object({
  to: z.array(z.string()).describe("List of recipient email addresses"),
  subject: z.string().describe("Email subject"),
  body: z.string().describe("Email body in Markdown. Rendered to HTML and sent as multipart/alternative (HTML plus this text as the plain-text part) by default."),
  from: z.string().optional().describe("Sender email address (must be a configured send-as alias in Gmail settings). Defaults to account's default send-as address if not specified."),
  htmlBody: z.string().optional().describe("Explicit HTML body. Overrides the HTML rendered from the Markdown body; only needed for hand-authored HTML."),
  mimeType: z.enum(['text/plain', 'text/html', 'multipart/alternative']).optional().describe("Override the content type. Omit for the default multipart/alternative (Markdown-rendered HTML plus plain text). Use 'text/plain' only when a plain-text-only message is explicitly required."),
  cc: z.array(z.string()).optional().describe("List of CC recipients"),
  bcc: z.array(z.string()).optional().describe("List of BCC recipients"),
  threadId: z.string().optional().describe("Thread ID to reply to"),
  inReplyTo: z.string().optional().describe("Message ID being replied to"),
  attachments: z.array(z.string()).optional().describe("List of file paths to attach to the email"),
});

export const ReadEmailSchema = z.object({
  messageId: z.string().describe("ID of the email message to retrieve"),
});

export const SearchEmailsSchema = z.object({
  query: z.string().describe("Gmail search query (e.g., 'from:example@gmail.com')"),
  maxResults: z.number().optional().describe("Maximum number of results to return"),
});

export const ModifyEmailSchema = z.object({
  messageId: z.string().describe("ID of the email message to modify"),
  labelIds: z.array(z.string()).optional().describe("List of label IDs to apply"),
  addLabelIds: z.array(z.string()).optional().describe("List of label IDs to add to the message"),
  removeLabelIds: z.array(z.string()).optional().describe("List of label IDs to remove from the message"),
});

export const DeleteEmailSchema = z.object({
  messageId: z.string().describe("ID of the email message to delete"),
});

// Draft lifecycle schemas
export const SendDraftSchema = z.object({
  draftId: z.string().describe("ID of the draft to send (returned by draft_email)"),
});

export const DeleteDraftSchema = z.object({
  draftId: z.string().describe("ID of the draft to delete"),
});

export const ReadDraftSchema = z.object({
  draftId: z.string().describe("ID of the draft to read"),
});

export const ListDraftsSchema = z.object({
  maxResults: z.number().optional().describe("Maximum number of drafts to return (default 25)"),
});

export const UpdateDraftSchema = z.object({
  draftId: z.string().describe("ID of the draft to update"),
  baseToken: z.string().describe("The baseToken returned by read_draft for this draft. Required: it proves the edit was built on the draft's current content. If the draft changed since that read, the edit is refused rather than overwriting the user's changes."),
  to: z.array(z.string()).optional().describe("Replace the recipients. Omit to keep the draft's existing recipients."),
  subject: z.string().optional().describe("Replace the subject. Omit to keep the draft's existing subject."),
  body: z.string().optional().describe("Replace the body, in Markdown. Omit to keep the draft's existing body. Supplying this discards whatever the body currently holds, so read the draft first and fold in any changes the user made."),
  from: z.string().optional().describe("Sender email address (must be a configured send-as alias in Gmail settings). Defaults to account's default send-as address if not specified."),
  htmlBody: z.string().optional().describe("Explicit HTML body, replacing the rendered Markdown. Omit to keep the draft's existing HTML."),
  mimeType: z.enum(['text/plain', 'text/html', 'multipart/alternative']).optional().describe("Override the content type. Omit for the default multipart/alternative (Markdown-rendered HTML plus plain text). Use 'text/plain' only when a plain-text-only message is explicitly required."),
  cc: z.array(z.string()).optional().describe("Replace the CC list. Omit to keep the draft's existing CC list."),
  bcc: z.array(z.string()).optional().describe("Replace the BCC list. Omit to keep the draft's existing BCC list."),
  threadId: z.string().optional().describe("Thread ID to reply to"),
  inReplyTo: z.string().optional().describe("Message ID being replied to"),
  attachments: z.array(z.string()).optional().describe("File paths to attach, replacing the draft's current attachments. An edit to a draft that already has attachments must either re-supply them here or set dropAttachments, because Gmail holds the bytes and they cannot be rebuilt from the draft."),
  dropAttachments: z.boolean().optional().describe("Deliberately remove the draft's existing attachments. Only needed when the draft has attachments and you are not re-supplying them."),
});

export const ListEmailLabelsSchema = z.object({}).describe("Retrieves all available Gmail labels");

export const CreateLabelSchema = z.object({
  name: z.string().describe("Name for the new label"),
  messageListVisibility: z.enum(['show', 'hide']).optional().describe("Whether to show or hide the label in the message list"),
  labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("Visibility of the label in the label list"),
}).describe("Creates a new Gmail label");

export const UpdateLabelSchema = z.object({
  id: z.string().describe("ID of the label to update"),
  name: z.string().optional().describe("New name for the label"),
  messageListVisibility: z.enum(['show', 'hide']).optional().describe("Whether to show or hide the label in the message list"),
  labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("Visibility of the label in the label list"),
}).describe("Updates an existing Gmail label");

export const DeleteLabelSchema = z.object({
  id: z.string().describe("ID of the label to delete"),
}).describe("Deletes a Gmail label");

export const GetOrCreateLabelSchema = z.object({
  name: z.string().describe("Name of the label to get or create"),
  messageListVisibility: z.enum(['show', 'hide']).optional().describe("Whether to show or hide the label in the message list"),
  labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("Visibility of the label in the label list"),
}).describe("Gets an existing label by name or creates it if it doesn't exist");

export const BatchModifyEmailsSchema = z.object({
  messageIds: z.array(z.string()).describe("List of message IDs to modify"),
  addLabelIds: z.array(z.string()).optional().describe("List of label IDs to add to all messages"),
  removeLabelIds: z.array(z.string()).optional().describe("List of label IDs to remove from all messages"),
  batchSize: z.number().optional().default(50).describe("Number of messages to process in each batch (default: 50)"),
});

export const ReportPhishingSchema = z.object({
  messageId: z.string().describe("ID of the email message to report as phishing"),
}).describe("Reports a message as phishing using the closest public Gmail API behavior by applying the SPAM label");

export const BatchReportPhishingSchema = z.object({
  messageIds: z.array(z.string()).describe("List of message IDs to report as phishing"),
  batchSize: z.number().optional().default(50).describe("Number of messages to process in each batch (default: 50)"),
}).describe("Reports multiple messages as phishing using the closest public Gmail API behavior by applying the SPAM label");

export const BatchDeleteEmailsSchema = z.object({
  messageIds: z.array(z.string()).describe("List of message IDs to delete"),
  batchSize: z.number().optional().default(50).describe("Number of messages to process in each batch (default: 50)"),
});

export const TrashEmailSchema = z.object({
  messageId: z.string().describe("ID of the email message to move to Trash"),
});
export const BatchTrashEmailsSchema = z.object({
  messageIds: z.array(z.string()).describe("List of message IDs to move to Trash"),
  batchSize: z.number().optional().default(50).describe("Number of messages to process in each batch (default: 50)"),
});

export const CreateFilterSchema = z.object({
  criteria: z.object({
    from: z.string().optional().describe("Sender email address to match"),
    to: z.string().optional().describe("Recipient email address to match"),
    subject: z.string().optional().describe("Subject text to match"),
    query: z.string().optional().describe("Gmail search query (e.g., 'has:attachment')"),
    negatedQuery: z.string().optional().describe("Text that must NOT be present"),
    hasAttachment: z.boolean().optional().describe("Whether to match emails with attachments"),
    excludeChats: z.boolean().optional().describe("Whether to exclude chat messages"),
    size: z.number().optional().describe("Email size in bytes"),
    sizeComparison: z.enum(['unspecified', 'smaller', 'larger']).optional().describe("Size comparison operator")
  }).describe("Criteria for matching emails"),
  action: z.object({
    addLabelIds: z.array(z.string()).optional().describe("Label IDs to add to matching emails"),
    removeLabelIds: z.array(z.string()).optional().describe("Label IDs to remove from matching emails"),
    forward: z.string().optional().describe("Email address to forward matching emails to")
  }).describe("Actions to perform on matching emails")
}).describe("Creates a new Gmail filter");

export const ListFiltersSchema = z.object({}).describe("Retrieves all Gmail filters");

export const GetFilterSchema = z.object({
  filterId: z.string().describe("ID of the filter to retrieve")
}).describe("Gets details of a specific Gmail filter");

export const DeleteFilterSchema = z.object({
  filterId: z.string().describe("ID of the filter to delete")
}).describe("Deletes a Gmail filter");

export const CreateFilterFromTemplateSchema = z.object({
  template: z.enum(['fromSender', 'withSubject', 'withAttachments', 'largeEmails', 'containingText', 'mailingList']).describe("Pre-defined filter template to use"),
  parameters: z.object({
    senderEmail: z.string().optional().describe("Sender email (for fromSender template)"),
    subjectText: z.string().optional().describe("Subject text (for withSubject template)"),
    searchText: z.string().optional().describe("Text to search for (for containingText template)"),
    listIdentifier: z.string().optional().describe("Mailing list identifier (for mailingList template)"),
    sizeInBytes: z.number().optional().describe("Size threshold in bytes (for largeEmails template)"),
    labelIds: z.array(z.string()).optional().describe("Label IDs to apply"),
    archive: z.boolean().optional().describe("Whether to archive (skip inbox)"),
    markAsRead: z.boolean().optional().describe("Whether to mark as read"),
    markImportant: z.boolean().optional().describe("Whether to mark as important")
  }).describe("Template-specific parameters")
}).describe("Creates a filter using a pre-defined template");

export const DownloadAttachmentSchema = z.object({
  messageId: z.string().describe("ID of the email message containing the attachment"),
  attachmentId: z.string().describe("ID of the attachment to download"),
  filename: z.string().optional().describe("Filename to save the attachment as (if not provided, uses original filename)"),
  savePath: z.string().optional().describe("Directory path to save the attachment (defaults to current directory)"),
});

export const DownloadEmailSchema = z.object({
  messageId: z.string().describe("ID of the email message to download"),
  savePath: z.string().describe("Directory path to save the email file"),
  format: z.enum(['json', 'eml', 'txt', 'html']).optional().default('json')
    .describe("Output format: json (structured data), eml (raw RFC822), txt (plain text), html (formatted HTML)"),
});

export const ModifyThreadSchema = z.object({
  threadId: z.string().describe("ID of the Gmail thread to modify"),
  addLabelIds: z.array(z.string()).optional().describe("List of label IDs to add to all messages in the thread"),
  removeLabelIds: z.array(z.string()).optional().describe("List of label IDs to remove from all messages in the thread"),
});

// Thread-level schemas
export const GetThreadSchema = z.object({
  threadId: z.string().describe("ID of the email thread to retrieve"),
  format: z.enum(['full', 'metadata', 'minimal']).optional().default('full').describe("Format of the email messages returned (default: full)"),
});

export const ListInboxThreadsSchema = z.object({
  query: z.string().optional().default('in:inbox').describe("Gmail search query (default: 'in:inbox')"),
  maxResults: z.number().optional().default(50).describe("Maximum number of threads to return (default: 50)"),
});

export const GetInboxWithThreadsSchema = z.object({
  query: z.string().optional().default('in:inbox').describe("Gmail search query (default: 'in:inbox')"),
  maxResults: z.number().optional().default(50).describe("Maximum number of threads to return (default: 50)"),
  expandThreads: z.boolean().optional().default(true).describe("Whether to fetch full thread content for each thread (default: true)"),
});

// Reply All schema - fetches original email and builds recipient list automatically
export const ReplyAllSchema = z.object({
  messageId: z.string().describe("ID of the email message to reply to"),
  body: z.string().describe("Reply body in Markdown. Rendered to HTML and sent as multipart/alternative (HTML plus this text as the plain-text part) by default."),
  htmlBody: z.string().optional().describe("Explicit HTML body. Overrides the HTML rendered from the Markdown body; only needed for hand-authored HTML."),
  mimeType: z.enum(['text/plain', 'text/html', 'multipart/alternative']).optional().describe("Override the content type. Omit for the default multipart/alternative (Markdown-rendered HTML plus plain text). Use 'text/plain' only when a plain-text-only message is explicitly required."),
  attachments: z.array(z.string()).optional().describe("List of file paths to attach to the reply"),
  from: z.string().optional().describe("Send the reply as this address (must be a configured send-as alias in Gmail settings). Defaults to the account's default send-as address. Use list_send_as to discover available aliases."),
});

export const ListSendAsSchema = z.object({});

// Draft integrity: messages holding both DRAFT and TRASH, which Gmail hides as
// deleted while IMAP clients keep listing them in Drafts.
export const FindStrandedDraftsSchema = z.object({});

export const RepairDraftsSchema = z.object({
  mode: z.enum(['restore', 'discard']).describe("restore: remove TRASH so the message is a live draft again in both Gmail and IMAP clients. discard: remove DRAFT so it is an ordinary trashed message and stops appearing in IMAP Drafts folders. Neither mode deletes anything."),
  messageIds: z.array(z.string()).optional().describe("Limit the repair to these message IDs. Omit to repair every stranded draft in the mailbox."),
});

// Mailbox settings schemas (users.settings.*)
export const GetSettingsSchema = z.object({});

export const SetSignatureSchema = z.object({
  signature: z.string().optional().describe("Signature in Markdown, rendered to HTML before saving. Pass an empty string to clear the signature."),
  signatureHtml: z.string().optional().describe("Explicit HTML signature, saved verbatim. Overrides the HTML rendered from the Markdown signature; only needed for hand-authored HTML."),
  sendAsEmail: z.string().optional().describe("Which send-as address to change. Defaults to the account's default From address. Use list_send_as to see the options."),
});

export const UpdateSendAsSchema = z.object({
  sendAsEmail: z.string().optional().describe("Which send-as address to change. Defaults to the account's default From address. Use list_send_as to see the options."),
  displayName: z.string().optional().describe("Name shown in the From header. Pass an empty string to clear it. Gmail silently ignores this for the primary address when an admin has disabled name changes; the tool reports when that happens."),
  replyToAddress: z.string().optional().describe("Address to put in the Reply-To header for mail sent from this alias. Pass an empty string to remove the header."),
  treatAsAlias: z.boolean().optional().describe("Whether Gmail treats this address as an alias of the primary address. Applies only to custom From addresses."),
  makeDefault: z.literal(true).optional().describe("Promote this address to the default From address. Only true is accepted: an account always has exactly one default, changed by promoting another address."),
});

export const SetVacationResponderSchema = z.object({
  enabled: z.boolean().describe("Turn the vacation responder on or off. Turning it off leaves the stored subject and body in place."),
  subject: z.string().optional().describe("Subject prefix for auto-replies. Gmail needs a nonempty subject or body to enable the responder."),
  body: z.string().optional().describe("Auto-reply body in Markdown, rendered to HTML before saving."),
  bodyHtml: z.string().optional().describe("Explicit HTML auto-reply body, saved verbatim. Overrides the HTML rendered from the Markdown body."),
  startTime: z.string().optional().describe("When to start auto-replying, as an ISO date (2026-08-20) or datetime (2026-08-20T09:00:00-07:00). A bare date is treated as UTC midnight, so pass an offset if the exact local hour matters."),
  endTime: z.string().optional().describe("When to stop auto-replying, same format as startTime. Must be after startTime."),
  restrictToContacts: z.boolean().optional().describe("Only auto-reply to senders in the user's contacts."),
  restrictToDomain: z.boolean().optional().describe("Only auto-reply to senders inside the user's own domain. Google Workspace accounts only."),
});

// Tool definition type
export interface ToolAnnotations {
  title: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

export interface ToolDefinition {
  name: string;
  description: string;
  schema: z.ZodType<any>;
  scopes: string[]; // Any of these scopes grants access
  annotations: ToolAnnotations;
}

// Tool registry with scope requirements
export const toolDefinitions: ToolDefinition[] = [
  // Read-only email operations
  {
    name: "read_email",
    description: "Retrieves the content of a specific email",
    schema: ReadEmailSchema,
    scopes: ["gmail.readonly", "gmail.modify"],
    annotations: { title: "Read Email", readOnlyHint: true },
  },
  {
    name: "search_emails",
    description: "Searches for emails using Gmail search syntax Draft message ids rotate when a draft is saved, so a previously returned id can 404; re-search or use list_drafts rather than caching draft message ids.",
    schema: SearchEmailsSchema,
    scopes: ["gmail.readonly", "gmail.modify"],
    annotations: { title: "Search Emails", readOnlyHint: true },
  },
  {
    name: "download_attachment",
    description: "Downloads an email attachment to a specified location",
    schema: DownloadAttachmentSchema,
    scopes: ["gmail.readonly", "gmail.modify"],
    annotations: { title: "Download Attachment", readOnlyHint: true },
  },

  // Thread-level operations
  {
    name: "get_thread",
    description: "Retrieves all messages in an email thread in one call. Returns messages ordered chronologically (oldest first) with full content, headers, labels, and attachment metadata.",
    schema: GetThreadSchema,
    scopes: ["gmail.readonly", "gmail.modify"],
    annotations: { title: "Get Thread", readOnlyHint: true },
  },
  {
    name: "list_inbox_threads",
    description: "Lists email threads matching a query (default: inbox). Returns thread-level view with snippet, message count, and latest message metadata.",
    schema: ListInboxThreadsSchema,
    scopes: ["gmail.readonly", "gmail.modify"],
    annotations: { title: "List Inbox Threads", readOnlyHint: true },
  },
  {
    name: "get_inbox_with_threads",
    description: "Convenience tool that lists threads and optionally expands each with full message content. One call returns the full inbox with complete thread bodies.",
    schema: GetInboxWithThreadsSchema,
    scopes: ["gmail.readonly", "gmail.modify"],
    annotations: { title: "Get Inbox with Threads", readOnlyHint: true },
  },
  {
    name: "modify_thread",
    description: "Modifies labels on ALL messages in a thread atomically using the Gmail threads.modify endpoint. Use this instead of modify_email when you want to apply label changes (e.g., archive, mark as read) to an entire thread at once.",
    schema: ModifyThreadSchema,
    scopes: ["gmail.modify"],
    annotations: { title: "Modify Thread", destructiveHint: true, idempotentHint: true },
  },
  {
    name: "download_email",
    description: "Downloads an email to a file in various formats (json, eml, txt, html). Returns metadata only - useful for saving emails without consuming context.",
    schema: DownloadEmailSchema,
    scopes: ["gmail.readonly", "gmail.modify"],
    annotations: { title: "Download Email", readOnlyHint: true },
  },

  // Email write operations
  {
    name: "send_email",
    description: "Sends a new email. The body is Markdown and is sent as HTML (multipart/alternative) by default.",
    schema: SendEmailSchema,
    scopes: ["gmail.modify", "gmail.compose", "gmail.send"],
    annotations: { title: "Send Email", destructiveHint: false },
  },
  {
    name: "draft_email",
    description: "Draft a new email. The body is Markdown and is sent as HTML (multipart/alternative) by default.",
    schema: SendEmailSchema,
    scopes: ["gmail.modify", "gmail.compose"],
    annotations: { title: "Draft Email", destructiveHint: false },
  },
  {
    name: "send_draft",
    description: "Sends an existing draft (created via draft_email) and atomically removes it from Drafts. Prefer this over send_email when you've previously created a draft for review — avoids leaving an orphan draft in the user's Drafts folder.",
    schema: SendDraftSchema,
    scopes: ["gmail.modify", "gmail.compose", "gmail.send"],
    annotations: { title: "Send Draft", destructiveHint: false },
  },
  {
    name: "delete_draft",
    description: "Deletes a draft. Use to discard an abandoned or superseded draft.",
    schema: DeleteDraftSchema,
    scopes: ["gmail.modify", "gmail.compose"],
    annotations: { title: "Delete Draft", destructiveHint: true },
  },
  {
    name: "read_draft",
    description: "Reads an outstanding draft's current content: recipients, subject, body and attachments, plus a baseToken. Call this before update_draft, always. The user may have edited the draft in Gmail since you last saw it, and update_draft requires the baseToken from this read so an edit cannot silently discard their changes.",
    schema: ReadDraftSchema,
    scopes: ["gmail.readonly", "gmail.modify", "gmail.compose"],
    annotations: { title: "Read Draft", readOnlyHint: true },
  },
  {
    name: "list_drafts",
    description: "Lists the outstanding drafts in the mailbox with their recipients, subject and a snippet, so a draft can be found by what it says rather than by remembering its ID. Use read_draft for a draft's full content.",
    schema: ListDraftsSchema,
    scopes: ["gmail.readonly", "gmail.modify", "gmail.compose"],
    annotations: { title: "List Drafts", readOnlyHint: true },
  },
  {
    name: "update_draft",
    description: "Revises an existing draft in place, keeping its ID. Requires the baseToken from read_draft: the draft is re-read at edit time and the edit refused if it changed since that read, so revisions cannot overwrite what the user wrote in Gmail. Fields you omit keep their current values, so changing only the subject leaves the body alone. The body is Markdown and is sent as HTML (multipart/alternative) by default.",
    schema: UpdateDraftSchema,
    scopes: ["gmail.modify", "gmail.compose"],
    annotations: { title: "Update Draft", destructiveHint: false },
  },
  {
    name: "modify_email",
    description: "Modifies email labels (move to different folders)",
    schema: ModifyEmailSchema,
    scopes: ["gmail.modify"],
    annotations: { title: "Modify Email", destructiveHint: true, idempotentHint: true },
  },
  {
    name: "trash_email",
    description: "Moves an email to Trash (recoverable for 30 days). Prefer this over delete_email — delete_email is a permanent, irreversible delete. Refuses to trash a draft: that would leave the message holding both DRAFT and TRASH, which hides it from Gmail while IMAP clients such as Apple Mail keep listing it in Drafts. Discard drafts with delete_draft instead.",
    schema: TrashEmailSchema,
    scopes: ["gmail.modify"],
    annotations: { title: "Trash Email", destructiveHint: false, idempotentHint: true },
  },
  {
    name: "batch_trash_emails",
    description: "Moves multiple emails to Trash (recoverable for 30 days). Prefer this over batch_delete_emails for clearing the inbox. If any id in the batch is a draft, nothing is trashed and every offending id is named, because trashing a draft strands it as visible in IMAP clients but deleted in Gmail.",
    schema: BatchTrashEmailsSchema,
    scopes: ["gmail.modify"],
    annotations: { title: "Batch Trash Emails", destructiveHint: false, idempotentHint: true },
  },
  {
    name: "find_stranded_drafts",
    description: "Finds messages holding both the DRAFT and TRASH labels. Gmail hides these as \"N deleted messages in this conversation\" while IMAP clients such as Apple Mail keep listing them in the Drafts folder, so the same message looks deleted in one client and editable in another. Use repair_drafts to resolve them.",
    schema: FindStrandedDraftsSchema,
    scopes: ["gmail.readonly", "gmail.modify"],
    annotations: { title: "Find Stranded Drafts", readOnlyHint: true },
  },
  {
    name: "repair_drafts",
    description: "Resolves messages stuck holding both DRAFT and TRASH into one consistent state. mode \"restore\" removes TRASH so they are live drafts again in Gmail and in IMAP clients; mode \"discard\" removes DRAFT so they are ordinary trashed messages. Neither mode deletes anything, so a wrong choice is recoverable.",
    schema: RepairDraftsSchema,
    scopes: ["gmail.modify"],
    annotations: { title: "Repair Stranded Drafts", destructiveHint: false, idempotentHint: true },
  },
  {
    name: "delete_email",
    description: "PERMANENTLY deletes an email (bypasses Trash, cannot be undone). Use trash_email instead unless permanent deletion is explicitly required.",
    schema: DeleteEmailSchema,
    scopes: ["gmail.modify"],
    annotations: { title: "Delete Email", destructiveHint: true },
  },
  {
    name: "batch_modify_emails",
    description: "Modifies labels for multiple emails in batches",
    schema: BatchModifyEmailsSchema,
    scopes: ["gmail.modify"],
    annotations: { title: "Batch Modify Emails", destructiveHint: true, idempotentHint: true },
  },
  {
    name: "report_phishing",
    description: "Reports a message as phishing using the closest public Gmail API behavior by applying the SPAM label",
    schema: ReportPhishingSchema,
    scopes: ["gmail.modify"],
    annotations: { title: "Report Phishing", destructiveHint: true, idempotentHint: true },
  },
  {
    name: "batch_report_phishing",
    description: "Reports multiple messages as phishing using the closest public Gmail API behavior by applying the SPAM label",
    schema: BatchReportPhishingSchema,
    scopes: ["gmail.modify"],
    annotations: { title: "Batch Report Phishing", destructiveHint: true, idempotentHint: true },
  },
  {
    name: "batch_delete_emails",
    description: "PERMANENTLY deletes multiple emails (bypasses Trash, cannot be undone). Use batch_trash_emails instead unless permanent deletion is explicitly required.",
    schema: BatchDeleteEmailsSchema,
    scopes: ["gmail.modify"],
    annotations: { title: "Batch Delete Emails", destructiveHint: true },
  },

  // Label operations
  {
    name: "list_email_labels",
    description: "Retrieves all available Gmail labels",
    schema: ListEmailLabelsSchema,
    scopes: ["gmail.readonly", "gmail.modify", "gmail.labels"],
    annotations: { title: "List Email Labels", readOnlyHint: true },
  },
  {
    name: "create_label",
    description: "Creates a new Gmail label",
    schema: CreateLabelSchema,
    scopes: ["gmail.modify", "gmail.labels"],
    annotations: { title: "Create Label", destructiveHint: false },
  },
  {
    name: "update_label",
    description: "Updates an existing Gmail label",
    schema: UpdateLabelSchema,
    scopes: ["gmail.modify", "gmail.labels"],
    annotations: { title: "Update Label", destructiveHint: true, idempotentHint: true },
  },
  {
    name: "delete_label",
    description: "Deletes a Gmail label",
    schema: DeleteLabelSchema,
    scopes: ["gmail.modify", "gmail.labels"],
    annotations: { title: "Delete Label", destructiveHint: true },
  },
  {
    name: "get_or_create_label",
    description: "Gets an existing label by name or creates it if it doesn't exist",
    schema: GetOrCreateLabelSchema,
    scopes: ["gmail.modify", "gmail.labels"],
    annotations: { title: "Get or Create Label", destructiveHint: false, idempotentHint: true },
  },

  // Filter operations (require settings scope)
  {
    name: "list_filters",
    description: "Retrieves all Gmail filters",
    schema: ListFiltersSchema,
    scopes: ["gmail.settings.basic"],
    annotations: { title: "List Filters", readOnlyHint: true },
  },
  {
    name: "get_filter",
    description: "Gets details of a specific Gmail filter",
    schema: GetFilterSchema,
    scopes: ["gmail.settings.basic"],
    annotations: { title: "Get Filter", readOnlyHint: true },
  },
  {
    name: "list_send_as",
    description: "Lists the send-as addresses (aliases) configured for the account, including which is the default and each one's verification status. Use the address as the 'from' parameter on send_email, draft_email, or reply_all to send as that alias.",
    schema: ListSendAsSchema,
    scopes: ["gmail.settings.basic"],
    annotations: { title: "List Send-As Aliases", readOnlyHint: true },
  },
  {
    name: "create_filter",
    description: "Creates a new Gmail filter with custom criteria and actions",
    schema: CreateFilterSchema,
    scopes: ["gmail.settings.basic"],
    annotations: { title: "Create Filter", destructiveHint: false },
  },
  {
    name: "delete_filter",
    description: "Deletes a Gmail filter",
    schema: DeleteFilterSchema,
    scopes: ["gmail.settings.basic"],
    annotations: { title: "Delete Filter", destructiveHint: true },
  },
  {
    name: "create_filter_from_template",
    description: "Creates a filter using a pre-defined template for common scenarios",
    schema: CreateFilterFromTemplateSchema,
    scopes: ["gmail.settings.basic"],
    annotations: { title: "Create Filter from Template", destructiveHint: false },
  },

  // Reply-all operation
  {
    name: "reply_all",
    description: "Replies to all recipients of an email. Automatically fetches the original email to build the recipient list (To, CC) and sets proper threading headers. The body is Markdown and is sent as HTML (multipart/alternative) by default.",
    schema: ReplyAllSchema,
    scopes: ["gmail.modify", "gmail.compose", "gmail.send"],
    annotations: { title: "Reply All", destructiveHint: false },
  },

  // Mailbox settings
  {
    name: "get_settings",
    description: "Reads the account's mailbox settings in one call: send-as addresses (with their signatures), vacation responder, auto-forwarding, forwarding addresses, delegates, IMAP, POP and display language. Each section reports its own state, so a section this account is not permitted to read is reported as unreadable rather than as empty or off. Use this to answer \"what is my mailbox configured to do\" and to check whether anything is forwarding or delegating mail.",
    schema: GetSettingsSchema,
    scopes: ["gmail.readonly", "gmail.modify", "gmail.settings.basic"],
    annotations: { title: "Get Mailbox Settings", readOnlyHint: true },
  },
  {
    name: "set_signature",
    description: "Sets the Gmail signature on a send-as address. The signature is Markdown and is rendered to HTML before saving. Note this is the signature Gmail appends when composing in the Gmail web UI; it is not added to mail sent through this server's send_email tool. Gmail sanitizes signature HTML, and the tool reports when what Gmail stored differs from what was sent.",
    schema: SetSignatureSchema,
    scopes: ["gmail.settings.basic", "gmail.settings.sharing"],
    annotations: { title: "Set Signature", destructiveHint: false, idempotentHint: true },
  },
  {
    name: "update_send_as",
    description: "Updates the identity fields of a send-as address: display name, Reply-To address, alias handling, and which address is the default From. Use set_signature for the signature. Only the fields provided are changed.",
    schema: UpdateSendAsSchema,
    scopes: ["gmail.settings.basic", "gmail.settings.sharing"],
    annotations: { title: "Update Send-As Address", destructiveHint: false, idempotentHint: true },
  },
  {
    name: "set_vacation_responder",
    description: "Turns the vacation responder (out-of-office auto-reply) on or off, with an optional subject, Markdown body, and start/end dates. Current settings are read and merged, so fields that are not provided keep their existing values.",
    schema: SetVacationResponderSchema,
    scopes: ["gmail.settings.basic"],
    annotations: { title: "Set Vacation Responder", destructiveHint: false, idempotentHint: true },
  },
];

// Convert tool definitions to MCP tool format
export function toMcpTools(tools: ToolDefinition[]) {
  return tools.map(tool => ({
    name: tool.name,
    description: tool.description,
    inputSchema: zodToJsonSchema(tool.schema),
    annotations: tool.annotations,
  }));
}

// Get a tool definition by name
export function getToolByName(name: string): ToolDefinition | undefined {
  return toolDefinitions.find(t => t.name === name);
}
