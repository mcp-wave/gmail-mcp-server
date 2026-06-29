#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { google } from 'googleapis';
import { OAuth2Client } from 'google-auth-library';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import http from 'http';
import open from 'open';
import os from 'os';
import {createEmailMessage, createEmailWithNodemailer} from "./utl.js";
import { createLabel, updateLabel, deleteLabel, listLabels, findLabelByName, getOrCreateLabel, GmailLabel } from "./label-manager.js";
import { createFilter, listFilters, getFilter, deleteFilter, filterTemplates, GmailFilterCriteria, GmailFilterAction } from "./filter-manager.js";
import { parseEmailAddresses, filterOutEmail, addRePrefix, buildReferencesHeader, buildReplyAllRecipients } from "./reply-all-helpers.js";
import { DEFAULT_SCOPES, scopeNamesToUrls, parseScopes, validateScopes, hasScope, getAvailableScopeNames } from "./scopes.js";
import { toolDefinitions, toMcpTools, getToolByName, SendEmailSchema, ReadEmailSchema, SearchEmailsSchema, ModifyEmailSchema, DeleteEmailSchema, BatchModifyEmailsSchema, ReportPhishingSchema, BatchReportPhishingSchema, BatchDeleteEmailsSchema, CreateLabelSchema, UpdateLabelSchema, DeleteLabelSchema, GetOrCreateLabelSchema, CreateFilterSchema, GetFilterSchema, DeleteFilterSchema, CreateFilterFromTemplateSchema, DownloadAttachmentSchema, ReplyAllSchema, GetThreadSchema, ListInboxThreadsSchema, GetInboxWithThreadsSchema, DownloadEmailSchema, ModifyThreadSchema, SendDraftSchema, DeleteDraftSchema, UpdateDraftSchema, ListSendAsSchema, TrashEmailSchema, BatchTrashEmailsSchema } from "./tools.js";
import { gmailMessageToJson, emailToTxt, emailToHtml, EmailAttachment } from "./email-export.js";
import type { Account, PrincipalSession, ResolveSession, SendPolicy } from "./session.js";
import { disallowedRecipients, emailAddressOf, isPublicEmailDomain, rejectedAllowlistEntry, type SendContext } from "./send-policy.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Configuration paths
const CONFIG_DIR = path.join(os.homedir(), '.gmail-mcp');
const OAUTH_PATH = process.env.GMAIL_OAUTH_PATH || path.join(CONFIG_DIR, 'gcp-oauth.keys.json');
const CREDENTIALS_PATH = process.env.GMAIL_CREDENTIALS_PATH || path.join(CONFIG_DIR, 'credentials.json');

// Type definitions for Gmail API responses
interface GmailMessagePart {
    partId?: string;
    mimeType?: string;
    filename?: string;
    headers?: Array<{
        name: string;
        value: string;
    }>;
    body?: {
        attachmentId?: string;
        size?: number;
        data?: string;
    };
    parts?: GmailMessagePart[];
}

interface EmailContent {
    text: string;
    html: string;
}

// OAuth2 configuration
let oauth2Client: OAuth2Client;
let authorizedScopes: string[] = DEFAULT_SCOPES;

// A per-request session: the Gmail client to use and the scopes it is authorized
// for. resolveSession turns the transport's request context (`extra`, which
// carries the validated bearer's AuthInfo in http mode) into one of these.
// Tools that mutate a mailbox require an explicit `account` when more than one is
// linked (the agent must never cross-write by accident). Everything not listed is
// a read and fans out across all linked accounts by default.
const WRITE_TOOLS = new Set([
    'send_email', 'draft_email', 'send_draft', 'delete_draft', 'update_draft',
    'modify_email', 'delete_email', 'batch_modify_emails', 'report_phishing',
    'batch_report_phishing', 'batch_delete_emails', 'trash_email', 'batch_trash_emails',
    'create_label', 'update_label',
    'delete_label', 'get_or_create_label', 'create_filter', 'delete_filter',
    'create_filter_from_template', 'reply_all', 'modify_thread',
]);

const errText = (text: string) => ({ content: [{ type: 'text', text }] });

function unionScopes(accounts: Account[]): string[] {
    const s = new Set<string>();
    for (const a of accounts) for (const sc of a.scopeNames) s.add(sc);
    return [...s];
}

function findAccount(session: PrincipalSession, selector: string): Account | undefined {
    const sel = String(selector).trim().toLowerCase();
    if (sel === 'primary') return session.accounts.find(a => a.primary) || session.accounts[0];
    return session.accounts.find(a => a.email.toLowerCase() === sel || a.sub === selector);
}

function stripAccount(args: any): any {
    if (!args || typeof args !== 'object') return args;
    const { account, ...rest } = args;
    void account;
    return rest;
}

// Prepend an account header so multi-account read results are always attributable.
function annotate(email: string, primary: boolean, result: any): any {
    const header = { type: 'text', text: `=== ${email}${primary ? ' (primary)' : ''} ===` };
    return { ...result, content: [header, ...(result?.content || [])] };
}

// `account` parameter injected into every Gmail tool's schema so the agent knows
// it can target a mailbox (and must, for writes, when multiple are linked).
const ACCOUNT_PARAM = {
    account: {
        type: 'string',
        description:
            'Which linked mailbox (email address) to act on. Reads: omit to search ALL linked accounts (results are labeled by account). Writes: required when more than one account is linked.',
    },
};

function metaToolDefs(session: PrincipalSession): any[] {
    const tools: any[] = [{
        name: 'list_accounts',
        description: 'List the Gmail accounts linked to this connection (email and which is primary).',
        inputSchema: { type: 'object', properties: {} },
    }];
    if (session.linkAccount) {
        tools.push({
            name: 'link_account',
            description: 'Link an additional Gmail account. Returns a sign-in link the user opens to authorize the new mailbox; afterwards it is available to all email tools.',
            inputSchema: { type: 'object', properties: {} },
        });
        tools.push({
            name: 'unlink_account',
            description: 'Unlink a previously linked Gmail account by email address.',
            inputSchema: { type: 'object', properties: { account: { type: 'string', description: 'Email address of the account to unlink.' } }, required: ['account'] },
        });
    }
    if (session.setSendPolicy) {
        tools.push({
            name: 'get_send_policy',
            description: "Show the outbound send policy (allowlist / dangerous flag) for each linked account. Sending to an account's own address is always allowed.",
            inputSchema: { type: 'object', properties: { account: { type: 'string', description: 'Email of the account (optional; defaults to all).' } } },
        });
        tools.push({
            name: 'allow_send_recipient',
            description: 'Permanently allow an account to send to a recipient or domain (adds to its allowlist). Confirms with the user first. Use this when the user wants to whitelist someone for the future.',
            inputSchema: { type: 'object', properties: { account: { type: 'string', description: 'Email of the sending account.' }, recipient: { type: 'string', description: 'Email address or domain to allow (e.g. boss@acme.com or acme.com).' } }, required: ['recipient'] },
        });
        tools.push({
            name: 'disallow_send_recipient',
            description: "Remove a recipient or domain from an account's send allowlist. Confirms with the user first.",
            inputSchema: { type: 'object', properties: { account: { type: 'string', description: 'Email of the sending account.' }, recipient: { type: 'string', description: 'Email address or domain to remove.' } }, required: ['recipient'] },
        });
        tools.push({
            name: 'set_dangerous_send',
            description: 'Turn the "allow sending to anyone" blanket override on or off for an account. Strongly confirms with the user first.',
            inputSchema: { type: 'object', properties: { account: { type: 'string', description: 'Email of the account.' }, enabled: { type: 'boolean', description: 'true = allow sending to anyone (no checks); false = restore the allowlist gate.' } }, required: ['enabled'] },
        });
    }
    return tools;
}

async function metaListAccounts(session: PrincipalSession) {
    const lines = session.accounts.map(
        a => `- ${a.email}${a.primary ? ' (primary)' : ''}`,
    );
    return errText(`Linked accounts (${session.accounts.length}):\n${lines.join('\n')}`);
}

async function metaLinkAccount(session: PrincipalSession) {
    if (!session.linkAccount) {
        return errText('Linking additional accounts is only available on the hosted server.');
    }
    const url = await session.linkAccount();
    return errText(
        `To link another Gmail account, open this link and sign in with the account you want to add:\n${url}\n\nAfter you authorize, it becomes available to all email tools.`,
    );
}

async function metaUnlinkAccount(session: PrincipalSession, args: any) {
    if (!session.unlinkAccount) {
        return errText('Unlinking is only available on the hosted server.');
    }
    const acct = args?.account ? findAccount(session, args.account) : undefined;
    if (!acct) {
        return errText(`Specify which account to unlink. Linked: ${session.accounts.map(a => a.email).join(', ')}`);
    }
    if (acct.primary) return errText('Cannot unlink the primary account.');
    await session.unlinkAccount(acct.sub);
    return errText(`Unlinked ${acct.email}.`);
}

// --- Send-policy management meta tools (hosted only) ------------------------

function describePolicy(p?: SendPolicy): string {
    if (p?.dangerouslyAllowAll) return 'DANGEROUS — may send to anyone';
    if (p && p.allowlist.length) return `allowed: ${p.allowlist.join(', ')} (+ own address)`;
    return 'own address only';
}

/** Resolve which account a settings tool targets. */
function settingsAccount(session: PrincipalSession, args: any): Account | { error: string } {
    if (args?.account) {
        const a = findAccount(session, args.account);
        return a || { error: `account "${args.account}" is not linked. Linked: ${session.accounts.map(x => x.email).join(', ')}` };
    }
    if (session.accounts.length === 1) return session.accounts[0];
    return { error: `Specify which account: ${session.accounts.map(a => a.email).join(', ')}` };
}

async function metaGetSendPolicy(session: PrincipalSession, args: any) {
    const accts = args?.account
        ? session.accounts.filter(a => a === findAccount(session, args.account))
        : session.accounts;
    if (accts.length === 0) return errText('No matching account.');
    const lines = accts.map(a => `- ${a.email}: ${describePolicy(a.sendPolicy)}`);
    return errText(`Send policy (sending to an account's own address is always allowed):\n${lines.join('\n')}`);
}

async function metaAllowSender(session: PrincipalSession, server: Server, args: any) {
    if (!session.setSendPolicy) return errText('Send settings are only available on the hosted server.');
    const acct = settingsAccount(session, args);
    if ('error' in acct) return errText(`Error: ${acct.error}`);
    const entry = String(args?.recipient || '').trim().toLowerCase();
    if (!entry) return errText('Provide a recipient email address or domain to allow.');
    const rejected = rejectedAllowlistEntry(entry);
    if (rejected) return errText(`Error: ${rejected}`);
    const confirm = await elicitConfirm(server, `Always allow ${acct.email} to send to "${entry}"?`);
    if (confirm.supported && confirm.choice !== 'yes') return errText('No change made.');
    const cur = acct.sendPolicy || { allowlist: [], dangerouslyAllowAll: false };
    const merged = Array.from(new Set([...cur.allowlist, entry]));
    await session.setSendPolicy(acct.sub, { allowlist: merged, dangerouslyAllowAll: cur.dangerouslyAllowAll });
    return errText(`Allowed "${entry}" for ${acct.email}. Now: ${describePolicy({ allowlist: merged, dangerouslyAllowAll: cur.dangerouslyAllowAll })}.`);
}

async function metaDisallowSender(session: PrincipalSession, server: Server, args: any) {
    if (!session.setSendPolicy) return errText('Send settings are only available on the hosted server.');
    const acct = settingsAccount(session, args);
    if ('error' in acct) return errText(`Error: ${acct.error}`);
    const entry = String(args?.recipient || '').trim().toLowerCase();
    if (!entry) return errText('Provide a recipient email address or domain to remove.');
    const confirm = await elicitConfirm(server, `Stop allowing ${acct.email} to send to "${entry}"?`);
    if (confirm.supported && confirm.choice !== 'yes') return errText('No change made.');
    const cur = acct.sendPolicy || { allowlist: [], dangerouslyAllowAll: false };
    const filtered = cur.allowlist.filter(e => e !== entry);
    await session.setSendPolicy(acct.sub, { allowlist: filtered, dangerouslyAllowAll: cur.dangerouslyAllowAll });
    return errText(`Removed "${entry}" from ${acct.email}. Now: ${describePolicy({ allowlist: filtered, dangerouslyAllowAll: cur.dangerouslyAllowAll })}.`);
}

async function metaSetDangerous(session: PrincipalSession, server: Server, args: any) {
    if (!session.setSendPolicy) return errText('Send settings are only available on the hosted server.');
    const acct = settingsAccount(session, args);
    if ('error' in acct) return errText(`Error: ${acct.error}`);
    const enabled = args?.enabled === true || args?.enabled === 'true' || args?.enabled === 'on';
    const confirm = await elicitConfirm(
        server,
        enabled
            ? `⚠️ Allow ${acct.email} to send email to ANYONE, with no recipient checks? This removes the send safety gate.`
            : `Turn OFF "send to anyone" for ${acct.email} and restore the allowlist gate?`,
    );
    if (confirm.supported && confirm.choice !== 'yes') return errText('No change made.');
    const cur = acct.sendPolicy || { allowlist: [], dangerouslyAllowAll: false };
    await session.setSendPolicy(acct.sub, { allowlist: cur.allowlist, dangerouslyAllowAll: enabled });
    return errText(`${acct.email}: "send to anyone" is now ${enabled ? 'ENABLED ⚠️' : 'disabled'}.`);
}

// --- Elicitation helpers ---------------------------------------------------
// MCP elicitation lets the SERVER ask the user a question mid-tool-call (via the
// client). elicitInput throws synchronously if the client hasn't advertised the
// elicitation capability, so we can fall back instantly with no hang.

const ELICIT_TIMEOUT_MS = 5 * 60 * 1000;

type ElicitOutcome = { supported: true; choice: string | null } | { supported: false };

/** Ask the user to pick one of `options` (value/label). Returns the chosen value. */
async function elicitChoice(
    server: Server,
    message: string,
    options: Array<{ value: string; label: string }>,
): Promise<ElicitOutcome> {
    try {
        const res = await server.elicitInput(
            {
                message,
                requestedSchema: {
                    type: 'object',
                    properties: {
                        choice: {
                            type: 'string',
                            description: 'How to proceed.',
                            enum: options.map((o) => o.value),
                            enumNames: options.map((o) => o.label),
                        },
                    },
                    required: ['choice'],
                },
            } as any,
            { timeout: ELICIT_TIMEOUT_MS },
        );
        if (res.action !== 'accept') return { supported: true, choice: null };
        const c = (res.content as any)?.choice;
        return { supported: true, choice: typeof c === 'string' ? c : null };
    } catch {
        // Client doesn't support elicitation (or it failed) — caller decides fallback.
        return { supported: false };
    }
}

/** Yes/no confirmation. Returns true only on an explicit "yes". */
async function elicitConfirm(server: Server, message: string): Promise<ElicitOutcome> {
    return elicitChoice(server, message, [
        { value: 'yes', label: 'Yes, proceed' },
        { value: 'no', label: 'No, cancel' },
    ]);
}

// Per-account send policy enforcement (logic in ./send-policy.ts).
function sendBlockedError(disallowed: string[]): { content: { type: string; text: string }[] } {
    return errText(
        `Error: this account is not allowed to send to: ${disallowed.join(', ')}. ` +
        `Create a draft instead (the user reviews and sends it), or the user can allow ` +
        `these recipients on the connection's setup screen (by email or domain).`,
    );
}

/**
 * Recursively extract email body content from MIME message parts
 * Handles complex email structures with nested parts
 */
function extractEmailContent(messagePart: GmailMessagePart): EmailContent {
    // Initialize containers for different content types
    let textContent = '';
    let htmlContent = '';

    // If the part has a body with data, process it based on MIME type
    if (messagePart.body && messagePart.body.data) {
        const content = Buffer.from(messagePart.body.data, 'base64').toString('utf8');

        // Store content based on its MIME type
        if (messagePart.mimeType === 'text/plain') {
            textContent = content;
        } else if (messagePart.mimeType === 'text/html') {
            htmlContent = content;
        }
    }

    // If the part has nested parts, recursively process them
    if (messagePart.parts && messagePart.parts.length > 0) {
        for (const part of messagePart.parts) {
            const { text, html } = extractEmailContent(part);
            if (text) textContent += text;
            if (html) htmlContent += html;
        }
    }

    // Return both plain text and HTML content
    return { text: textContent, html: htmlContent };
}

/**
 * Extract common headers from Gmail message payload
 */
function extractHeaders(payload: any): { subject: string; from: string; to: string; cc: string; bcc: string; date: string; rfcMessageId: string } {
    const headers = payload?.headers || [];
    const getHeader = (name: string) =>
        headers.find((h: any) => h.name?.toLowerCase() === name.toLowerCase())?.value || "";
    return {
        subject: getHeader("subject"),
        from: getHeader("from"),
        to: getHeader("to"),
        cc: getHeader("cc"),
        bcc: getHeader("bcc"),
        date: getHeader("date"),
        rfcMessageId: getHeader("message-id"),
    };
}

/**
 * Extract attachments from Gmail message payload
 */
function extractAttachments(payload: GmailMessagePart): EmailAttachment[] {
    const attachments: EmailAttachment[] = [];

    function processAttachmentParts(part: GmailMessagePart) {
        if (part.body && part.body.attachmentId) {
            attachments.push({
                id: part.body.attachmentId,
                filename: part.filename || `attachment-${part.body.attachmentId}`,
                mimeType: part.mimeType || "application/octet-stream",
                size: part.body.size || 0,
            });
        }
        if (part.parts) {
            part.parts.forEach((subpart: GmailMessagePart) => processAttachmentParts(subpart));
        }
    }

    processAttachmentParts(payload);
    return attachments;
}

async function loadCredentials() {
    try {
        // Create config directory if it doesn't exist
        if (!process.env.GMAIL_OAUTH_PATH && !process.env.GMAIL_CREDENTIALS_PATH && !fs.existsSync(CONFIG_DIR)) {
            fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
        }

        // Check for OAuth keys in current directory first, then in config directory
        const localOAuthPath = path.join(process.cwd(), 'gcp-oauth.keys.json');
        let oauthPath = OAUTH_PATH;

        if (fs.existsSync(localOAuthPath)) {
            // If found in current directory, copy to config directory
            fs.copyFileSync(localOAuthPath, OAUTH_PATH);
            console.log('OAuth keys found in current directory, copied to global config.');
        }

        if (!fs.existsSync(OAUTH_PATH)) {
            console.error('Error: OAuth keys file not found. Please place gcp-oauth.keys.json in current directory or', CONFIG_DIR);
            process.exit(1);
        }

        const keysContent = JSON.parse(fs.readFileSync(OAUTH_PATH, 'utf8'));
        const keys = keysContent.installed || keysContent.web;

        if (!keys) {
            console.error('Error: Invalid OAuth keys file format. File should contain either "installed" or "web" credentials.');
            process.exit(1);
        }

        // Parse callback URL from args (must be a URL, not a flag)
        // Supports: node index.js auth https://example.com/callback
        // Or: node index.js auth --scopes=gmail.readonly (uses default callback)
        const callbackArg = process.argv.find(arg =>
            arg.startsWith('http://') || arg.startsWith('https://')
        );
        const callback = callbackArg || "http://localhost:3000/oauth2callback";

        oauth2Client = new OAuth2Client(
            keys.client_id,
            keys.client_secret,
            callback
        );

        if (fs.existsSync(CREDENTIALS_PATH)) {
            const credentials = JSON.parse(fs.readFileSync(CREDENTIALS_PATH, 'utf8'));

            // Credentials file structure (v1.2.0+):
            //   { "tokens": { access_token, refresh_token, ... }, "scopes": ["gmail.readonly", ...] }
            //
            // Legacy structure (pre-v1.2.0):
            //   { access_token, refresh_token, ... }
            //
            // We support both formats for backwards compatibility. Users with legacy
            // credentials will get DEFAULT_SCOPES (full access) until they re-authenticate.
            const tokens = credentials.tokens || credentials;
            oauth2Client.setCredentials(tokens);

            if (credentials.scopes) {
                authorizedScopes = credentials.scopes;
            }
        }
    } catch (error) {
        console.error('Error loading credentials:', error);
        process.exit(1);
    }
}

async function authenticate(scopes: string[]) {
    const server = http.createServer();
    server.listen(3000, '127.0.0.1');

    // Convert shorthand scope names (e.g., "gmail.readonly") to full Google API URLs
    const scopeUrls = scopeNamesToUrls(scopes);

    return new Promise<void>((resolve, reject) => {
        const authUrl = oauth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: scopeUrls,
        });

        console.log('Requesting scopes:', scopes.join(', '));
        console.log('Please visit this URL to authenticate:', authUrl);
        open(authUrl);

        server.on('request', async (req, res) => {
            if (!req.url?.startsWith('/oauth2callback')) return;

            const url = new URL(req.url, 'http://localhost:3000');
            const code = url.searchParams.get('code');

            if (!code) {
                res.writeHead(400);
                res.end('No code provided');
                reject(new Error('No code provided'));
                return;
            }

            try {
                const { tokens } = await oauth2Client.getToken(code);
                oauth2Client.setCredentials(tokens);

                // Store both tokens and authorized scopes for runtime filtering
                const credentials = { tokens, scopes };
                fs.writeFileSync(CREDENTIALS_PATH, JSON.stringify(credentials, null, 2), { mode: 0o600 });

                res.writeHead(200);
                res.end('Authentication successful! You can close this window.');
                console.log('Credentials saved with scopes:', scopes.join(', '));
                server.close();
                resolve();
            } catch (error) {
                res.writeHead(500);
                res.end('Authentication failed');
                reject(error);
            }
        });
    });
}

// Main function
async function main() {
    // Remote (claude.ai) multi-tenant mode: loaded lazily so stdio users never
    // pull in Express / the OAuth stack. It manages its own per-user credentials
    // and does not use the single local account loaded by loadCredentials().
    if (process.argv[2] === 'http') {
        const { startHttpServer } = await import('./http/server.js');
        await startHttpServer(createMcpServer);
        return;
    }

    await loadCredentials();

    if (process.argv[2] === 'auth') {
        // Parse --scopes flag from CLI arguments
        // Usage: node dist/index.js auth --scopes=<scope1,scope2,...>
        // Example: node dist/index.js auth --scopes=gmail.readonly
        // Example: node dist/index.js auth --scopes=gmail.readonly,gmail.settings.basic
        const scopesArg = process.argv.find(arg => arg.startsWith('--scopes='));
        let scopes = DEFAULT_SCOPES;

        if (scopesArg) {
            const scopesValue = scopesArg.slice('--scopes='.length);
            scopes = parseScopes(scopesValue);
            const validation = validateScopes(scopes);

            if (!validation.valid) {
                console.error('Error: Invalid scope(s):', validation.invalid.join(', '));
                console.error('Available scopes:', getAvailableScopeNames().join(', '));
                process.exit(1);
            }
        } else {
            console.log('No --scopes flag specified, using defaults:', DEFAULT_SCOPES.join(', '));
            console.log('Tip: Use --scopes=gmail.readonly for read-only access');
            console.log('Available scopes:', getAvailableScopeNames().join(', '));
        }

        await authenticate(scopes);
        console.log('Authentication completed successfully');
        process.exit(0);
    }

    // stdio mode (default): a single Gmail client bound to the locally
    // authenticated account, surfaced as a one-account principal.
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
    const stdioSession: PrincipalSession = {
        principalId: 'local',
        accounts: [{ sub: 'local', email: 'me', primary: true, scopeNames: authorizedScopes }],
        getClient: () => ({ gmail, authorizedScopes }),
    };
    const server = createMcpServer(() => stdioSession);
    const transport = new StdioServerTransport();
    await server.connect(transport);
}

/**
 * Builds the MCP Server and registers tool handlers. Each request resolves a
 * per-call session via resolveSession(extra) — for stdio that is the single
 * local account; for http (multi-tenant) it is the caller's own Gmail client,
 * derived from the validated bearer token.
 */
function createMcpServer(resolveSession: ResolveSession): Server {
    // Server implementation
    const server = new Server(
        {
            name: "gmail",
            version: "1.0.0",
        },
        {
            capabilities: {
                tools: {},
            },
        },
    );

    // Tool handlers
    // Filter available tools based on the requesting session's authorized scopes
    server.setRequestHandler(ListToolsRequestSchema, async (_request, extra) => {
        const session = await resolveSession(extra);
        const scopes = unionScopes(session.accounts);
        const availableTools = toolDefinitions.filter(tool =>
            hasScope(scopes, tool.scopes)
        );
        // Advertise the `account` selector on every Gmail tool, then append the
        // account-management meta tools.
        const gmailTools = toMcpTools(availableTools).map((t: any) => ({
            ...t,
            inputSchema: {
                ...t.inputSchema,
                properties: { ...(t.inputSchema?.properties || {}), ...ACCOUNT_PARAM },
            },
        }));
        return { tools: [...gmailTools, ...metaToolDefs(session)] };
    });

    // Runs a single tool against ONE resolved Gmail client. The CallTool handler
    // below orchestrates account selection and fan-out, then calls this per account.
    async function executeTool(
        name: string,
        args: any,
        gmail: ReturnType<typeof google.gmail>,
        authorizedScopes: string[],
        sendCtx: SendContext,
    ): Promise<any> {
        // Gate a send against the per-account policy. If recipients are blocked,
        // ask the user (elicitation) to allow once, always (save), or cancel.
        // Returns { allow } when the send may proceed, or { deny } with the result
        // to return instead.
        async function gateSend(recipients: Array<string | undefined>): Promise<{ allow: true } | { allow: false; deny: any }> {
            const blocked = disallowedRecipients(recipients, sendCtx.ownEmail, sendCtx.policy);
            if (blocked.length === 0) return { allow: true };

            // Distinct domains among the blocked recipients — surfaced as "allow the
            // whole domain" options when a pattern emerges. Public providers
            // (gmail.com, etc.) are excluded: allowing the whole domain there would
            // mean "send to anyone", so only specific addresses can be allowed.
            const domains = [...new Set(
                blocked.map((r) => emailAddressOf(r).split('@')[1]).filter(Boolean),
            )].filter((d) => !isPublicEmailDomain(d));

            const options: Array<{ value: string; label: string }> = [
                { value: 'once', label: 'Send this time only' },
                {
                    value: 'always',
                    label: blocked.length === 1
                        ? `Always allow ${blocked[0]}`
                        : `Always allow these ${blocked.length} recipients`,
                },
            ];
            if (domains.length === 1) {
                options.push({ value: 'domain', label: `Always allow anyone @${domains[0]}` });
            } else if (domains.length > 1) {
                options.push({ value: 'domains', label: `Always allow all ${domains.length} domains (${domains.join(', ')})` });
            }
            options.push({ value: 'cancel', label: "Don't send" });

            const hint = domains.length === 1
                ? ` (they're all @${domains[0]} — you can allow the whole domain)`
                : '';
            const outcome = await elicitChoice(
                server,
                `${sendCtx.ownEmail} isn't allowed to send to: ${blocked.join(', ')}.${hint} How should I proceed?`,
                options,
            );
            if (!outcome.supported) return { allow: false, deny: sendBlockedError(blocked) };
            switch (outcome.choice) {
                case 'once':
                    return { allow: true };
                case 'always':
                    if (sendCtx.persistAllow) await sendCtx.persistAllow(blocked);
                    return { allow: true };
                case 'domain':
                    if (sendCtx.persistAllow) await sendCtx.persistAllow([domains[0]]);
                    return { allow: true };
                case 'domains':
                    if (sendCtx.persistAllow) await sendCtx.persistAllow(domains);
                    return { allow: true };
                default:
                    return { allow: false, deny: errText(`Send cancelled — not sent to: ${blocked.join(', ')}.`) };
            }
        }

        // Confirm a permanent (irreversible) delete via elicitation. Falls back to
        // a hard block (no delete) if the client can't confirm — the safe default.
        async function confirmPermanentDelete(count: number): Promise<{ allow: true } | { allow: false; deny: any }> {
            const msg = count === 1
                ? 'Permanently delete this message? This CANNOT be undone — it bypasses Trash. (trash_email moves it to Trash instead, recoverable for 30 days.)'
                : `Permanently delete ${count} message(s)? This CANNOT be undone — it bypasses Trash. (batch_trash_emails moves them to Trash instead, recoverable for 30 days.)`;
            const c = await elicitConfirm(server, msg);
            if (!c.supported) {
                return { allow: false, deny: errText('Permanent delete was not confirmed (this client cannot show a confirmation prompt). Use trash_email / batch_trash_emails instead — those are recoverable.') };
            }
            if (c.choice !== 'yes') return { allow: false, deny: errText('Permanent delete cancelled.') };
            return { allow: true };
        }

        async function handleEmailAction(action: "send" | "draft", validatedArgs: any) {
            // Enforce the per-account send policy before actually sending.
            if (action === "send") {
                const gate = await gateSend([
                    ...(validatedArgs.to || []),
                    ...(validatedArgs.cc || []),
                    ...(validatedArgs.bcc || []),
                ]);
                if (!gate.allow) return gate.deny;
            }
            let message: string;

            try {
                // Auto-resolve threading headers when threadId is provided but inReplyTo is missing
                if (validatedArgs.threadId && !validatedArgs.inReplyTo) {
                    try {
                        const threadResponse = await gmail.users.threads.get({
                            userId: 'me',
                            id: validatedArgs.threadId,
                            format: 'metadata',
                            metadataHeaders: ['Message-ID'],
                        });

                        const threadMessages = threadResponse.data.messages || [];
                        if (threadMessages.length > 0) {
                            // Collect all Message-ID values for the References chain
                            const allMessageIds: string[] = [];
                            for (const msg of threadMessages) {
                                const msgHeaders = msg.payload?.headers || [];
                                const messageIdHeader = msgHeaders.find(
                                    (h) => h.name?.toLowerCase() === 'message-id'
                                );
                                if (messageIdHeader?.value) {
                                    allMessageIds.push(messageIdHeader.value);
                                }
                            }

                            // Last message's Message-ID becomes In-Reply-To
                            const lastMessage = threadMessages[threadMessages.length - 1];
                            const lastHeaders = lastMessage.payload?.headers || [];
                            const lastMessageId = lastHeaders.find(
                                (h) => h.name?.toLowerCase() === 'message-id'
                            )?.value;

                            if (lastMessageId) {
                                validatedArgs.inReplyTo = lastMessageId;
                            }
                            if (allMessageIds.length > 0) {
                                validatedArgs.references = allMessageIds.join(' ');
                            }
                        }
                    } catch (threadError: any) {
                        console.warn(`Warning: Could not fetch thread ${validatedArgs.threadId} for header resolution: ${threadError.message}`);
                        // Continue without threading headers - degraded but not broken
                    }
                }

                // Check if we have attachments
                if (validatedArgs.attachments && validatedArgs.attachments.length > 0) {
                    // Use Nodemailer to create properly formatted RFC822 message
                    message = await createEmailWithNodemailer(validatedArgs);
                    
                    if (action === "send") {
                        const encodedMessage = Buffer.from(message).toString('base64')
                            .replace(/\+/g, '-')
                            .replace(/\//g, '_')
                            .replace(/=+$/, '');

                        const result = await gmail.users.messages.send({
                            userId: 'me',
                            requestBody: {
                                raw: encodedMessage,
                                ...(validatedArgs.threadId && { threadId: validatedArgs.threadId })
                            }
                        });
                        
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Email sent successfully with ID: ${result.data.id}`,
                                },
                            ],
                        };
                    } else {
                        // For drafts with attachments, use the raw message
                        const encodedMessage = Buffer.from(message).toString('base64')
                            .replace(/\+/g, '-')
                            .replace(/\//g, '_')
                            .replace(/=+$/, '');
                        
                        const messageRequest = {
                            raw: encodedMessage,
                            ...(validatedArgs.threadId && { threadId: validatedArgs.threadId })
                        };
                        
                        const response = await gmail.users.drafts.create({
                            userId: 'me',
                            requestBody: {
                                message: messageRequest,
                            },
                        });
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Email draft created successfully with ID: ${response.data.id}`,
                                },
                            ],
                        };
                    }
                } else {
                    // For emails without attachments, use the existing simple method
                    message = createEmailMessage(validatedArgs);
                    
                    const encodedMessage = Buffer.from(message).toString('base64')
                        .replace(/\+/g, '-')
                        .replace(/\//g, '_')
                        .replace(/=+$/, '');

                    // Define the type for messageRequest
                    interface GmailMessageRequest {
                        raw: string;
                        threadId?: string;
                    }

                    const messageRequest: GmailMessageRequest = {
                        raw: encodedMessage,
                    };

                    // Add threadId if specified
                    if (validatedArgs.threadId) {
                        messageRequest.threadId = validatedArgs.threadId;
                    }

                    if (action === "send") {
                        const response = await gmail.users.messages.send({
                            userId: 'me',
                            requestBody: messageRequest,
                        });
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Email sent successfully with ID: ${response.data.id}`,
                                },
                            ],
                        };
                    } else {
                        const response = await gmail.users.drafts.create({
                            userId: 'me',
                            requestBody: {
                                message: messageRequest,
                        },
                        });
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Email draft created successfully with ID: ${response.data.id}`,
                                },
                            ],
                        };
                    }
                }
            } catch (error: any) {
                // Log attachment-related errors for debugging
                if (validatedArgs.attachments && validatedArgs.attachments.length > 0) {
                    console.error(`Failed to send email with ${validatedArgs.attachments.length} attachments:`, error.message);
                }
                throw error;
            }
        }

        // Helper function to process operations in batches
        async function processBatches<T, U>(
            items: T[],
            batchSize: number,
            processFn: (batch: T[]) => Promise<U[]>
        ): Promise<{ successes: U[], failures: { item: T, error: Error }[] }> {
            const successes: U[] = [];
            const failures: { item: T, error: Error }[] = [];
            
            // Process in batches
            for (let i = 0; i < items.length; i += batchSize) {
                const batch = items.slice(i, i + batchSize);
                try {
                    const results = await processFn(batch);
                    successes.push(...results);
                } catch (error) {
                    // If batch fails, try individual items
                    for (const item of batch) {
                        try {
                            const result = await processFn([item]);
                            successes.push(...result);
                        } catch (itemError) {
                            failures.push({ item, error: itemError as Error });
                        }
                    }
                }
            }
            
            return { successes, failures };
        }

        try {
            switch (name) {
                case "send_email":
                case "draft_email": {
                    const validatedArgs = SendEmailSchema.parse(args);
                    const action = name === "send_email" ? "send" : "draft";
                    return await handleEmailAction(action, validatedArgs);
                }

                case "read_email": {
                    const validatedArgs = ReadEmailSchema.parse(args);
                    const response = await gmail.users.messages.get({
                        userId: 'me',
                        id: validatedArgs.messageId,
                        format: 'full',
                    });

                    const { subject, from, to, cc, bcc, date, rfcMessageId } = extractHeaders(response.data.payload);
                    const threadId = response.data.threadId || '';
                    const { text, html } = extractEmailContent(response.data.payload as GmailMessagePart || {});
                    const attachments = extractAttachments(response.data.payload as GmailMessagePart);

                    // Use plain text content if available, otherwise use HTML content
                    const body = text || html || '';
                    const contentTypeNote = !text && html ?
                        '[Note: This email is HTML-formatted. Plain text version not available.]\n\n' : '';

                    // Add attachment info to output if any are present
                    const attachmentInfo = attachments.length > 0 ?
                        `\n\nAttachments (${attachments.length}):\n` +
                        attachments.map(a => `- ${a.filename} (${a.mimeType}, ${Math.round(a.size/1024)} KB, ID: ${a.id})`).join('\n') : '';

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Thread ID: ${threadId}\nMessage-ID: ${rfcMessageId}\nSubject: ${subject}\nFrom: ${from}\nTo: ${to}${cc ? `\nCC: ${cc}` : ''}${bcc ? `\nBCC: ${bcc}` : ''}\nDate: ${date}\n\n${contentTypeNote}${body}${attachmentInfo}`,
                            },
                        ],
                    };
                }

                case "search_emails": {
                    const validatedArgs = SearchEmailsSchema.parse(args);
                    const response = await gmail.users.messages.list({
                        userId: 'me',
                        q: validatedArgs.query,
                        maxResults: validatedArgs.maxResults || 10,
                    });

                    const messages = response.data.messages || [];
                    const results = await Promise.all(
                        messages.map(async (msg) => {
                            const detail = await gmail.users.messages.get({
                                userId: 'me',
                                id: msg.id!,
                                format: 'metadata',
                                metadataHeaders: ['Subject', 'From', 'Date'],
                            });
                            const headers = detail.data.payload?.headers || [];
                            return {
                                id: msg.id,
                                subject: headers.find(h => h.name === 'Subject')?.value || '',
                                from: headers.find(h => h.name === 'From')?.value || '',
                                date: headers.find(h => h.name === 'Date')?.value || '',
                            };
                        })
                    );

                    return {
                        content: [
                            {
                                type: "text",
                                text: results.map(r =>
                                    `ID: ${r.id}\nSubject: ${r.subject}\nFrom: ${r.from}\nDate: ${r.date}\n`
                                ).join('\n'),
                            },
                        ],
                    };
                }

                case "download_email": {
                    const validatedArgs = DownloadEmailSchema.parse(args);
                    const { messageId, savePath, format } = validatedArgs;

                    try {
                        // Ensure save directory exists
                        if (!fs.existsSync(savePath)) {
                            fs.mkdirSync(savePath, { recursive: true });
                        }

                        // Always fetch full message for metadata (needed for attachments list)
                        const fullResponse = await gmail.users.messages.get({
                            userId: "me",
                            id: messageId,
                            format: "full",
                        });

                        const { subject, from, date } = extractHeaders(fullResponse.data.payload);
                        const attachments = extractAttachments(fullResponse.data.payload as GmailMessagePart);

                        let content: string;

                        if (format === "eml") {
                            // For EML format, fetch raw RFC822 message
                            const rawResponse = await gmail.users.messages.get({
                                userId: "me",
                                id: messageId,
                                format: "raw",
                            });
                            content = Buffer.from(rawResponse.data.raw || "", "base64url").toString("utf-8");
                        } else {
                            // Extract email content for json/txt/html
                            const emailContent = extractEmailContent(fullResponse.data.payload as GmailMessagePart || {});

                            if (format === "json") {
                                const jsonData = gmailMessageToJson(fullResponse.data, emailContent, attachments);
                                content = JSON.stringify(jsonData, null, 2);
                            } else if (format === "txt") {
                                content = emailToTxt(fullResponse.data, emailContent, attachments);
                            } else {
                                // html - just return the raw HTML content
                                content = emailToHtml(emailContent);
                            }
                        }

                        // Write file
                        const filename = `${messageId}.${format}`;
                        const fullPath = path.join(savePath, filename);
                        fs.writeFileSync(fullPath, content, "utf-8");
                        const stats = fs.statSync(fullPath);

                        // Return metadata with attachments
                        const result = {
                            status: "saved",
                            path: fullPath,
                            size: stats.size,
                            messageId,
                            subject,
                            from,
                            date,
                            attachments,
                        };

                        return {
                            content: [
                                {
                                    type: "text",
                                    text: JSON.stringify(result, null, 2),
                                },
                            ],
                        };
                    } catch (error: any) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Failed to download email: ${error.message}`,
                                },
                            ],
                        };
                    }
                }

                // Updated implementation for the modify_email handler
                case "modify_email": {
                    const validatedArgs = ModifyEmailSchema.parse(args);
                    
                    // Prepare request body
                    const requestBody: any = {};
                    
                    if (validatedArgs.labelIds) {
                        requestBody.addLabelIds = validatedArgs.labelIds;
                    }
                    
                    if (validatedArgs.addLabelIds) {
                        requestBody.addLabelIds = validatedArgs.addLabelIds;
                    }
                    
                    if (validatedArgs.removeLabelIds) {
                        requestBody.removeLabelIds = validatedArgs.removeLabelIds;
                    }
                    
                    await gmail.users.messages.modify({
                        userId: 'me',
                        id: validatedArgs.messageId,
                        requestBody: requestBody,
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Email ${validatedArgs.messageId} labels updated successfully`,
                            },
                        ],
                    };
                }

                case "trash_email": {
                    const validatedArgs = TrashEmailSchema.parse(args);
                    await gmail.users.messages.trash({
                        userId: 'me',
                        id: validatedArgs.messageId,
                    });
                    return {
                        content: [
                            {
                                type: "text",
                                text: `Email ${validatedArgs.messageId} moved to Trash (recoverable for 30 days).`,
                            },
                        ],
                    };
                }

                case "batch_trash_emails": {
                    const validatedArgs = BatchTrashEmailsSchema.parse(args);
                    const messageIds = validatedArgs.messageIds;
                    const batchSize = validatedArgs.batchSize || 50;
                    const { successes, failures } = await processBatches(
                        messageIds,
                        batchSize,
                        async (batch) => Promise.all(
                            batch.map(async (messageId) => {
                                await gmail.users.messages.trash({ userId: 'me', id: messageId });
                                return { messageId, success: true };
                            })
                        )
                    );
                    let summary = `Batch trash complete.\nMoved to Trash (recoverable): ${successes.length}/${messageIds.length}`;
                    if (failures.length > 0) {
                        summary += `\nFailed: ${failures.length}\n` +
                            failures.map(f => `- ${(f.item as string).substring(0, 16)}... (${f.error.message})`).join('\n');
                    }
                    return { content: [{ type: "text", text: summary }] };
                }

                case "delete_email": {
                    const validatedArgs = DeleteEmailSchema.parse(args);
                    const gate = await confirmPermanentDelete(1);
                    if (!gate.allow) return gate.deny;
                    await gmail.users.messages.delete({
                        userId: 'me',
                        id: validatedArgs.messageId,
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Email ${validatedArgs.messageId} permanently deleted`,
                            },
                        ],
                    };
                }

                case "send_draft": {
                    const validatedArgs = SendDraftSchema.parse(args);
                    // Enforce the send policy against the draft's actual recipients.
                    const draft = await gmail.users.drafts.get({
                        userId: 'me',
                        id: validatedArgs.draftId,
                        format: 'metadata',
                    });
                    const draftHeaders = draft.data.message?.payload?.headers || [];
                    const draftRecipients = draftHeaders
                        .filter((h) => ['to', 'cc', 'bcc'].includes((h.name || '').toLowerCase()))
                        .flatMap((h) => (h.value || '').split(',').map((s: string) => s.trim()))
                        .filter((s: string) => s.length > 0);
                    const gate = await gateSend(draftRecipients);
                    if (!gate.allow) return gate.deny;

                    const response = await gmail.users.drafts.send({
                        userId: 'me',
                        requestBody: { id: validatedArgs.draftId },
                    });
                    return {
                        content: [
                            {
                                type: "text",
                                text: `Draft ${validatedArgs.draftId} sent successfully as message ID: ${response.data.id}. The draft has been removed from Drafts.`,
                            },
                        ],
                    };
                }

                case "delete_draft": {
                    const validatedArgs = DeleteDraftSchema.parse(args);
                    await gmail.users.drafts.delete({
                        userId: 'me',
                        id: validatedArgs.draftId,
                    });
                    return {
                        content: [
                            {
                                type: "text",
                                text: `Draft ${validatedArgs.draftId} deleted successfully.`,
                            },
                        ],
                    };
                }

                case "update_draft": {
                    const validatedArgs = UpdateDraftSchema.parse(args);
                    const { draftId, ...messageArgs } = validatedArgs;

                    // Build the new MIME message using the same helpers as draft_email/send_email
                    let message: string;
                    if (messageArgs.attachments && messageArgs.attachments.length > 0) {
                        message = await createEmailWithNodemailer(messageArgs);
                    } else {
                        message = createEmailMessage(messageArgs);
                    }

                    const encodedMessage = Buffer.from(message).toString('base64')
                        .replace(/\+/g, '-')
                        .replace(/\//g, '_')
                        .replace(/=+$/, '');

                    const messageRequest: any = { raw: encodedMessage };
                    if (messageArgs.threadId) messageRequest.threadId = messageArgs.threadId;

                    const response = await gmail.users.drafts.update({
                        userId: 'me',
                        id: draftId,
                        requestBody: { message: messageRequest },
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Draft ${draftId} updated successfully (draft ID unchanged, content replaced).`,
                            },
                        ],
                    };
                }

                case "list_email_labels": {
                    const labelResults = await listLabels(gmail);
                    const systemLabels = labelResults.system;
                    const userLabels = labelResults.user;

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Found ${labelResults.count.total} labels (${labelResults.count.system} system, ${labelResults.count.user} user):\n\n` +
                                    "System Labels:\n" +
                                    systemLabels.map((l: GmailLabel) => `ID: ${l.id}\nName: ${l.name}\n`).join('\n') +
                                    "\nUser Labels:\n" +
                                    userLabels.map((l: GmailLabel) => `ID: ${l.id}\nName: ${l.name}\n`).join('\n')
                            },
                        ],
                    };
                }

                case "batch_modify_emails": {
                    const validatedArgs = BatchModifyEmailsSchema.parse(args);
                    const messageIds = validatedArgs.messageIds;
                    const batchSize = validatedArgs.batchSize || 50;
                    
                    // Prepare request body
                    const requestBody: any = {};
                    
                    if (validatedArgs.addLabelIds) {
                        requestBody.addLabelIds = validatedArgs.addLabelIds;
                    }
                    
                    if (validatedArgs.removeLabelIds) {
                        requestBody.removeLabelIds = validatedArgs.removeLabelIds;
                    }

                    // Process messages in batches
                    const { successes, failures } = await processBatches(
                        messageIds,
                        batchSize,
                        async (batch) => {
                            const results = await Promise.all(
                                batch.map(async (messageId) => {
                                    const result = await gmail.users.messages.modify({
                                        userId: 'me',
                                        id: messageId,
                                        requestBody: requestBody,
                                    });
                                    return { messageId, success: true };
                                })
                            );
                            return results;
                        }
                    );

                    // Generate summary of the operation
                    const successCount = successes.length;
                    const failureCount = failures.length;
                    
                    let resultText = `Batch label modification complete.\n`;
                    resultText += `Successfully processed: ${successCount} messages\n`;
                    
                    if (failureCount > 0) {
                        resultText += `Failed to process: ${failureCount} messages\n\n`;
                        resultText += `Failed message IDs:\n`;
                        resultText += failures.map(f => `- ${(f.item as string).substring(0, 16)}... (${f.error.message})`).join('\n');
                    }

                    return {
                        content: [
                            {
                                type: "text",
                                text: resultText,
                            },
                        ],
                    };
                }

                case "report_phishing": {
                    const validatedArgs = ReportPhishingSchema.parse(args);

                    await gmail.users.messages.modify({
                        userId: 'me',
                        id: validatedArgs.messageId,
                        requestBody: {
                            addLabelIds: ['SPAM'],
                        },
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Email ${validatedArgs.messageId} was updated with the SPAM label as the closest public Gmail API approximation of reporting phishing. Note: the Gmail API does not expose the full native Report phishing workflow.`,
                            },
                        ],
                    };
                }

                case "batch_report_phishing": {
                    const validatedArgs = BatchReportPhishingSchema.parse(args);
                    const messageIds = validatedArgs.messageIds;
                    const batchSize = validatedArgs.batchSize || 50;

                    const { successes, failures } = await processBatches(
                        messageIds,
                        batchSize,
                        async (batch) => {
                            await gmail.users.messages.batchModify({
                                userId: 'me',
                                requestBody: {
                                    ids: batch,
                                    addLabelIds: ['SPAM'],
                                },
                            });

                            return batch.map((messageId) => ({ messageId, success: true }));
                        }
                    );

                    const successCount = successes.length;
                    const failureCount = failures.length;

                    let resultText = `Batch phishing report complete.\n`;
                    resultText += `Successfully processed: ${successCount} messages\n`;
                    resultText += `Behavior: each message was updated with the SPAM label as the closest public Gmail API approximation of reporting phishing.\n`;
                    resultText += `Limitation: the Gmail API does not expose the full native Report phishing workflow.\n`;

                    if (failureCount > 0) {
                        resultText += `Failed to process: ${failureCount} messages\n\n`;
                        resultText += `Failed message IDs:\n`;
                        resultText += failures.map(f => `- ${(f.item as string).substring(0, 16)}... (${f.error.message})`).join('\n');
                    }

                    return {
                        content: [
                            {
                                type: "text",
                                text: resultText,
                            },
                        ],
                    };
                }

                case "batch_delete_emails": {
                    const validatedArgs = BatchDeleteEmailsSchema.parse(args);
                    const messageIds = validatedArgs.messageIds;
                    const batchSize = validatedArgs.batchSize || 50;

                    const gate = await confirmPermanentDelete(messageIds.length);
                    if (!gate.allow) return gate.deny;

                    // Process messages in batches
                    const { successes, failures } = await processBatches(
                        messageIds,
                        batchSize,
                        async (batch) => {
                            const results = await Promise.all(
                                batch.map(async (messageId) => {
                                    await gmail.users.messages.delete({
                                        userId: 'me',
                                        id: messageId,
                                    });
                                    return { messageId, success: true };
                                })
                            );
                            return results;
                        }
                    );

                    // Generate summary of the operation
                    const successCount = successes.length;
                    const failureCount = failures.length;
                    
                    let resultText = `Batch delete operation complete.\n`;
                    resultText += `Successfully deleted: ${successCount} messages\n`;
                    
                    if (failureCount > 0) {
                        resultText += `Failed to delete: ${failureCount} messages\n\n`;
                        resultText += `Failed message IDs:\n`;
                        resultText += failures.map(f => `- ${(f.item as string).substring(0, 16)}... (${f.error.message})`).join('\n');
                    }

                    return {
                        content: [
                            {
                                type: "text",
                                text: resultText,
                            },
                        ],
                    };
                }

                // New label management handlers
                case "create_label": {
                    const validatedArgs = CreateLabelSchema.parse(args);
                    const result = await createLabel(gmail, validatedArgs.name, {
                        messageListVisibility: validatedArgs.messageListVisibility,
                        labelListVisibility: validatedArgs.labelListVisibility,
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Label created successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`,
                            },
                        ],
                    };
                }

                case "update_label": {
                    const validatedArgs = UpdateLabelSchema.parse(args);
                    
                    // Prepare request body with only the fields that were provided
                    const updates: any = {};
                    if (validatedArgs.name) updates.name = validatedArgs.name;
                    if (validatedArgs.messageListVisibility) updates.messageListVisibility = validatedArgs.messageListVisibility;
                    if (validatedArgs.labelListVisibility) updates.labelListVisibility = validatedArgs.labelListVisibility;
                    
                    const result = await updateLabel(gmail, validatedArgs.id, updates);

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Label updated successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`,
                            },
                        ],
                    };
                }

                case "delete_label": {
                    const validatedArgs = DeleteLabelSchema.parse(args);
                    const result = await deleteLabel(gmail, validatedArgs.id);

                    return {
                        content: [
                            {
                                type: "text",
                                text: result.message,
                            },
                        ],
                    };
                }

                case "get_or_create_label": {
                    const validatedArgs = GetOrCreateLabelSchema.parse(args);
                    const result = await getOrCreateLabel(gmail, validatedArgs.name, {
                        messageListVisibility: validatedArgs.messageListVisibility,
                        labelListVisibility: validatedArgs.labelListVisibility,
                    });

                    const action = result.type === 'user' && result.name === validatedArgs.name ? 'found existing' : 'created new';
                    
                    return {
                        content: [
                            {
                                type: "text",
                                text: `Successfully ${action} label:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`,
                            },
                        ],
                    };
                }


                // Filter management handlers
                case "create_filter": {
                    const validatedArgs = CreateFilterSchema.parse(args);
                    const result = await createFilter(gmail, validatedArgs.criteria, validatedArgs.action);

                    // Format criteria for display
                    const criteriaText = Object.entries(validatedArgs.criteria)
                        .filter(([_, value]) => value !== undefined)
                        .map(([key, value]) => `${key}: ${value}`)
                        .join(', ');

                    // Format actions for display
                    const actionText = Object.entries(validatedArgs.action)
                        .filter(([_, value]) => value !== undefined && (Array.isArray(value) ? value.length > 0 : true))
                        .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : value}`)
                        .join(', ');

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Filter created successfully:\nID: ${result.id}\nCriteria: ${criteriaText}\nActions: ${actionText}`,
                            },
                        ],
                    };
                }

                case "list_filters": {
                    const result = await listFilters(gmail);
                    const filters = result.filters;

                    if (filters.length === 0) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: "No filters found.",
                                },
                            ],
                        };
                    }

                    const filtersText = filters.map((filter: any) => {
                        const criteriaEntries = Object.entries(filter.criteria || {})
                            .filter(([_, value]) => value !== undefined)
                            .map(([key, value]) => `${key}: ${value}`)
                            .join(', ');
                        
                        const actionEntries = Object.entries(filter.action || {})
                            .filter(([_, value]) => value !== undefined && (Array.isArray(value) ? value.length > 0 : true))
                            .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : value}`)
                            .join(', ');

                        return `ID: ${filter.id}\nCriteria: ${criteriaEntries}\nActions: ${actionEntries}\n`;
                    }).join('\n');

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Found ${result.count} filters:\n\n${filtersText}`,
                            },
                        ],
                    };
                }

                case "get_filter": {
                    const validatedArgs = GetFilterSchema.parse(args);
                    const result = await getFilter(gmail, validatedArgs.filterId);

                    const criteriaText = Object.entries(result.criteria || {})
                        .filter(([_, value]) => value !== undefined)
                        .map(([key, value]) => `${key}: ${value}`)
                        .join(', ');
                    
                    const actionText = Object.entries(result.action || {})
                        .filter(([_, value]) => value !== undefined && (Array.isArray(value) ? value.length > 0 : true))
                        .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : value}`)
                        .join(', ');

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Filter details:\nID: ${result.id}\nCriteria: ${criteriaText}\nActions: ${actionText}`,
                            },
                        ],
                    };
                }

                case "list_send_as": {
                    ListSendAsSchema.parse(args);
                    const sendAsResponse = await gmail.users.settings.sendAs.list({ userId: 'me' });
                    const aliases = sendAsResponse.data.sendAs || [];
                    if (aliases.length === 0) {
                        return { content: [{ type: "text", text: "No send-as addresses configured." }] };
                    }
                    const lines = aliases.map((a) => {
                        const tags = [
                            a.isPrimary ? 'primary' : null,
                            a.isDefault ? 'default' : null,
                            a.verificationStatus && a.verificationStatus !== 'accepted'
                                ? `verification: ${a.verificationStatus}`
                                : 'verified',
                        ].filter(Boolean).join(', ');
                        const name = a.displayName ? ` "${a.displayName}"` : '';
                        return `- ${a.sendAsEmail}${name} (${tags})`;
                    });
                    return {
                        content: [{
                            type: "text",
                            text: `Send-as addresses (use as the "from" parameter):\n${lines.join('\n')}`,
                        }],
                    };
                }

                case "delete_filter": {
                    const validatedArgs = DeleteFilterSchema.parse(args);
                    const result = await deleteFilter(gmail, validatedArgs.filterId);

                    return {
                        content: [
                            {
                                type: "text",
                                text: result.message,
                            },
                        ],
                    };
                }

                case "create_filter_from_template": {
                    const validatedArgs = CreateFilterFromTemplateSchema.parse(args);
                    const template = validatedArgs.template;
                    const params = validatedArgs.parameters;

                    let filterConfig;
                    
                    switch (template) {
                        case 'fromSender':
                            if (!params.senderEmail) throw new Error("senderEmail is required for fromSender template");
                            filterConfig = filterTemplates.fromSender(params.senderEmail, params.labelIds, params.archive);
                            break;
                        case 'withSubject':
                            if (!params.subjectText) throw new Error("subjectText is required for withSubject template");
                            filterConfig = filterTemplates.withSubject(params.subjectText, params.labelIds, params.markAsRead);
                            break;
                        case 'withAttachments':
                            filterConfig = filterTemplates.withAttachments(params.labelIds);
                            break;
                        case 'largeEmails':
                            if (!params.sizeInBytes) throw new Error("sizeInBytes is required for largeEmails template");
                            filterConfig = filterTemplates.largeEmails(params.sizeInBytes, params.labelIds);
                            break;
                        case 'containingText':
                            if (!params.searchText) throw new Error("searchText is required for containingText template");
                            filterConfig = filterTemplates.containingText(params.searchText, params.labelIds, params.markImportant);
                            break;
                        case 'mailingList':
                            if (!params.listIdentifier) throw new Error("listIdentifier is required for mailingList template");
                            filterConfig = filterTemplates.mailingList(params.listIdentifier, params.labelIds, params.archive);
                            break;
                        default:
                            throw new Error(`Unknown template: ${template}`);
                    }

                    const result = await createFilter(gmail, filterConfig.criteria, filterConfig.action);

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Filter created from template '${template}':\nID: ${result.id}\nTemplate used: ${template}`,
                            },
                        ],
                    };
                }
                case "download_attachment": {
                    const validatedArgs = DownloadAttachmentSchema.parse(args);

                    try {
                        // Get the attachment data from Gmail API
                        const attachmentResponse = await gmail.users.messages.attachments.get({
                            userId: 'me',
                            messageId: validatedArgs.messageId,
                            id: validatedArgs.attachmentId,
                        });

                        if (!attachmentResponse.data.data) {
                            throw new Error('No attachment data received');
                        }

                        // Decode the base64 data
                        const data = attachmentResponse.data.data;
                        const buffer = Buffer.from(data, 'base64url');

                        // Determine save path and filename
                        const savePath = validatedArgs.savePath || process.cwd();
                        let filename = validatedArgs.filename;

                        if (!filename) {
                            // Get original filename from message if not provided
                            const messageResponse = await gmail.users.messages.get({
                                userId: 'me',
                                id: validatedArgs.messageId,
                                format: 'full',
                            });

                            // Find the attachment part to get original filename
                            const findAttachment = (part: any): string | null => {
                                if (part.body && part.body.attachmentId === validatedArgs.attachmentId) {
                                    return part.filename || `attachment-${validatedArgs.attachmentId}`;
                                }
                                if (part.parts) {
                                    for (const subpart of part.parts) {
                                        const found = findAttachment(subpart);
                                        if (found) return found;
                                    }
                                }
                                return null;
                            };

                            filename = findAttachment(messageResponse.data.payload) || `attachment-${validatedArgs.attachmentId}`;
                        }

                        // Sanitize filename to prevent path traversal
                        filename = path.basename(filename);

                        // Ensure save directory exists
                        if (!fs.existsSync(savePath)) {
                            fs.mkdirSync(savePath, { recursive: true });
                        }

                        // Resolve and validate final path stays within savePath
                        const resolvedSavePath = path.resolve(savePath);
                        const fullPath = path.resolve(resolvedSavePath, filename);
                        if (!fullPath.startsWith(resolvedSavePath + path.sep) && fullPath !== resolvedSavePath) {
                            throw new Error('Invalid filename: path traversal detected');
                        }
                        fs.writeFileSync(fullPath, buffer);

                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Attachment downloaded successfully:\nFile: ${filename}\nSize: ${buffer.length} bytes\nSaved to: ${fullPath}`,
                                },
                            ],
                        };
                    } catch (error: any) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Failed to download attachment: ${error.message}`,
                                },
                            ],
                        };
                    }
                }

                case "get_thread": {
                    const validatedArgs = GetThreadSchema.parse(args);
                    const threadResponse = await gmail.users.threads.get({
                        userId: 'me',
                        id: validatedArgs.threadId,
                        format: validatedArgs.format || 'full',
                    });

                    const threadMessages = threadResponse.data.messages || [];

                    // Process each message in the thread (already chronological from API)
                    const messagesOutput = threadMessages.map((msg) => {
                        const headers = msg.payload?.headers || [];
                        const subject = headers.find(h => h.name?.toLowerCase() === 'subject')?.value || '';
                        const from = headers.find(h => h.name?.toLowerCase() === 'from')?.value || '';
                        const to = headers.find(h => h.name?.toLowerCase() === 'to')?.value || '';
                        const cc = headers.find(h => h.name?.toLowerCase() === 'cc')?.value || '';
                        const bcc = headers.find(h => h.name?.toLowerCase() === 'bcc')?.value || '';
                        const date = headers.find(h => h.name?.toLowerCase() === 'date')?.value || '';

                        // Extract body content
                        let body = '';
                        if (validatedArgs.format !== 'minimal') {
                            const { text, html } = extractEmailContent(msg.payload as GmailMessagePart || {});
                            body = text || html || '';
                        }

                        // Extract attachment metadata
                        const attachments: EmailAttachment[] = [];
                        const processAttachmentParts = (part: GmailMessagePart) => {
                            if (part.body && part.body.attachmentId) {
                                const filename = part.filename || `attachment-${part.body.attachmentId}`;
                                attachments.push({
                                    id: part.body.attachmentId,
                                    filename: filename,
                                    mimeType: part.mimeType || 'application/octet-stream',
                                    size: part.body.size || 0,
                                });
                            }
                            if (part.parts) {
                                part.parts.forEach((subpart: GmailMessagePart) => processAttachmentParts(subpart));
                            }
                        };
                        if (msg.payload) {
                            processAttachmentParts(msg.payload as GmailMessagePart);
                        }

                        return {
                            messageId: msg.id || '',
                            threadId: msg.threadId || '',
                            from,
                            to,
                            cc,
                            bcc,
                            subject,
                            date,
                            body,
                            labelIds: msg.labelIds || [],
                            attachments: attachments.map(a => ({
                                filename: a.filename,
                                mimeType: a.mimeType,
                                size: a.size,
                            })),
                        };
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: JSON.stringify({
                                    threadId: validatedArgs.threadId,
                                    messageCount: messagesOutput.length,
                                    messages: messagesOutput,
                                }, null, 2),
                            },
                        ],
                    };
                }

                case "list_inbox_threads": {
                    const validatedArgs = ListInboxThreadsSchema.parse(args);
                    const threadsResponse = await gmail.users.threads.list({
                        userId: 'me',
                        q: validatedArgs.query || 'in:inbox',
                        maxResults: validatedArgs.maxResults || 50,
                    });

                    const threads = threadsResponse.data.threads || [];

                    // Fetch metadata for each thread to get message count and latest message info
                    const threadDetails = await Promise.all(
                        threads.map(async (thread) => {
                            const detail = await gmail.users.threads.get({
                                userId: 'me',
                                id: thread.id!,
                                format: 'metadata',
                                metadataHeaders: ['Subject', 'From', 'Date'],
                            });

                            const messages = detail.data.messages || [];
                            const latestMessage = messages[messages.length - 1];
                            const latestHeaders = latestMessage?.payload?.headers || [];

                            return {
                                threadId: thread.id || '',
                                snippet: thread.snippet || '',
                                historyId: thread.historyId || '',
                                messageCount: messages.length,
                                latestMessage: {
                                    from: latestHeaders.find(h => h.name === 'From')?.value || '',
                                    subject: latestHeaders.find(h => h.name === 'Subject')?.value || '',
                                    date: latestHeaders.find(h => h.name === 'Date')?.value || '',
                                },
                            };
                        })
                    );

                    return {
                        content: [
                            {
                                type: "text",
                                text: JSON.stringify({
                                    resultCount: threadDetails.length,
                                    threads: threadDetails,
                                }, null, 2),
                            },
                        ],
                    };
                }

                case "get_inbox_with_threads": {
                    const validatedArgs = GetInboxWithThreadsSchema.parse(args);
                    const threadsResponse = await gmail.users.threads.list({
                        userId: 'me',
                        q: validatedArgs.query || 'in:inbox',
                        maxResults: validatedArgs.maxResults || 50,
                    });

                    const threads = threadsResponse.data.threads || [];

                    if (!validatedArgs.expandThreads) {
                        // Return basic thread list without expansion (same as list_inbox_threads)
                        const threadSummaries = await Promise.all(
                            threads.map(async (thread) => {
                                const detail = await gmail.users.threads.get({
                                    userId: 'me',
                                    id: thread.id!,
                                    format: 'metadata',
                                    metadataHeaders: ['Subject', 'From', 'Date'],
                                });

                                const messages = detail.data.messages || [];
                                const latestMessage = messages[messages.length - 1];
                                const latestHeaders = latestMessage?.payload?.headers || [];

                                return {
                                    threadId: thread.id || '',
                                    snippet: thread.snippet || '',
                                    historyId: thread.historyId || '',
                                    messageCount: messages.length,
                                    latestMessage: {
                                        from: latestHeaders.find(h => h.name === 'From')?.value || '',
                                        subject: latestHeaders.find(h => h.name === 'Subject')?.value || '',
                                        date: latestHeaders.find(h => h.name === 'Date')?.value || '',
                                    },
                                };
                            })
                        );

                        return {
                            content: [
                                {
                                    type: "text",
                                    text: JSON.stringify({
                                        resultCount: threadSummaries.length,
                                        threads: threadSummaries,
                                    }, null, 2),
                                },
                            ],
                        };
                    }

                    // Expand each thread with full message content (parallel fetch)
                    const expandedThreads = await Promise.all(
                        threads.map(async (thread) => {
                            const threadDetail = await gmail.users.threads.get({
                                userId: 'me',
                                id: thread.id!,
                                format: 'full',
                            });

                            const threadMessages = threadDetail.data.messages || [];

                            const messages = threadMessages.map((msg) => {
                                const headers = msg.payload?.headers || [];
                                const subject = headers.find(h => h.name?.toLowerCase() === 'subject')?.value || '';
                                const from = headers.find(h => h.name?.toLowerCase() === 'from')?.value || '';
                                const to = headers.find(h => h.name?.toLowerCase() === 'to')?.value || '';
                                const cc = headers.find(h => h.name?.toLowerCase() === 'cc')?.value || '';
                                const bcc = headers.find(h => h.name?.toLowerCase() === 'bcc')?.value || '';
                                const date = headers.find(h => h.name?.toLowerCase() === 'date')?.value || '';

                                const { text, html } = extractEmailContent(msg.payload as GmailMessagePart || {});
                                const body = text || html || '';

                                // Extract attachment metadata
                                const attachments: EmailAttachment[] = [];
                                const processAttachmentParts = (part: GmailMessagePart) => {
                                    if (part.body && part.body.attachmentId) {
                                        const filename = part.filename || `attachment-${part.body.attachmentId}`;
                                        attachments.push({
                                            id: part.body.attachmentId,
                                            filename: filename,
                                            mimeType: part.mimeType || 'application/octet-stream',
                                            size: part.body.size || 0,
                                        });
                                    }
                                    if (part.parts) {
                                        part.parts.forEach((subpart: GmailMessagePart) => processAttachmentParts(subpart));
                                    }
                                };
                                if (msg.payload) {
                                    processAttachmentParts(msg.payload as GmailMessagePart);
                                }

                                return {
                                    messageId: msg.id || '',
                                    threadId: msg.threadId || '',
                                    from,
                                    to,
                                    cc,
                                    bcc,
                                    subject,
                                    date,
                                    body,
                                    labelIds: msg.labelIds || [],
                                    attachments: attachments.map(a => ({
                                        filename: a.filename,
                                        mimeType: a.mimeType,
                                        size: a.size,
                                    })),
                                };
                            });

                            return {
                                threadId: thread.id || '',
                                messageCount: messages.length,
                                messages,
                            };
                        })
                    );

                    return {
                        content: [
                            {
                                type: "text",
                                text: JSON.stringify({
                                    resultCount: expandedThreads.length,
                                    threads: expandedThreads,
                                }, null, 2),
                            },
                        ],
                    };
                }

                case "reply_all": {
                    const validatedArgs = ReplyAllSchema.parse(args);

                    // Fetch the original email to get headers
                    const originalEmail = await gmail.users.messages.get({
                        userId: 'me',
                        id: validatedArgs.messageId,
                        format: 'full',
                    });

                    const headers = originalEmail.data.payload?.headers || [];
                    const threadId = originalEmail.data.threadId || '';

                    // Extract relevant headers
                    const originalFrom = headers.find(h => h.name?.toLowerCase() === 'from')?.value || '';
                    const originalTo = headers.find(h => h.name?.toLowerCase() === 'to')?.value || '';
                    const originalCc = headers.find(h => h.name?.toLowerCase() === 'cc')?.value || '';
                    const originalSubject = headers.find(h => h.name?.toLowerCase() === 'subject')?.value || '';
                    const originalMessageId = headers.find(h => h.name?.toLowerCase() === 'message-id')?.value || '';
                    const originalReferences = headers.find(h => h.name?.toLowerCase() === 'references')?.value || '';

                    // Get authenticated user's email to exclude from recipients
                    const profile = await gmail.users.getProfile({ userId: 'me' });
                    const myEmail = profile.data.emailAddress?.toLowerCase() || '';

                    // Build recipient list using helper functions
                    const { to: replyTo, cc: replyCc } = buildReplyAllRecipients(
                        originalFrom,
                        originalTo,
                        originalCc,
                        myEmail
                    );

                    if (replyTo.length === 0) {
                        throw new Error('Could not determine recipient for reply');
                    }

                    // Build subject with "Re:" prefix if not already present
                    const replySubject = addRePrefix(originalSubject);

                    // Build References header (original References + original Message-ID)
                    const references = buildReferencesHeader(originalReferences, originalMessageId);

                    // Prepare the email arguments for handleEmailAction
                    const emailArgs = {
                        to: replyTo,
                        cc: replyCc.length > 0 ? replyCc : undefined,
                        subject: replySubject,
                        body: validatedArgs.body,
                        htmlBody: validatedArgs.htmlBody,
                        mimeType: validatedArgs.mimeType,
                        threadId: threadId,
                        inReplyTo: originalMessageId,
                        attachments: validatedArgs.attachments,
                        from: validatedArgs.from, // send as a configured send-as alias
                    };

                    // Use the existing handleEmailAction to send the reply
                    const result = await handleEmailAction("send", emailArgs);

                    // Enhance the response with reply-all specific info
                    return {
                        content: [
                            {
                                type: "text",
                                text: `Reply-all sent successfully!\nTo: ${replyTo.join(', ')}${replyCc.length > 0 ? `\nCC: ${replyCc.join(', ')}` : ''}\nSubject: ${replySubject}\nThread ID: ${threadId}`,
                            },
                        ],
                    };
                }

                case "modify_thread": {
                    const validatedArgs = ModifyThreadSchema.parse(args);

                    // Prepare request body for threads.modify
                    const modifyRequestBody: any = {};

                    if (validatedArgs.addLabelIds) {
                        modifyRequestBody.addLabelIds = validatedArgs.addLabelIds;
                    }

                    if (validatedArgs.removeLabelIds) {
                        modifyRequestBody.removeLabelIds = validatedArgs.removeLabelIds;
                    }

                    await gmail.users.threads.modify({
                        userId: 'me',
                        id: validatedArgs.threadId,
                        requestBody: modifyRequestBody,
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Thread ${validatedArgs.threadId} labels updated successfully (all messages in thread modified)`,
                            },
                        ],
                    };
                }

                default:
                    throw new Error(`Unknown tool: ${name}`);
            }
        } catch (error: any) {
            return {
                content: [
                    {
                        type: "text",
                        text: `Error: ${error.message}`,
                    },
                ],
            };
        }
    }

    server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
        const { name, arguments: rawArgs } = request.params;
        const args: any = rawArgs || {};

        let session: PrincipalSession;
        try {
            session = await resolveSession(extra);
        } catch (error: any) {
            return errText(`Error: ${error.message}`);
        }

        // Account-management meta tools (no per-account Gmail client needed).
        if (name === 'list_accounts') return metaListAccounts(session);
        if (name === 'link_account') return metaLinkAccount(session);
        if (name === 'unlink_account') return metaUnlinkAccount(session, args);
        // Send-policy management (confirmed via elicitation).
        if (name === 'get_send_policy') return metaGetSendPolicy(session, args);
        if (name === 'allow_send_recipient') return metaAllowSender(session, server, args);
        if (name === 'disallow_send_recipient') return metaDisallowSender(session, server, args);
        if (name === 'set_dangerous_send') return metaSetDangerous(session, server, args);

        // Availability gating against the union of scopes across linked accounts.
        const toolDef = getToolByName(name);
        if (!toolDef || !hasScope(unionScopes(session.accounts), toolDef.scopes)) {
            return errText(`Error: Tool "${name}" is not available. You may need to re-authenticate with additional scopes.`);
        }

        const sendCtx = (a: Account): SendContext => ({
            ownEmail: a.email,
            policy: a.sendPolicy,
            persistAllow: session.setSendPolicy
                ? async (entries: string[]) => {
                    const cur = a.sendPolicy || { allowlist: [], dangerouslyAllowAll: false };
                    const merged = Array.from(
                        new Set([...cur.allowlist, ...entries.map(emailAddressOf)]),
                    );
                    await session.setSendPolicy!(a.sub, {
                        allowlist: merged,
                        dangerouslyAllowAll: cur.dangerouslyAllowAll,
                    });
                }
                : undefined,
        });

        const accounts = session.accounts;
        const multi = accounts.length > 1;
        const selector: string | undefined = args.account;
        const toolArgs = stripAccount(args);

        if (WRITE_TOOLS.has(name)) {
            // Writes need an explicit account whenever the choice is ambiguous.
            let target: Account | undefined;
            if (selector) target = findAccount(session, selector);
            else if (accounts.length === 1) target = accounts[0];
            if (!target) {
                return errText(
                    `Error: "${name}" changes a mailbox, so it needs an explicit account. ` +
                    `Set "account" to one of: ${accounts.map(a => a.email).join(', ')}`,
                );
            }
            const { gmail, authorizedScopes } = session.getClient(target.sub);
            const result = await executeTool(name, toolArgs, gmail, authorizedScopes, sendCtx(target));
            return multi ? annotate(target.email, target.primary, result) : result;
        }

        // Reads: a specific account if named, otherwise fan out across all linked.
        let targets: Account[];
        if (selector) {
            const a = findAccount(session, selector);
            if (!a) {
                return errText(`Error: account "${selector}" is not linked. Linked: ${accounts.map(x => x.email).join(', ')}`);
            }
            targets = [a];
        } else {
            targets = accounts;
        }

        if (!multi) {
            const { gmail, authorizedScopes } = session.getClient(targets[0].sub);
            return executeTool(name, toolArgs, gmail, authorizedScopes, sendCtx(targets[0]));
        }

        const content: any[] = [];
        for (const acct of targets) {
            const { gmail, authorizedScopes } = session.getClient(acct.sub);
            const result = await executeTool(name, toolArgs, gmail, authorizedScopes, sendCtx(acct));
            content.push({ type: 'text', text: `=== ${acct.email}${acct.primary ? ' (primary)' : ''} ===` });
            for (const c of result?.content || []) content.push(c);
        }
        return { content };
    });

    return server;
}

main().catch((error) => {
    console.error('Server error:', error);
    process.exit(1);
});
