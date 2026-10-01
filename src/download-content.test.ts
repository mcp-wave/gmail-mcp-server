/**
 * Tests for download content delivery (commit 44badb4):
 * downloadAttachment and deliverEmailExport return file bytes inside the MCP
 * tool result (image/resource blocks); the hosted server never touches its
 * own filesystem, and the local stdio server still writes when asked.
 */

import { describe, it, expect, vi, afterEach, type Mock } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
 MAX_INLINE_BYTES,
 downloadAttachment,
 deliverEmailExport,
 withInlineBudget,
 type ToolResult,
 type ImageBlock,
 type TextBlock,
 type ResourceBlock,
 type DeliveryContext,
 type EmailExport,
 type MessagePart,
} from './download-content.js';
import { toolDefinitions, toMcpTools } from './tools.js';

const HOSTED: DeliveryContext = { account: 'user@gmail.com', localFilesystem: false };
const LOCAL: DeliveryContext = { account: 'user@gmail.com', localFilesystem: true };

type Block = ToolResult['content'][number];
type ResourcePayload = Extract<ResourceBlock['resource'], { blob?: string; text?: string }>;

type FakeGmail = {
 users: {
  messages: {
   get: Mock;
   attachments: { get: Mock };
  };
 };
};

/** A fake gmail whose messages.get serves `payload` and whose attachments.get serves bytes by id, base64url-encoded like googleapis. */
function fakeGmail(payload: MessagePart, attachmentsById: Record<string, Buffer>): FakeGmail {
 return {
  users: {
   messages: {
    get: vi.fn(async () => ({ data: { payload } })),
    attachments: {
     get: vi.fn(async ({ id }: { id: string }) => {
      const bytes = attachmentsById[id];
      if (!bytes) throw new Error(`No attachment data for id ${id}`);
      return { data: { data: bytes.toString('base64url') } };
     }),
    },
   },
  },
 };
}

/** An attachment part carrying a body with an attachmentId, as Gmail serves it. */
function filePart(overrides: {
 partId?: string;
 filename?: string;
 mimeType: string;
 attachmentId: string;
 size: number;
}): MessagePart {
 return {
  partId: overrides.partId ?? '0',
  filename: overrides.filename,
  mimeType: overrides.mimeType,
  body: { attachmentId: overrides.attachmentId, size: overrides.size },
 };
}

function isImage(block: Block): block is ImageBlock {
 return block.type === 'image';
}

function isResource(block: Block): block is ResourceBlock {
 return block.type === 'resource';
}

function isText(block: Block): block is TextBlock {
 return block.type === 'text';
}

function attachmentOf(result: ToolResult): ImageBlock | null {
 return result.content.find(isImage) ?? null;
}

function resourceOf(result: ToolResult): ResourceBlock | null {
 return result.content.find(isResource) ?? null;
}

function textOf(result: ToolResult): string {
 return result.content.filter(isText).map(b => b.text).join('\n');
}

/** A promise with its resolver, for gating a fake fetch mid-flight. */
function deferred(): { promise: Promise<void>; resolve: () => void } {
 const { promise, resolve } = Promise.withResolvers<void>();
 return { promise, resolve };
}

/** Let pending microtasks and one immediate callback run. */
function flush(): Promise<void> {
 return new Promise(r => setImmediate(r));
}

afterEach(() => {
 vi.restoreAllMocks();
});

describe('downloadAttachment returns a PNG as an image block', () => {
 it('carries the exact input bytes, the part mimeType and a text summary', async () => {
  const bytes = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x01, 0x02, 0x03, 0x04]);
  const payload = filePart({ filename: 'logo.png', mimeType: 'image/png', attachmentId: 'att-1', size: bytes.length });
  const gmail = fakeGmail(payload, { 'att-1': bytes });

  const result = await downloadAttachment(gmail, { messageId: 'm1', attachmentId: 'att-1' }, HOSTED);

  expect(result.isError).toBeUndefined();
  const image = attachmentOf(result);
  expect(image).not.toBeNull();
  expect(image!.mimeType).toBe('image/png');
  expect(Buffer.from(image!.data, 'base64').equals(bytes)).toBe(true);

  const text = textOf(result);
  expect(text).toContain('logo.png');
  expect(text).toContain(`${bytes.length} bytes`);
  expect(text).toContain('user@gmail.com');
 });
});

describe('downloadAttachment returns non-raster files as embedded resources', () => {
 it('returns a PDF as a resource with exact bytes, mimeType and a uri naming message and file', async () => {
  const bytes = Buffer.from('%PDF-1.4 fake pdf bytes'.repeat(4));
  const payload = filePart({ filename: 'report.pdf', mimeType: 'application/pdf', attachmentId: 'att-pdf', size: bytes.length });
  const gmail = fakeGmail(payload, { 'att-pdf': bytes });

  const result = await downloadAttachment(gmail, { messageId: 'm1', attachmentId: 'att-pdf' }, HOSTED);

  expect(attachmentOf(result)).toBeNull();
  const block = resourceOf(result);
  expect(block).not.toBeNull();
  const resource = block!.resource as ResourcePayload;
  expect(resource.mimeType).toBe('application/pdf');
  expect(Buffer.from(resource.blob ?? '', 'base64').equals(bytes)).toBe(true);
  expect(resource.uri).toContain('m1');
  expect(resource.uri).toContain('report.pdf');
 });

 it('returns image/svg+xml as a resource, not an image block', async () => {
  const bytes = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"></svg>');
  const payload = filePart({ filename: 'diagram.svg', mimeType: 'image/svg+xml', attachmentId: 'att-svg', size: bytes.length });
  const gmail = fakeGmail(payload, { 'att-svg': bytes });

  const result = await downloadAttachment(gmail, { messageId: 'm1', attachmentId: 'att-svg' }, HOSTED);

  expect(attachmentOf(result)).toBeNull();
  const resource = resourceOf(result)!.resource as ResourcePayload;
  expect(resource.mimeType).toBe('image/svg+xml');
 });

 it('returns a PNG whose base64 exceeds the 5 MiB image-block limit as a resource', async () => {
  // 4,000,000 bytes -> ~5.34 MiB of base64, over the image-block cap but under MAX_INLINE_BYTES.
  const bytes = Buffer.alloc(4_000_000, 0x7f);
  const payload = filePart({ filename: 'big.png', mimeType: 'image/png', attachmentId: 'att-big', size: bytes.length });
  const gmail = fakeGmail(payload, { 'att-big': bytes });

  const result = await downloadAttachment(gmail, { messageId: 'm1', attachmentId: 'att-big' }, HOSTED);

  expect(result.isError).toBeUndefined();
  expect(attachmentOf(result)).toBeNull();
  const resource = resourceOf(result)!.resource as ResourcePayload;
  expect(resource.mimeType).toBe('image/png');
  expect(Buffer.from(resource.blob ?? '', 'base64').equals(bytes)).toBe(true);
 });
});

describe('downloadAttachment finds the part a rotated attachmentId refers to', () => {
 it('uses filename and mimeType from the message part when the caller id is stale', async () => {
  const bytes = Buffer.from('unique-size-body');
  // The caller's id no longer exists; the re-fetched message carries a fresh id.
  const payload = filePart({ filename: 'fresh-name.bin', mimeType: 'application/x-fresh', attachmentId: 'fresh-id', size: bytes.length });
  const gmail = fakeGmail(payload, { 'rotated-id': bytes, 'fresh-id': bytes });

  const result = await downloadAttachment(gmail, { messageId: 'm1', attachmentId: 'rotated-id' }, HOSTED);

  expect(result.isError).toBeUndefined();
  const text = textOf(result);
  expect(text).toContain('fresh-name.bin');
  expect(text).toContain('application/x-fresh');
 });

 it('disambiguates two same-size parts by comparing the downloaded bytes', async () => {
  const bytesA = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);
  const bytesB = Buffer.from([9, 10, 11, 12, 13, 14, 15, 16]);
  const payload: MessagePart = {
   mimeType: 'multipart/mixed',
   parts: [
    filePart({ partId: '0', filename: 'a.bin', mimeType: 'application/x-a', attachmentId: 'id-a', size: bytesA.length }),
    filePart({ partId: '1', filename: 'b.bin', mimeType: 'application/x-b', attachmentId: 'id-b', size: bytesB.length }),
   ],
  };
  // The caller's rotated id serves bytes equal to part b's content.
  const gmail = fakeGmail(payload, { 'rotated-id': bytesB, 'id-a': bytesA, 'id-b': bytesB });

  const result = await downloadAttachment(gmail, { messageId: 'm1', attachmentId: 'rotated-id' }, HOSTED);

  expect(result.isError).toBeUndefined();
  const resource = resourceOf(result)!.resource as ResourcePayload;
  expect(resource.mimeType).toBe('application/x-b');
  expect(resource.uri).toContain('b.bin');
  const text = textOf(result);
  expect(text).toContain('b.bin');
 });
});

describe('hosted mode never writes the caller\'s file to the server disk', () => {
 it('downloadAttachment with savePath set: no fs writes, bytes still returned', async () => {
  const writeFile = vi.spyOn(fs, 'writeFileSync');
  const mkdir = vi.spyOn(fs, 'mkdirSync');
  const bytes = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x01, 0x02, 0x03]);
  const payload = filePart({ filename: 'logo.png', mimeType: 'image/png', attachmentId: 'att-1', size: bytes.length });
  const gmail = fakeGmail(payload, { 'att-1': bytes });

  const result = await downloadAttachment(
   gmail,
   { messageId: 'm1', attachmentId: 'att-1', savePath: '/tmp/should-never-happen' },
   HOSTED,
  );

  expect(writeFile).not.toHaveBeenCalled();
  expect(mkdir).not.toHaveBeenCalled();
  expect(result.isError).toBeUndefined();
  const image = attachmentOf(result);
  expect(image).not.toBeNull();
  expect(Buffer.from(image!.data, 'base64').equals(bytes)).toBe(true);
 });

 it('deliverEmailExport with savePath set: no fs writes, the email still comes back', () => {
  const writeFile = vi.spyOn(fs, 'writeFileSync');
  const mkdir = vi.spyOn(fs, 'mkdirSync');
  const exp: EmailExport = { messageId: 'm2', format: 'eml', bytes: Buffer.from('raw eml bytes'), metadata: {} };

  const result = deliverEmailExport(exp, HOSTED, '/tmp/should-never-happen');

  expect(writeFile).not.toHaveBeenCalled();
  expect(mkdir).not.toHaveBeenCalled();
  expect(result.isError).toBeUndefined();
  const resource = resourceOf(result)!.resource as ResourcePayload;
  expect(Buffer.from(resource.blob ?? '', 'base64').toString()).toBe('raw eml bytes');
 });
});

describe('local mode writes into the requested directory', () => {
 it('downloadAttachment writes the exact bytes and keeps a traversal filename inside the dir', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gmail-dl-'));
  try {
   const bytes = Buffer.from('local write payload');
   const payload = filePart({ filename: 'originally.txt', mimeType: 'text/plain', attachmentId: 'att-1', size: bytes.length });
   const gmail = fakeGmail(payload, { 'att-1': bytes });

   const result = await downloadAttachment(
    gmail,
    { messageId: 'm1', attachmentId: 'att-1', filename: '../../evil', savePath: dir },
    LOCAL,
   );

   expect(result.isError).toBeUndefined();
   expect(fs.readdirSync(dir)).toEqual(['evil']);
   expect(fs.readFileSync(path.join(dir, 'evil')).equals(bytes)).toBe(true);
  } finally {
   fs.rmSync(dir, { recursive: true, force: true });
  }
 });

 it('deliverEmailExport writes the export file into the directory', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gmail-dl-'));
  try {
   const exp: EmailExport = { messageId: 'm3', format: 'json', bytes: Buffer.from('{"a":1}'), metadata: {} };

   const result = deliverEmailExport(exp, LOCAL, dir);

   expect(result.isError).toBeUndefined();
   expect(fs.readdirSync(dir)).toEqual(['m3.json']);
   expect(fs.readFileSync(path.join(dir, 'm3.json'), 'utf-8')).toBe('{"a":1}');
  } finally {
   fs.rmSync(dir, { recursive: true, force: true });
  }
 });
});

describe('oversize files are refused, not truncated', () => {
 it('MAX_INLINE_BYTES + 1 bytes is refused before any bytes are fetched', async () => {
  const payload = filePart({
   filename: 'huge.bin',
   mimeType: 'application/octet-stream',
   attachmentId: 'att-huge',
   size: MAX_INLINE_BYTES + 1,
  });
  // No attachment data in the fake: a fetch attempt would throw, so reaching the
  // size refusal at all proves it happened before fetching.
  const gmail = fakeGmail(payload, {});

  const result = await downloadAttachment(gmail, { messageId: 'm1', attachmentId: 'att-huge' }, HOSTED);

  expect(result.isError).toBe(true);
  expect(attachmentOf(result)).toBeNull();
  expect(resourceOf(result)).toBeNull();
  expect(gmail.users.messages.attachments.get).not.toHaveBeenCalled();
 });

 it('exactly MAX_INLINE_BYTES is still accepted', async () => {
  const bytes = Buffer.alloc(MAX_INLINE_BYTES, 0x62);
  const payload = filePart({ filename: 'max.bin', mimeType: 'application/octet-stream', attachmentId: 'att-max', size: bytes.length });
  const gmail = fakeGmail(payload, { 'att-max': bytes });

  const result = await downloadAttachment(gmail, { messageId: 'm1', attachmentId: 'att-max' }, HOSTED);

  expect(result.isError).toBeUndefined();
  const block = resourceOf(result);
  expect(block).not.toBeNull();
  expect(Buffer.from((block!.resource as ResourcePayload).blob ?? '', 'base64').equals(bytes)).toBe(true);
 });
});

describe('concurrent inline deliveries share a byte budget', () => {
 it('a third download whose reservation would exceed the budget waits until an earlier one finishes', async () => {
  // Two reservations of MAX_INLINE_BYTES fill the 2x budget exactly; the third must wait.
  const size = MAX_INLINE_BYTES;
  const bytesFor: Record<string, Buffer> = {
   'id-1': Buffer.alloc(size, 0x11),
   'id-2': Buffer.alloc(size, 0x22),
   'id-3': Buffer.alloc(size, 0x33),
  };
  const payload: MessagePart = {
   mimeType: 'multipart/mixed',
   parts: [
    filePart({ partId: '0', filename: 'one.bin', mimeType: 'application/x-one', attachmentId: 'id-1', size }),
    filePart({ partId: '1', filename: 'two.bin', mimeType: 'application/x-two', attachmentId: 'id-2', size }),
    filePart({ partId: '2', filename: 'three.bin', mimeType: 'application/x-three', attachmentId: 'id-3', size }),
   ],
  };

  const firstFetchStarted = deferred();
  const secondFetchStarted = deferred();
  const releaseFirstFetch = deferred();
  const releaseSecondFetch = deferred();
  let firstReturned = false;
  let thirdFetchedAfterFirstReturned = false;

  const attachmentsGet = vi.fn(async ({ id }: { id: string }) => {
   if (id === 'id-1') {
    firstFetchStarted.resolve();
    await releaseFirstFetch.promise;
    firstReturned = true;
    return { data: { data: bytesFor['id-1'].toString('base64url') } };
   }
   if (id === 'id-2') {
    secondFetchStarted.resolve();
    await releaseSecondFetch.promise;
    return { data: { data: bytesFor['id-2'].toString('base64url') } };
   }
   if (id === 'id-3') thirdFetchedAfterFirstReturned = firstReturned;
   return { data: { data: bytesFor[id].toString('base64url') } };
  });
  const gmail: FakeGmail = {
   users: {
    messages: { get: vi.fn(async () => ({ data: { payload } })), attachments: { get: attachmentsGet } },
   },
  };

  const first = downloadAttachment(gmail, { messageId: 'm1', attachmentId: 'id-1' }, HOSTED);
  await firstFetchStarted.promise;
  const second = downloadAttachment(gmail, { messageId: 'm1', attachmentId: 'id-2' }, HOSTED);
  await secondFetchStarted.promise;
  const third = downloadAttachment(gmail, { messageId: 'm1', attachmentId: 'id-3' }, HOSTED);
  await flush();

  // The first two hold the whole budget; the third must not have fetched yet.
  const thirdFetches = attachmentsGet.mock.calls.filter(c => c[0].id === 'id-3');
  expect(thirdFetches).toHaveLength(0);

  releaseFirstFetch.resolve();
  // The release fires on setImmediate after the first result returns; wait until
  // the third fetch has actually started rather than guessing the flush count.
  for (let i = 0; i < 100 && !thirdFetchedAfterFirstReturned; i++) await flush();
  expect(thirdFetchedAfterFirstReturned).toBe(true);

  releaseSecondFetch.resolve();
  const results = await Promise.all([first, second, third]);
  for (const [result, id] of results.map((r, i) => [r, `id-${i + 1}`] as const)) {
   expect(result.isError).toBeUndefined();
   const blob = (resourceOf(result)!.resource as ResourcePayload).blob ?? '';
   expect(Buffer.from(blob, 'base64').equals(bytesFor[id])).toBe(true);
  }
 });

 it('withInlineBudget releases its reservation when deliver throws', async () => {
  await expect(withInlineBudget(MAX_INLINE_BYTES, async () => {
   throw new Error('boom');
  })).rejects.toThrow('boom');

  // If the failed delivery had leaked its reservation, this full-size
  // reservation would wait forever and the test would time out.
  const result = await withInlineBudget(MAX_INLINE_BYTES, async () => ({
   content: [{ type: 'text', text: 'later reservation went through' }],
  }));
  expect(result.content[0].text).toBe('later reservation went through');
 });
});

describe('deliverEmailExport resource encodings', () => {
 it('eml stays bytes: non-UTF-8 bytes survive exactly', () => {
  const bytes = Buffer.from([0x72, 0x61, 0xff, 0xfe, 0x77]); // includes 0xff 0xfe, not valid UTF-8
  const exp: EmailExport = { messageId: 'm4', format: 'eml', bytes, metadata: {} };

  const result = deliverEmailExport(exp, HOSTED);

  const resource = resourceOf(result)!.resource as ResourcePayload;
  expect(resource.mimeType).toBe('message/rfc822');
  expect('blob' in resource).toBe(true);
  expect(Buffer.from(resource.blob ?? '', 'base64').equals(bytes)).toBe(true);
 });

 it('json travels as text with mimeType application/json', () => {
  const exp: EmailExport = { messageId: 'm5', format: 'json', bytes: Buffer.from('{"subject":"hi"}'), metadata: { subject: 'hi' } };

  const result = deliverEmailExport(exp, HOSTED);

  const resource = resourceOf(result)!.resource as ResourcePayload;
  expect(resource.mimeType).toBe('application/json');
  expect('text' in resource).toBe(true);
  expect(resource.text).toBe('{"subject":"hi"}');
 });
});

describe('toMcpTools hides local-only parameters from hosted callers', () => {
 const hosted = toMcpTools(toolDefinitions, { localFilesystem: false });
 const local = toMcpTools(toolDefinitions, { localFilesystem: true });

 type JsonSchema = { properties: Record<string, unknown>; required?: string[] };

 it('download_attachment schema has no savePath or filename when hosted', () => {
  const props = (hosted.find(t => t.name === 'download_attachment')!.inputSchema as JsonSchema).properties;
  expect(props.savePath).toBeUndefined();
  expect(props.filename).toBeUndefined();
 });

 it('download_email schema has no savePath and it is not required when hosted', () => {
  const schema = hosted.find(t => t.name === 'download_email')!.inputSchema as JsonSchema;
  expect(schema.properties.savePath).toBeUndefined();
  expect(schema.required ?? []).not.toContain('savePath');
 });

 it('local stdio callers still see savePath', () => {
  expect((local.find(t => t.name === 'download_attachment')!.inputSchema as JsonSchema).properties.savePath).toBeDefined();
  expect((local.find(t => t.name === 'download_email')!.inputSchema as JsonSchema).properties.savePath).toBeDefined();
 });
});
