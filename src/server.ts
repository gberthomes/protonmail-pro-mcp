/**
 * MCP server factory: builds the tool surface for one caller.
 *
 * The same factory backs every transport (stdio, Streamable HTTP for both the
 * 2026-07-28 stateless revision and 2025-era clients, and the deprecated
 * HTTP+SSE transport). It is cheap: connections live in the shared
 * AccountRegistry, never on the McpServer instance.
 */

import { McpServer, type CallToolResult } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';

import { AccessPolicy, type Principal } from './auth/principal.js';
import type { AccountRegistry, ProtonAccount } from './mail/account.js';
import type { AccountDirectory } from './mail/directory.js';
import { VERSION } from './version.js';

export interface ServerDeps {
  registry: AccountRegistry;
  policy: AccessPolicy;
  directory: AccountDirectory;
  /** Where users add accounts (HTTP mode with the web interface). */
  adminUrl?: string;
}

const MAX_ATTACHMENT_BYTES = 15 * 1024 * 1024;

function ok(data: unknown, summary?: string): CallToolResult {
  const json = JSON.stringify(data, null, 2);
  return { content: [{ type: 'text', text: summary ? `${summary}\n\n${json}` : json }] };
}

function fail(err: unknown): CallToolResult {
  return { isError: true, content: [{ type: 'text', text: err instanceof Error ? err.message : String(err) }] };
}

const emails = z
  .union([z.string(), z.array(z.string())])
  .transform(v => (Array.isArray(v) ? v : v.split(',')).map(s => s.trim()).filter(Boolean));

const uidList = z
  .union([z.int().positive(), z.array(z.int().positive()).min(1).max(500)])
  .transform(v => (Array.isArray(v) ? v : [v]))
  .describe('Message UID or list of UIDs (from list_emails / search_emails), all in the same folder');

const attachmentInput = z.object({
  filename: z.string(),
  content: z.string().describe('Base64-encoded file content'),
  contentType: z.string().optional()
});

export function buildServer(principal: Principal, deps: ServerDeps): McpServer {
  const allowed = deps.policy.accountsFor(principal);
  const defaultAccount = deps.policy.defaultAccountFor(principal);
  const accountList = allowed.map(a => `"${a.id}" (${a.email})`).join(', ') || 'none';

  const server = new McpServer(
    { name: 'protonmail-pro-mcp', title: 'Proton Mail', version: VERSION },
    {
      capabilities: { tools: {} },
      instructions: [
        'Read, search, organize and send Proton Mail messages through Proton Mail Bridge.',
        `Accounts available to this caller: ${accountList}. Default account: ${defaultAccount ? `"${defaultAccount.id}"` : 'none'}.`,
        'Every tool accepts an optional `account` (id or email address); omit it to use the default account.',
        'Messages are addressed by `folder` + `uid`. Folder aliases: inbox, sent, drafts, trash, spam, archive, all, starred.',
        'Always confirm with the user before sending, forwarding or permanently deleting mail.'
      ].join('\n')
    }
  );

  // The account selector is mirrored into the `Mcp-Param-Account` HTTP header
  // (SEP-2243 / x-mcp-header) so gateways can route or rate-limit per mailbox.
  const accountParam = z
    .string()
    .optional()
    .describe(`Account id or email address. One of: ${accountList}. Defaults to ${defaultAccount ? `"${defaultAccount.id}"` : 'the first account'}.`)
    .meta({ 'x-mcp-header': 'Account' });
  const folderParam = z.string().optional().describe('Folder path or alias (inbox, sent, drafts, trash, spam, archive, all, starred). Default: inbox');

  const resolve = (account?: string): ProtonAccount => {
    if (allowed.length === 0) {
      throw new Error(
        deps.adminUrl && deps.policy.canSelfService(principal)
          ? `No Proton account is configured for you yet. Add one at ${deps.adminUrl}`
          : 'No Proton account is available to you. Ask the administrator to grant access (MCP_ALLOWED_USERS or the account "users" list).'
      );
    }
    const wanted = account?.trim().toLowerCase();
    const cfg = wanted ? allowed.find(a => a.id === wanted || a.email === wanted) : defaultAccount;
    if (!cfg) throw new Error(`Unknown or forbidden account "${account}". Available: ${accountList}`);
    const acc = deps.registry.get(cfg.id);
    if (!acc) throw new Error(`Account "${cfg.id}" is not loaded`);
    return acc;
  };

  const tool = <S extends z.ZodObject>(
    name: string,
    config: { title: string; description: string; inputSchema: S; annotations: { readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean } },
    handler: (args: z.output<S>) => Promise<CallToolResult>
  ) => {
    server.registerTool(name, config, (async (args: z.output<S>) => {
      try {
        return await handler(args);
      } catch (err) {
        return fail(err);
      }
    }) as never);
  };

  // ------------------------------------------------------------------ accounts

  tool(
    'list_accounts',
    {
      title: 'List accounts',
      description: 'List the Proton accounts you can use and which one is the default.',
      inputSchema: z.object({}),
      annotations: { readOnlyHint: true, openWorldHint: false }
    },
    async () =>
      ok({
        caller: { sub: principal.sub, email: principal.email, name: principal.name, via: principal.via },
        default: defaultAccount?.id,
        accounts: allowed.map(a => ({ id: a.id, email: a.email, displayName: a.displayName }))
      })
  );

  tool(
    'check_connection',
    {
      title: 'Check Bridge connection',
      description: 'Check that Proton Mail Bridge IMAP and SMTP are reachable for an account.',
      inputSchema: z.object({ account: accountParam }),
      annotations: { readOnlyHint: true, openWorldHint: true }
    },
    async ({ account }) => {
      const acc = resolve(account);
      return ok({ account: acc.id, ...(await acc.status()) });
    }
  );

  // ------------------------------------------------------------------ reading

  tool(
    'list_folders',
    {
      title: 'List folders',
      description: 'List folders and labels with message and unread counts.',
      inputSchema: z.object({ account: accountParam }),
      annotations: { readOnlyHint: true, openWorldHint: true }
    },
    async ({ account }) => {
      const acc = resolve(account);
      return ok({ account: acc.id, folders: await acc.listFolders() });
    }
  );

  tool(
    'list_emails',
    {
      title: 'List emails',
      description: 'List the most recent messages of a folder (newest first) with sender, subject, date and flags.',
      inputSchema: z.object({
        account: accountParam,
        folder: folderParam,
        limit: z.int().min(1).max(200).default(25),
        offset: z.int().min(0).default(0).describe('Number of newest messages to skip (pagination)'),
        unreadOnly: z.boolean().default(false)
      }),
      annotations: { readOnlyHint: true, openWorldHint: true }
    },
    async ({ account, folder, limit, offset, unreadOnly }) => {
      const acc = resolve(account);
      const res = await acc.listMessages(folder, { limit, offset, unreadOnly });
      return ok({ account: acc.id, ...res, nextOffset: offset + res.messages.length < res.total ? offset + res.messages.length : undefined });
    }
  );

  tool(
    'search_emails',
    {
      title: 'Search emails',
      description: 'Search a folder by sender, recipient, subject, text, dates and flags. Use folder "all" to search every folder.',
      inputSchema: z.object({
        account: accountParam,
        folder: folderParam,
        text: z.string().optional().describe('Matches headers and body'),
        from: z.string().optional(),
        to: z.string().optional(),
        subject: z.string().optional(),
        body: z.string().optional(),
        since: z.string().optional().describe('ISO date (inclusive), e.g. 2026-01-31'),
        before: z.string().optional().describe('ISO date (exclusive)'),
        unread: z.boolean().optional(),
        flagged: z.boolean().optional(),
        answered: z.boolean().optional(),
        largerThanBytes: z.int().positive().optional(),
        limit: z.int().min(1).max(200).default(50)
      }),
      annotations: { readOnlyHint: true, openWorldHint: true }
    },
    async ({ account, folder, limit, largerThanBytes, ...criteria }) => {
      const acc = resolve(account);
      return ok({ account: acc.id, ...(await acc.search(folder, { ...criteria, larger: largerThanBytes }, limit)) });
    }
  );

  tool(
    'get_email',
    {
      title: 'Read email',
      description: 'Read one message: headers, plain-text body (HTML converted when needed) and attachment list.',
      inputSchema: z.object({
        account: accountParam,
        folder: folderParam,
        uid: z.int().positive(),
        markAsRead: z.boolean().default(false),
        includeHtml: z.boolean().default(false),
        maxChars: z.int().min(500).max(500_000).default(50_000)
      }),
      annotations: { readOnlyHint: false, idempotentHint: true, openWorldHint: true }
    },
    async ({ account, folder, uid, markAsRead, includeHtml, maxChars }) => {
      const acc = resolve(account);
      return ok({ account: acc.id, ...(await acc.getMessage(folder, uid, { markAsRead, includeHtml, maxChars })) });
    }
  );

  server.registerTool(
    'get_attachment',
    {
      title: 'Download attachment',
      description: 'Return one attachment of a message as an embedded resource (base64). Use the index from get_email.',
      inputSchema: z.object({ account: accountParam, folder: folderParam, uid: z.int().positive(), index: z.int().min(0) }),
      annotations: { readOnlyHint: true, openWorldHint: true }
    },
    async ({ account, folder, uid, index }) => {
      try {
        const acc = resolve(account);
        const att = await acc.getAttachment(folder, uid, index);
        if (att.size > MAX_ATTACHMENT_BYTES) throw new Error(`Attachment is ${att.size} bytes, above the ${MAX_ATTACHMENT_BYTES} bytes limit`);
        const resolvedFolder = await acc.resolveFolder(folder);
        return {
          content: [
            { type: 'text', text: `${att.filename ?? 'attachment'} (${att.contentType}, ${att.size} bytes)` },
            {
              type: 'resource',
              resource: {
                uri: `protonmail://${acc.id}/${encodeURIComponent(resolvedFolder)}/${uid}/attachments/${index}`,
                mimeType: att.contentType,
                blob: att.base64
              }
            }
          ]
        };
      } catch (err) {
        return fail(err);
      }
    }
  );

  // ------------------------------------------------------------------ writing

  tool(
    'send_email',
    {
      title: 'Send email',
      description: 'Send a new email from a Proton account. Confirm recipients and content with the user first.',
      inputSchema: z.object({
        account: accountParam,
        to: emails.describe('Recipient address(es), comma-separated or array'),
        cc: emails.optional(),
        bcc: emails.optional(),
        subject: z.string(),
        body: z.string().describe('Message body'),
        isHtml: z.boolean().default(false),
        replyTo: z.string().optional(),
        priority: z.enum(['high', 'normal', 'low']).optional(),
        attachments: z.array(attachmentInput).max(20).optional()
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true }
    },
    async ({ account, body, isHtml, ...msg }) => {
      const acc = resolve(account);
      if (msg.to.length === 0) throw new Error('At least one recipient is required');
      const res = await acc.send({ ...msg, text: isHtml ? undefined : body, html: isHtml ? body : undefined });
      return ok({ account: acc.id, from: acc.email, ...res }, 'Email sent.');
    }
  );

  tool(
    'reply_email',
    {
      title: 'Reply to email',
      description: 'Reply (or reply-all) to a message, keeping the thread headers and quoting the original. Set draft=true to save it in Drafts instead of sending.',
      inputSchema: z.object({
        account: accountParam,
        folder: folderParam,
        uid: z.int().positive(),
        body: z.string(),
        isHtml: z.boolean().default(false),
        replyAll: z.boolean().default(false),
        draft: z.boolean().default(false),
        attachments: z.array(attachmentInput).max(20).optional()
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true }
    },
    async ({ account, folder, uid, body, isHtml, replyAll, draft, attachments }) => {
      const acc = resolve(account);
      const reply = await acc.buildReply(folder, uid, isHtml ? { html: body } : { text: body }, replyAll);
      reply.attachments = attachments;
      if (draft) return ok({ account: acc.id, ...(await acc.saveDraft(reply)), to: reply.to, cc: reply.cc, subject: reply.subject }, 'Reply saved as draft.');
      const sent = await acc.send(reply);
      await acc.setFlags(folder, [uid], { seen: true, answered: true }).catch(() => undefined);
      return ok({ account: acc.id, to: reply.to, cc: reply.cc, subject: reply.subject, ...sent }, 'Reply sent.');
    }
  );

  tool(
    'forward_email',
    {
      title: 'Forward email',
      description: 'Forward a message (optionally with its attachments) to new recipients.',
      inputSchema: z.object({
        account: accountParam,
        folder: folderParam,
        uid: z.int().positive(),
        to: emails,
        note: z.string().optional().describe('Text added above the forwarded message'),
        includeAttachments: z.boolean().default(true),
        draft: z.boolean().default(false)
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true }
    },
    async ({ account, folder, uid, to, note, includeAttachments, draft }) => {
      const acc = resolve(account);
      const fwd = await acc.buildForward(folder, uid, to, note, includeAttachments);
      if (draft) return ok({ account: acc.id, ...(await acc.saveDraft(fwd)), subject: fwd.subject }, 'Forward saved as draft.');
      return ok({ account: acc.id, subject: fwd.subject, ...(await acc.send(fwd)) }, 'Message forwarded.');
    }
  );

  tool(
    'create_draft',
    {
      title: 'Create draft',
      description: 'Save a message in the Drafts folder without sending it (safe way to prepare an email for the user to review).',
      inputSchema: z.object({
        account: accountParam,
        to: emails.optional(),
        cc: emails.optional(),
        bcc: emails.optional(),
        subject: z.string(),
        body: z.string(),
        isHtml: z.boolean().default(false),
        attachments: z.array(attachmentInput).max(20).optional()
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true }
    },
    async ({ account, body, isHtml, to, ...msg }) => {
      const acc = resolve(account);
      const res = await acc.saveDraft({ ...msg, to: to ?? [], text: isHtml ? undefined : body, html: isHtml ? body : undefined });
      return ok({ account: acc.id, ...res }, 'Draft saved.');
    }
  );

  // ------------------------------------------------------------------ organizing

  tool(
    'mark_emails',
    {
      title: 'Mark emails',
      description: 'Mark messages as read/unread and/or starred/unstarred.',
      inputSchema: z.object({
        account: accountParam,
        folder: folderParam,
        uids: uidList,
        read: z.boolean().optional(),
        starred: z.boolean().optional()
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true }
    },
    async ({ account, folder, uids, read, starred }) => {
      if (read === undefined && starred === undefined) throw new Error('Provide "read" and/or "starred"');
      const acc = resolve(account);
      await acc.setFlags(folder, uids, { seen: read, flagged: starred });
      return ok({ account: acc.id, uids, read, starred }, 'Flags updated.');
    }
  );

  tool(
    'move_emails',
    {
      title: 'Move emails',
      description: 'Move messages to another folder (e.g. archive, spam, or a custom "Folders/..." path). Applying a label: move/copy to "Labels/<name>".',
      inputSchema: z.object({ account: accountParam, folder: folderParam, uids: uidList, destination: z.string() }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true }
    },
    async ({ account, folder, uids, destination }) => {
      const acc = resolve(account);
      return ok({ account: acc.id, uids, ...(await acc.move(folder, uids, destination)) }, 'Messages moved.');
    }
  );

  tool(
    'delete_emails',
    {
      title: 'Delete emails',
      description: 'Move messages to Trash, or delete them permanently with permanent=true (irreversible — confirm with the user).',
      inputSchema: z.object({ account: accountParam, folder: folderParam, uids: uidList, permanent: z.boolean().default(false) }),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true }
    },
    async ({ account, folder, uids, permanent }) => {
      const acc = resolve(account);
      return ok({ account: acc.id, uids, ...(await acc.delete(folder, uids, permanent)) }, permanent ? 'Messages permanently deleted.' : 'Messages moved to Trash.');
    }
  );

  tool(
    'create_folder',
    {
      title: 'Create folder',
      description: 'Create a folder ("Folders/Name") or a label ("Labels/Name").',
      inputSchema: z.object({ account: accountParam, path: z.string().min(1) }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true }
    },
    async ({ account, path }) => {
      const acc = resolve(account);
      return ok({ account: acc.id, path: await acc.createFolder(path) }, 'Folder created.');
    }
  );

  tool(
    'delete_folder',
    {
      title: 'Delete folder',
      description: 'Delete a custom folder or label (irreversible — confirm with the user).',
      inputSchema: z.object({ account: accountParam, path: z.string().min(1) }),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true }
    },
    async ({ account, path }) => {
      const acc = resolve(account);
      await acc.deleteFolder(path);
      return ok({ account: acc.id, path }, 'Folder deleted.');
    }
  );

  return server;
}
