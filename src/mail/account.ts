/**
 * One Proton account reached through Proton Mail Bridge (IMAP + SMTP).
 *
 * A single IMAP connection is kept per account and re-established on demand;
 * every operation holds the mailbox lock for its duration so concurrent tool
 * calls (several MCP clients, parallel calls) never step on each other.
 */

import { isIP } from 'node:net';

import { ImapFlow, type FetchMessageObject, type ListResponse, type MessageAddressObject, type MessageStructureObject, type SearchObject } from 'imapflow';
import { simpleParser, type AddressObject, type ParsedMail } from 'mailparser';
import nodemailer, { type Transporter } from 'nodemailer';
import MailComposer from 'nodemailer/lib/mail-composer/index.js';
import type Mail from 'nodemailer/lib/mailer/index.js';

import type { AccountConfig, Endpoint } from '../config.js';
import { createLogger } from '../logger.js';

const log = createLogger('mail');

export interface Address {
  name?: string;
  address?: string;
}

export interface MessageSummary {
  uid: number;
  folder: string;
  date?: string;
  from: Address[];
  to: Address[];
  cc: Address[];
  subject: string;
  messageId?: string;
  seen: boolean;
  flagged: boolean;
  answered: boolean;
  draft: boolean;
  hasAttachments: boolean;
  size?: number;
}

export interface AttachmentInfo {
  index: number;
  filename?: string;
  contentType: string;
  size: number;
  inline: boolean;
}

export interface MessageDetail extends MessageSummary {
  replyTo: Address[];
  inReplyTo?: string;
  references: string[];
  text: string;
  html?: string;
  truncated: boolean;
  attachments: AttachmentInfo[];
}

export interface FolderInfo {
  path: string;
  name: string;
  specialUse?: string;
  messages?: number;
  unseen?: number;
  subscribed: boolean;
}

export interface SearchCriteria {
  text?: string;
  from?: string;
  to?: string;
  subject?: string;
  body?: string;
  since?: string;
  before?: string;
  unread?: boolean;
  flagged?: boolean;
  answered?: boolean;
  larger?: number;
}

export interface OutgoingAttachment {
  filename: string;
  content: string; // base64
  contentType?: string;
}

export interface OutgoingMessage {
  to: string[];
  cc?: string[];
  bcc?: string[];
  subject: string;
  text?: string;
  html?: string;
  replyTo?: string;
  inReplyTo?: string;
  references?: string[];
  attachments?: OutgoingAttachment[];
  priority?: 'high' | 'normal' | 'low';
}

type SpecialUse = '\\Inbox' | '\\Sent' | '\\Drafts' | '\\Trash' | '\\Junk' | '\\Archive' | '\\All' | '\\Flagged';

const FALLBACK_NAMES: Record<string, string[]> = {
  '\\Sent': ['Sent', 'Sent Messages', 'Envoyés'],
  '\\Drafts': ['Drafts', 'Brouillons'],
  '\\Trash': ['Trash', 'Corbeille', 'Deleted Messages'],
  '\\Junk': ['Spam', 'Junk'],
  '\\Archive': ['Archive'],
  '\\All': ['All Mail'],
  '\\Flagged': ['Starred']
};

function addresses(list?: MessageAddressObject[]): Address[] {
  return (list ?? []).map(a => ({ name: a.name || undefined, address: a.address }));
}

function parsedAddresses(value?: AddressObject | AddressObject[]): Address[] {
  if (!value) return [];
  const arr = Array.isArray(value) ? value : [value];
  return arr.flatMap(v => v.value.map(a => ({ name: a.name || undefined, address: a.address })));
}

function hasAttachment(node?: MessageStructureObject): boolean {
  if (!node) return false;
  if (node.disposition?.toLowerCase() === 'attachment') return true;
  if (node.childNodes) return node.childNodes.some(hasAttachment);
  return false;
}

function isoDate(value?: Date | string): string | undefined {
  if (!value) return undefined;
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

function htmlToText(html: string): string {
  return html
    .replace(/<(script|style)[\s\S]*?<\/\1>/gi, '')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|tr|li|h[1-6])>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function tlsOptions(ep: Endpoint) {
  // SNI must not carry an IP address (RFC 6066).
  return { rejectUnauthorized: ep.rejectUnauthorized, ca: ep.ca, servername: isIP(ep.host) ? undefined : ep.host, minVersion: 'TLSv1.2' as const };
}

export class ProtonAccount {
  private client?: ImapFlow;
  private connecting?: Promise<ImapFlow>;
  private smtp?: Transporter;
  private folderCache?: { at: number; folders: ListResponse[] };

  constructor(readonly config: AccountConfig) {}

  get id(): string {
    return this.config.id;
  }

  get email(): string {
    return this.config.email;
  }

  // ------------------------------------------------------------------ IMAP plumbing

  private async imap(): Promise<ImapFlow> {
    if (this.client?.usable) return this.client;
    if (this.connecting) return this.connecting;
    const { imap, username, password } = this.config;
    const client = new ImapFlow({
      host: imap.host,
      port: imap.port,
      secure: imap.security === 'tls',
      doSTARTTLS: imap.security === 'starttls' ? true : imap.security === 'none' ? false : undefined,
      auth: { user: username, pass: password },
      tls: tlsOptions(imap),
      logger: false,
      clientInfo: { name: 'protonmail-pro-mcp' },
      connectionTimeout: 15_000,
      greetingTimeout: 15_000,
      socketTimeout: 5 * 60_000
    });
    client.on('error', err => log.warn(`IMAP error on ${this.id}`, err instanceof Error ? err.message : err));
    client.on('close', () => {
      if (this.client === client) this.client = undefined;
    });
    this.connecting = client
      .connect()
      .then(() => {
        this.client = client;
        log.info(`IMAP connected for ${this.id} (${imap.host}:${imap.port})`);
        return client;
      })
      .catch(err => {
        throw new Error(
          `Cannot connect to IMAP for account "${this.id}" at ${imap.host}:${imap.port} — is Proton Mail Bridge running and are the Bridge credentials correct? (${err instanceof Error ? err.message : String(err)})`
        );
      })
      .finally(() => {
        this.connecting = undefined;
      });
    return this.connecting;
  }

  private async withMailbox<T>(folder: string, fn: (client: ImapFlow) => Promise<T>, readOnly = false): Promise<T> {
    const client = await this.imap();
    const lock = await client.getMailboxLock(folder, { readOnly, acquireTimeout: 60_000 }).catch(err => {
      if ((err as { mailboxMissing?: boolean }).mailboxMissing) throw new Error(`Folder "${folder}" does not exist`);
      throw err;
    });
    try {
      return await fn(client);
    } finally {
      lock.release();
    }
  }

  private async folders(refresh = false): Promise<ListResponse[]> {
    if (!refresh && this.folderCache && Date.now() - this.folderCache.at < 60_000) return this.folderCache.folders;
    const client = await this.imap();
    const folders = await client.list();
    this.folderCache = { at: Date.now(), folders };
    return folders;
  }

  async specialFolder(use: SpecialUse): Promise<string> {
    if (use === '\\Inbox') return 'INBOX';
    const folders = await this.folders();
    const found =
      folders.find(f => f.specialUse === use) ??
      folders.find(f => (FALLBACK_NAMES[use] ?? []).some(n => n.toLowerCase() === f.path.toLowerCase()));
    if (!found) throw new Error(`No ${use.slice(1)} folder found on account "${this.id}"`);
    return found.path;
  }

  /** Accepts real paths and friendly aliases ("sent", "trash", "spam", "drafts", "archive", "all", "starred"). */
  async resolveFolder(folder?: string): Promise<string> {
    if (!folder) return 'INBOX';
    const alias: Record<string, SpecialUse> = {
      inbox: '\\Inbox',
      sent: '\\Sent',
      drafts: '\\Drafts',
      trash: '\\Trash',
      spam: '\\Junk',
      junk: '\\Junk',
      archive: '\\Archive',
      all: '\\All',
      'all mail': '\\All',
      starred: '\\Flagged'
    };
    const special = alias[folder.toLowerCase()];
    if (special) {
      try {
        return await this.specialFolder(special);
      } catch {
        return folder;
      }
    }
    return folder;
  }

  // ------------------------------------------------------------------ reading

  async listFolders(): Promise<FolderInfo[]> {
    const client = await this.imap();
    const folders = await client.list({ statusQuery: { messages: true, unseen: true } });
    this.folderCache = { at: Date.now(), folders };
    return folders.map(f => ({
      path: f.path,
      name: f.name,
      specialUse: f.specialUse,
      messages: f.status?.messages,
      unseen: f.status?.unseen,
      subscribed: f.subscribed
    }));
  }

  private summarize(folder: string, msg: FetchMessageObject): MessageSummary {
    const flags = msg.flags ?? new Set<string>();
    return {
      uid: msg.uid,
      folder,
      date: isoDate(msg.envelope?.date ?? msg.internalDate),
      from: addresses(msg.envelope?.from),
      to: addresses(msg.envelope?.to),
      cc: addresses(msg.envelope?.cc),
      subject: msg.envelope?.subject ?? '(no subject)',
      messageId: msg.envelope?.messageId,
      seen: flags.has('\\Seen'),
      flagged: flags.has('\\Flagged'),
      answered: flags.has('\\Answered'),
      draft: flags.has('\\Draft'),
      hasAttachments: hasAttachment(msg.bodyStructure),
      size: msg.size
    };
  }

  private async fetchSummaries(client: ImapFlow, folder: string, uids: number[]): Promise<MessageSummary[]> {
    if (uids.length === 0) return [];
    const out: MessageSummary[] = [];
    for await (const msg of client.fetch(uids, { uid: true, envelope: true, flags: true, size: true, internalDate: true, bodyStructure: true }, { uid: true })) {
      out.push(this.summarize(folder, msg));
    }
    // newest first
    return out.sort((a, b) => b.uid - a.uid);
  }

  async listMessages(
    folderInput: string | undefined,
    opts: { limit: number; offset: number; unreadOnly?: boolean }
  ): Promise<{ folder: string; total: number; messages: MessageSummary[] }> {
    const folder = await this.resolveFolder(folderInput);
    return this.withMailbox(
      folder,
      async client => {
        const query: SearchObject = opts.unreadOnly ? { seen: false } : { all: true };
        const uids = ((await client.search(query, { uid: true })) || []).sort((a, b) => b - a);
        const page = uids.slice(opts.offset, opts.offset + opts.limit);
        return { folder, total: uids.length, messages: await this.fetchSummaries(client, folder, page) };
      },
      true
    );
  }

  async search(
    folderInput: string | undefined,
    criteria: SearchCriteria,
    limit: number
  ): Promise<{ folder: string; total: number; messages: MessageSummary[] }> {
    const folder = await this.resolveFolder(folderInput);
    const query: SearchObject = {};
    if (criteria.text) query.text = criteria.text;
    if (criteria.from) query.from = criteria.from;
    if (criteria.to) query.to = criteria.to;
    if (criteria.subject) query.subject = criteria.subject;
    if (criteria.body) query.body = criteria.body;
    if (criteria.since) query.since = new Date(criteria.since);
    if (criteria.before) query.before = new Date(criteria.before);
    if (criteria.unread !== undefined) query.seen = !criteria.unread;
    if (criteria.flagged !== undefined) query.flagged = criteria.flagged;
    if (criteria.answered !== undefined) query.answered = criteria.answered;
    if (criteria.larger !== undefined) query.larger = criteria.larger;
    if (Object.keys(query).length === 0) query.all = true;
    return this.withMailbox(
      folder,
      async client => {
        const uids = ((await client.search(query, { uid: true })) || []).sort((a, b) => b - a);
        return { folder, total: uids.length, messages: await this.fetchSummaries(client, folder, uids.slice(0, limit)) };
      },
      true
    );
  }

  private async fetchParsed(folder: string, uid: number): Promise<{ msg: FetchMessageObject; parsed: ParsedMail }> {
    return this.withMailbox(
      folder,
      async client => {
        const msg = await client.fetchOne(String(uid), { uid: true, source: true, flags: true, envelope: true, size: true, internalDate: true, bodyStructure: true }, { uid: true });
        if (!msg || !msg.source) throw new Error(`Message ${uid} not found in "${folder}"`);
        const parsed = await simpleParser(msg.source);
        return { msg, parsed };
      },
      true
    );
  }

  async getMessage(folderInput: string | undefined, uid: number, opts: { maxChars: number; includeHtml: boolean; markAsRead: boolean }): Promise<MessageDetail> {
    const folder = await this.resolveFolder(folderInput);
    const { msg, parsed } = await this.fetchParsed(folder, uid);
    let text = parsed.text ?? (parsed.html ? htmlToText(parsed.html) : '');
    let truncated = false;
    if (text.length > opts.maxChars) {
      text = text.slice(0, opts.maxChars);
      truncated = true;
    }
    if (opts.markAsRead) await this.setFlags(folder, [uid], { seen: true });
    const refs = parsed.references ? (Array.isArray(parsed.references) ? parsed.references : [parsed.references]) : [];
    return {
      ...this.summarize(folder, msg),
      seen: opts.markAsRead || this.summarize(folder, msg).seen,
      replyTo: parsedAddresses(parsed.replyTo),
      inReplyTo: parsed.inReplyTo,
      references: refs,
      text,
      html: opts.includeHtml && parsed.html ? parsed.html.slice(0, opts.maxChars) : undefined,
      truncated,
      attachments: parsed.attachments.map((a, index) => ({
        index,
        filename: a.filename,
        contentType: a.contentType,
        size: a.size,
        inline: a.contentDisposition === 'inline'
      }))
    };
  }

  async getAttachment(folderInput: string | undefined, uid: number, index: number): Promise<{ filename?: string; contentType: string; size: number; base64: string }> {
    const folder = await this.resolveFolder(folderInput);
    const { parsed } = await this.fetchParsed(folder, uid);
    const att = parsed.attachments[index];
    if (!att) throw new Error(`Message ${uid} has no attachment #${index} (it has ${parsed.attachments.length})`);
    return { filename: att.filename, contentType: att.contentType, size: att.size, base64: att.content.toString('base64') };
  }

  // ------------------------------------------------------------------ organizing

  async setFlags(folderInput: string | undefined, uids: number[], flags: { seen?: boolean; flagged?: boolean; answered?: boolean }): Promise<void> {
    const folder = await this.resolveFolder(folderInput);
    await this.withMailbox(folder, async client => {
      const add: string[] = [];
      const remove: string[] = [];
      if (flags.seen !== undefined) (flags.seen ? add : remove).push('\\Seen');
      if (flags.flagged !== undefined) (flags.flagged ? add : remove).push('\\Flagged');
      if (flags.answered !== undefined) (flags.answered ? add : remove).push('\\Answered');
      if (add.length) await client.messageFlagsAdd(uids, add, { uid: true });
      if (remove.length) await client.messageFlagsRemove(uids, remove, { uid: true });
    });
  }

  async move(folderInput: string | undefined, uids: number[], destinationInput: string): Promise<{ from: string; to: string }> {
    const folder = await this.resolveFolder(folderInput);
    const destination = await this.resolveFolder(destinationInput);
    await this.withMailbox(folder, async client => {
      const res = await client.messageMove(uids, destination, { uid: true });
      if (!res) throw new Error(`Move to "${destination}" failed`);
    });
    return { from: folder, to: destination };
  }

  async delete(folderInput: string | undefined, uids: number[], permanent: boolean): Promise<{ permanent: boolean; folder: string; movedTo?: string }> {
    const folder = await this.resolveFolder(folderInput);
    const trash = await this.specialFolder('\\Trash').catch(() => undefined);
    if (!permanent && trash && trash !== folder) {
      await this.move(folder, uids, trash);
      return { permanent: false, folder, movedTo: trash };
    }
    await this.withMailbox(folder, async client => {
      await client.messageDelete(uids, { uid: true });
    });
    return { permanent: true, folder };
  }

  async createFolder(path: string): Promise<string> {
    const client = await this.imap();
    const res = await client.mailboxCreate(path);
    this.folderCache = undefined;
    return res.path;
  }

  async deleteFolder(path: string): Promise<void> {
    const client = await this.imap();
    await client.mailboxDelete(path);
    this.folderCache = undefined;
  }

  // ------------------------------------------------------------------ sending

  private transporter(): Transporter {
    if (this.smtp) return this.smtp;
    const { smtp, username, password } = this.config;
    this.smtp = nodemailer.createTransport({
      host: smtp.host,
      port: smtp.port,
      secure: smtp.security === 'tls',
      requireTLS: smtp.security === 'starttls',
      ignoreTLS: smtp.security === 'none',
      auth: { user: username, pass: password },
      tls: tlsOptions(smtp),
      disableFileAccess: true,
      disableUrlAccess: true,
      connectionTimeout: 15_000,
      greetingTimeout: 15_000
    });
    return this.smtp;
  }

  private mailOptions(message: OutgoingMessage): Mail.Options {
    const from = this.config.displayName ? { name: this.config.displayName, address: this.config.email } : this.config.email;
    return {
      // Content comes from the model: never let it pull local files or URLs into a message.
      disableFileAccess: true,
      disableUrlAccess: true,
      from,
      to: message.to,
      cc: message.cc,
      bcc: message.bcc,
      subject: message.subject,
      text: message.text,
      html: message.html,
      replyTo: message.replyTo,
      inReplyTo: message.inReplyTo,
      references: message.references,
      priority: message.priority,
      attachments: message.attachments?.map(a => ({
        filename: a.filename,
        content: Buffer.from(a.content, 'base64'),
        contentType: a.contentType
      }))
    };
  }

  async send(message: OutgoingMessage): Promise<{ messageId: string; accepted: string[]; rejected: string[] }> {
    try {
      const info = await this.transporter().sendMail(this.mailOptions(message));
      return {
        messageId: info.messageId,
        accepted: (info.accepted as Array<string | { address: string }>).map(a => (typeof a === 'string' ? a : a.address)),
        rejected: (info.rejected as Array<string | { address: string }>).map(a => (typeof a === 'string' ? a : a.address))
      };
    } catch (err) {
      throw new Error(
        `SMTP send failed for account "${this.id}" via ${this.config.smtp.host}:${this.config.smtp.port}: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  async saveDraft(message: OutgoingMessage): Promise<{ folder: string; uid?: number }> {
    const raw = await new MailComposer(this.mailOptions(message)).compile().build();
    const drafts = await this.specialFolder('\\Drafts');
    const client = await this.imap();
    const res = await client.append(drafts, raw, ['\\Draft', '\\Seen']);
    return { folder: drafts, uid: res ? res.uid : undefined };
  }

  /** Build a reply (or reply-all) to an existing message. */
  async buildReply(folderInput: string | undefined, uid: number, body: { text?: string; html?: string }, replyAll: boolean): Promise<OutgoingMessage> {
    const folder = await this.resolveFolder(folderInput);
    const { parsed } = await this.fetchParsed(folder, uid);
    const me = this.config.email;
    const replyTo = parsedAddresses(parsed.replyTo);
    const fromAddrs = parsedAddresses(parsed.from);
    const sentByMe = fromAddrs.some(a => a.address?.toLowerCase() === me);
    const primary = sentByMe ? parsedAddresses(parsed.to) : replyTo.length ? replyTo : fromAddrs;
    const to = primary.map(a => a.address).filter((a): a is string => Boolean(a));
    const cc = replyAll
      ? [...parsedAddresses(parsed.to), ...parsedAddresses(parsed.cc)]
          .map(a => a.address)
          .filter((a): a is string => Boolean(a) && a!.toLowerCase() !== me && !to.includes(a!))
      : [];
    const subject = /^re:/i.test(parsed.subject ?? '') ? parsed.subject! : `Re: ${parsed.subject ?? ''}`.trim();
    const refs = parsed.references ? (Array.isArray(parsed.references) ? parsed.references : [parsed.references]) : [];
    const references = parsed.messageId ? [...refs, parsed.messageId] : refs;

    const when = parsed.date ? parsed.date.toUTCString() : 'an earlier date';
    const who = fromAddrs[0]?.name || fromAddrs[0]?.address || 'the sender';
    const quotedText = (parsed.text ?? '').split('\n').map(l => `> ${l}`).join('\n');
    const text = body.text !== undefined ? `${body.text}\n\nOn ${when}, ${who} wrote:\n${quotedText}` : undefined;
    const html =
      body.html !== undefined
        ? `${body.html}<br><br><div>On ${when}, ${who} wrote:</div><blockquote style="margin:0 0 0 .8ex;border-left:1px solid #ccc;padding-left:1ex">${parsed.html || (parsed.textAsHtml ?? '')}</blockquote>`
        : undefined;
    return { to, cc, subject, text, html, inReplyTo: parsed.messageId, references };
  }

  async buildForward(
    folderInput: string | undefined,
    uid: number,
    to: string[],
    note: string | undefined,
    includeAttachments: boolean
  ): Promise<OutgoingMessage> {
    const folder = await this.resolveFolder(folderInput);
    const { parsed } = await this.fetchParsed(folder, uid);
    const header = [
      '---------- Forwarded message ----------',
      `From: ${parsed.from?.text ?? ''}`,
      `Date: ${parsed.date?.toUTCString() ?? ''}`,
      `Subject: ${parsed.subject ?? ''}`,
      `To: ${Array.isArray(parsed.to) ? parsed.to.map(t => t.text).join(', ') : (parsed.to?.text ?? '')}`
    ].join('\n');
    const subject = /^(fwd?|tr):/i.test(parsed.subject ?? '') ? parsed.subject! : `Fwd: ${parsed.subject ?? ''}`.trim();
    return {
      to,
      subject,
      text: `${note ? `${note}\n\n` : ''}${header}\n\n${parsed.text ?? (parsed.html ? htmlToText(parsed.html) : '')}`,
      attachments: includeAttachments
        ? parsed.attachments.map(a => ({ filename: a.filename ?? 'attachment', content: a.content.toString('base64'), contentType: a.contentType }))
        : undefined
    };
  }

  // ------------------------------------------------------------------ health

  async status(): Promise<{ imap: { ok: boolean; error?: string }; smtp: { ok: boolean; error?: string } }> {
    const imap = await this.imap()
      .then(c => c.noop())
      .then(() => ({ ok: true }))
      .catch(err => ({ ok: false, error: err instanceof Error ? err.message : String(err) }));
    const smtp = await this.transporter()
      .verify()
      .then(() => ({ ok: true }))
      .catch(err => ({ ok: false, error: err instanceof Error ? err.message : String(err) }));
    return { imap, smtp };
  }

  async close(): Promise<void> {
    await this.client?.logout().catch(() => undefined);
    this.client = undefined;
    this.smtp?.close();
    this.smtp = undefined;
  }
}

export class AccountRegistry {
  private readonly accounts = new Map<string, ProtonAccount>();

  constructor(configs: AccountConfig[]) {
    for (const c of configs) this.accounts.set(c.id, new ProtonAccount(c));
  }

  get(id: string): ProtonAccount | undefined {
    return this.accounts.get(id);
  }

  all(): ProtonAccount[] {
    return [...this.accounts.values()];
  }

  async closeAll(): Promise<void> {
    await Promise.all(this.all().map(a => a.close()));
  }
}
