/**
 * Account directory: accounts from the configuration (env / JSON file, read-only)
 * plus accounts managed from the web interface, persisted in MCP_DATA_DIR with
 * their Bridge passwords encrypted (AES-256-GCM).
 *
 * The file is re-read when another process changes it, so an account added in
 * the web interface is also available to a stdio server sharing the data dir.
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import type { AccountConfig, Endpoint } from '../config.js';
import { createLogger } from '../logger.js';

const log = createLogger('accounts');

export type AccountSource = 'config' | 'ui';

export interface AccountEntry extends AccountConfig {
  source: AccountSource;
  /** Subject of the user who created a UI-managed account. */
  owner?: string;
  ownerEmail?: string;
  createdAt?: string;
  updatedAt?: string;
}

interface StoredAccount {
  id: string;
  email: string;
  displayName?: string;
  username: string;
  password: string; // encrypted: iv.tag.ciphertext (base64url)
  imap: Endpoint;
  smtp: Endpoint;
  users: string[];
  owner: string;
  ownerEmail?: string;
  createdAt: string;
  updatedAt: string;
}

interface StoredFile {
  version: 1;
  accounts: StoredAccount[];
}

export interface AccountInput {
  id: string;
  email: string;
  displayName?: string;
  username: string;
  /** Plain password; when omitted on update the stored one is kept. */
  password?: string;
  imap: Endpoint;
  smtp: Endpoint;
  users: string[];
}

export const ACCOUNT_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,39}$/;

export class AccountDirectory {
  private readonly file: string;
  private readonly key: Buffer;
  private managed: StoredAccount[] = [];
  private mtime = 0;
  private lastCheck = 0;
  private listeners = new Set<() => void>();

  constructor(
    private readonly staticAccounts: AccountConfig[],
    dataDir: string,
    encryptionKey?: string
  ) {
    mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    this.file = join(dataDir, 'accounts.json');
    this.key = this.loadKey(dataDir, encryptionKey);
    this.reload(true);
  }

  private loadKey(dataDir: string, configured?: string): Buffer {
    if (configured) {
      const raw = /^[A-Za-z0-9_-]{43}$/.test(configured) ? Buffer.from(configured, 'base64url') : Buffer.from(configured);
      if (raw.length < 32) throw new Error('MCP_ENCRYPTION_KEY must be at least 32 bytes');
      return raw.subarray(0, 32);
    }
    const keyFile = join(dataDir, 'encryption.key');
    if (existsSync(keyFile)) return Buffer.from(readFileSync(keyFile, 'utf8').trim(), 'base64url');
    const key = randomBytes(32);
    writeFileSync(keyFile, key.toString('base64url'), { mode: 0o600 });
    return key;
  }

  private encrypt(plain: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    const data = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
    return [iv, cipher.getAuthTag(), data].map(b => b.toString('base64url')).join('.');
  }

  private decrypt(sealed: string): string {
    const [iv, tag, data] = sealed.split('.').map(p => Buffer.from(p, 'base64url'));
    if (!iv || !tag || !data) throw new Error('corrupted secret');
    const decipher = createDecipheriv('aes-256-gcm', this.key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
  }

  private reload(force = false): void {
    const now = Date.now();
    if (!force && now - this.lastCheck < 2000) return;
    this.lastCheck = now;
    if (!existsSync(this.file)) {
      this.managed = [];
      return;
    }
    const mtime = statSync(this.file).mtimeMs;
    if (!force && mtime === this.mtime) return;
    try {
      const parsed = JSON.parse(readFileSync(this.file, 'utf8')) as StoredFile;
      this.managed = parsed.accounts ?? [];
      this.mtime = mtime;
      if (!force) this.emit();
    } catch (err) {
      log.error(`Cannot read ${this.file}`, err);
    }
  }

  private persist(): void {
    const tmp = `${this.file}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify({ version: 1, accounts: this.managed } satisfies StoredFile, null, 2), { mode: 0o600 });
    renameSync(tmp, this.file);
    try {
      chmodSync(this.file, 0o600);
    } catch {
      /* best effort */
    }
    this.mtime = statSync(this.file).mtimeMs;
    this.emit();
  }

  private emit(): void {
    for (const l of this.listeners) l();
  }

  onChange(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private toEntry(s: StoredAccount): AccountEntry | undefined {
    try {
      return {
        id: s.id,
        email: s.email,
        displayName: s.displayName,
        username: s.username,
        password: this.decrypt(s.password),
        imap: s.imap,
        smtp: s.smtp,
        users: s.users,
        source: 'ui',
        owner: s.owner,
        ownerEmail: s.ownerEmail,
        createdAt: s.createdAt,
        updatedAt: s.updatedAt
      };
    } catch (err) {
      log.error(`Cannot decrypt the password of account "${s.id}" (was MCP_ENCRYPTION_KEY or encryption.key changed?)`, err instanceof Error ? err.message : err);
      return undefined;
    }
  }

  list(): AccountEntry[] {
    this.reload();
    const fromConfig: AccountEntry[] = this.staticAccounts.map(a => ({ ...a, source: 'config' }));
    const taken = new Set(fromConfig.map(a => a.id));
    const fromUi = this.managed
      .filter(a => !taken.has(a.id))
      .map(a => this.toEntry(a))
      .filter((a): a is AccountEntry => Boolean(a));
    return [...fromConfig, ...fromUi];
  }

  get(id: string): AccountEntry | undefined {
    return this.list().find(a => a.id === id);
  }

  isTaken(id: string, email: string, exceptId?: string): string | undefined {
    for (const a of this.list()) {
      if (a.id === exceptId) continue;
      if (a.id === id) return `The id "${id}" is already used`;
      if (a.email === email) return `${email} is already configured`;
    }
    return undefined;
  }

  create(input: AccountInput, owner: { sub: string; email?: string }): AccountEntry {
    if (!input.password) throw new Error('The Bridge password is required');
    const now = new Date().toISOString();
    this.reload(true);
    this.managed.push({
      id: input.id,
      email: input.email,
      displayName: input.displayName,
      username: input.username,
      password: this.encrypt(input.password),
      imap: input.imap,
      smtp: input.smtp,
      users: input.users,
      owner: owner.sub,
      ownerEmail: owner.email,
      createdAt: now,
      updatedAt: now
    });
    this.persist();
    log.info(`Account "${input.id}" added by ${owner.email ?? owner.sub}`);
    return this.get(input.id)!;
  }

  update(id: string, input: AccountInput): AccountEntry {
    this.reload(true);
    const current = this.managed.find(a => a.id === id);
    if (!current) throw new Error(`Account "${id}" cannot be edited here`);
    Object.assign(current, {
      id: input.id,
      email: input.email,
      displayName: input.displayName,
      username: input.username,
      password: input.password ? this.encrypt(input.password) : current.password,
      imap: input.imap,
      smtp: input.smtp,
      users: input.users,
      updatedAt: new Date().toISOString()
    });
    this.persist();
    log.info(`Account "${id}" updated`);
    return this.get(input.id)!;
  }

  remove(id: string): void {
    this.reload(true);
    const before = this.managed.length;
    this.managed = this.managed.filter(a => a.id !== id);
    if (this.managed.length === before) throw new Error(`Account "${id}" cannot be deleted here`);
    this.persist();
    log.info(`Account "${id}" deleted`);
  }
}
