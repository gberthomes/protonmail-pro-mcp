/**
 * Exposes the Proton accounts signed in to a Bridge instance as MCP mailboxes.
 *
 * Their IMAP/SMTP password is read from Bridge over gRPC and kept in memory
 * only: the Manager never writes it to disk. Who may use each account is
 * recorded when it is added from the web interface (owner + sharing list);
 * accounts added elsewhere (CLI, bridge-gui) follow the global access rules.
 */

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import type { AccountConfig } from '../config.js';
import { createLogger } from '../logger.js';
import type { AccountEntry } from '../mail/directory.js';
import type { BridgeManager } from './manager.js';

const log = createLogger('bridge-accounts');

export interface BridgeAccountMeta {
  owner?: string;
  ownerEmail?: string;
  users?: string[];
  id?: string;
}

/** Ownership and sharing of Bridge accounts (no secret in here). */
export class BridgeAccountMetaStore {
  private readonly file: string;
  private data: Record<string, BridgeAccountMeta> = {};

  constructor(dataDir: string) {
    mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    this.file = join(dataDir, 'bridge-accounts.json');
    if (existsSync(this.file)) this.data = JSON.parse(readFileSync(this.file, 'utf8')) as Record<string, BridgeAccountMeta>;
  }

  private key(instance: string, bridgeUserId: string): string {
    return `${instance}/${bridgeUserId}`;
  }

  get(instance: string, bridgeUserId: string): BridgeAccountMeta | undefined {
    return this.data[this.key(instance, bridgeUserId)];
  }

  set(instance: string, bridgeUserId: string, meta: BridgeAccountMeta): void {
    this.data[this.key(instance, bridgeUserId)] = meta;
    const tmp = `${this.file}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.data, null, 2), { mode: 0o600 });
    renameSync(tmp, this.file);
  }

  delete(instance: string, bridgeUserId: string): void {
    delete this.data[this.key(instance, bridgeUserId)];
    writeFileSync(this.file, JSON.stringify(this.data, null, 2), { mode: 0o600 });
  }
}

function slug(s: string): string {
  return s.toLowerCase().replace(/@.*/, '').replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 30) || 'proton';
}

export class BridgeAccountSource {
  private snapshot: AccountEntry[] = [];
  private timer?: NodeJS.Timeout;
  private refreshing?: Promise<void>;
  private listeners = new Set<() => void>();

  constructor(
    private readonly manager: BridgeManager,
    readonly meta: BridgeAccountMetaStore,
    private readonly takenIds: () => Set<string>,
    private readonly takenEmails: () => Set<string>
  ) {}

  list(): AccountEntry[] {
    return this.snapshot;
  }

  onChange(fn: () => void): void {
    this.listeners.add(fn);
  }

  /**
   * Keep the snapshot fresh every minute, and on account events when `live`
   * (this attaches to Bridge's single event stream: only the server does it).
   */
  async start(live = true): Promise<void> {
    for (const inst of live ? this.manager.instances() : []) {
      await this.manager
        .onEvents(inst.id, e => {
          if (e.kind === 'user' || (e.kind === 'login' && (e.type === 'finished' || e.type === 'alreadyLoggedIn'))) void this.refresh();
        })
        .catch(err => log.warn(`Instance ${inst.id}: no live updates (${err instanceof Error ? err.message : err})`));
    }
    await this.refresh();
    this.timer = setInterval(() => void this.refresh(), 60_000);
    this.timer.unref();
  }

  refresh(): Promise<void> {
    this.refreshing ??= this.doRefresh().finally(() => {
      this.refreshing = undefined;
    });
    return this.refreshing;
  }

  private async doRefresh(): Promise<void> {
    const next: AccountEntry[] = [];
    const taken = this.takenIds();
    const emails = this.takenEmails();
    for (const inst of this.manager.instances()) {
      let accounts: Awaited<ReturnType<BridgeManager['connectedCredentials']>>;
      try {
        accounts = await this.manager.connectedCredentials(inst.id);
      } catch (err) {
        // Keep the previous accounts of this instance: Bridge may be restarting.
        next.push(...this.snapshot.filter(a => a.bridge?.instance === inst.id));
        log.debug(`Instance ${inst.id} unavailable: ${err instanceof Error ? err.message : err}`);
        continue;
      }
      for (const a of accounts) {
        const email = a.credentials.username.toLowerCase();
        if (emails.has(email)) continue; // configured explicitly elsewhere: that one wins
        const meta = this.meta.get(inst.id, a.id) ?? {};
        let id = meta.id ?? slug(email);
        for (let i = 2; taken.has(id) || next.some(n => n.id === id); i++) id = `${slug(email)}-${i}`;
        const endpoint = (e: typeof a.credentials.imap) => ({ host: e.host, port: e.port, security: e.security, rejectUnauthorized: false });
        const config: AccountConfig = {
          id,
          email,
          displayName: undefined,
          username: a.credentials.username,
          password: a.credentials.password,
          imap: endpoint(a.credentials.imap),
          smtp: endpoint(a.credentials.smtp),
          users: meta.users,
          provider: 'proton-bridge',
          saveSent: false
        };
        next.push({ ...config, source: 'bridge', owner: meta.owner, ownerEmail: meta.ownerEmail, bridge: { instance: inst.id, userId: a.id, addresses: a.addresses } });
      }
    }
    const changed = JSON.stringify(next.map(n => [n.id, n.email, n.password, n.users])) !== JSON.stringify(this.snapshot.map(n => [n.id, n.email, n.password, n.users]));
    this.snapshot = next;
    if (changed) for (const l of this.listeners) l();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
  }
}
