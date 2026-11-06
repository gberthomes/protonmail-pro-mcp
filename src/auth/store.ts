/**
 * Small persistent store for the built-in authorization server:
 * signing keys, dynamically registered clients and refresh tokens.
 *
 * A JSON file (mode 0600) in MCP_DATA_DIR keeps users signed in across
 * restarts without any database. Short-lived state (pending authorizations,
 * authorization codes) stays in memory.
 */

import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync, existsSync, chmodSync } from 'node:fs';
import { join } from 'node:path';

import { createLogger } from '../logger.js';
import type { Principal } from './principal.js';

const log = createLogger('store');

export interface RegisteredClient {
  client_id: string;
  client_secret?: string;
  client_id_issued_at: number;
  client_secret_expires_at?: number;
  redirect_uris: string[];
  client_name?: string;
  client_uri?: string;
  logo_uri?: string;
  token_endpoint_auth_method: 'none' | 'client_secret_post' | 'client_secret_basic';
  grant_types: string[];
  response_types: string[];
  application_type?: 'web' | 'native';
  scope?: string;
  /** Set for Client ID Metadata Document clients (client_id is an HTTPS URL). */
  metadata_document?: boolean;
}

export interface RefreshRecord {
  clientId: string;
  principal: Principal;
  scope: string;
  resource: string;
  expiresAt: number;
}

interface State {
  version: 1;
  signingKey: string;
  cookieKey: string;
  clients: Record<string, RegisteredClient>;
  refreshTokens: Record<string, RefreshRecord>;
}

export function sha256(value: string): string {
  return createHash('sha256').update(value).digest('base64url');
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export class AuthStore {
  private state: State;
  private readonly file: string;
  private saveTimer?: NodeJS.Timeout;

  constructor(dataDir: string, signingSecret?: string) {
    mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    this.file = join(dataDir, 'auth-state.json');
    this.state = this.load();
    if (signingSecret) {
      if (Buffer.byteLength(signingSecret) < 32) throw new Error('MCP_SIGNING_SECRET must be at least 32 bytes');
      this.state.signingKey = Buffer.from(signingSecret).toString('base64url');
    }
    this.prune();
  }

  private load(): State {
    if (existsSync(this.file)) {
      try {
        const parsed = JSON.parse(readFileSync(this.file, 'utf8')) as State;
        if (parsed.version === 1 && parsed.signingKey) return parsed;
      } catch (err) {
        log.warn(`Ignoring unreadable ${this.file}`, err);
      }
    }
    const fresh: State = { version: 1, signingKey: randomToken(32), cookieKey: randomToken(32), clients: {}, refreshTokens: {} };
    this.state = fresh;
    this.flush();
    return fresh;
  }

  private flush(): void {
    const tmp = `${this.file}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.state, null, 2), { mode: 0o600 });
    renameSync(tmp, this.file);
    try {
      chmodSync(this.file, 0o600);
    } catch {
      /* best effort */
    }
  }

  private save(): void {
    if (this.saveTimer) return;
    this.saveTimer = setTimeout(() => {
      this.saveTimer = undefined;
      try {
        this.flush();
      } catch (err) {
        log.error('Failed to persist auth state', err);
      }
    }, 50);
    this.saveTimer.unref();
  }

  flushNow(): void {
    if (this.saveTimer) clearTimeout(this.saveTimer);
    this.saveTimer = undefined;
    this.flush();
  }

  private prune(): void {
    const now = Date.now() / 1000;
    let changed = false;
    for (const [k, v] of Object.entries(this.state.refreshTokens)) {
      if (v.expiresAt < now) {
        delete this.state.refreshTokens[k];
        changed = true;
      }
    }
    if (changed) this.save();
  }

  get signingKey(): Uint8Array {
    return Buffer.from(this.state.signingKey, 'base64url');
  }

  get cookieKey(): Buffer {
    return Buffer.from(this.state.cookieKey, 'base64url');
  }

  // clients
  getClient(id: string): RegisteredClient | undefined {
    return this.state.clients[id];
  }

  saveClient(client: RegisteredClient): void {
    this.state.clients[client.client_id] = client;
    this.save();
  }

  // refresh tokens (stored hashed)
  issueRefreshToken(record: RefreshRecord): string {
    const token = randomToken(32);
    this.state.refreshTokens[sha256(token)] = record;
    this.save();
    return token;
  }

  consumeRefreshToken(token: string): RefreshRecord | undefined {
    const key = sha256(token);
    const rec = this.state.refreshTokens[key];
    if (!rec) return undefined;
    delete this.state.refreshTokens[key];
    this.save();
    if (rec.expiresAt < Date.now() / 1000) return undefined;
    return rec;
  }

  peekRefreshToken(token: string): RefreshRecord | undefined {
    return this.state.refreshTokens[sha256(token)];
  }

  revokeRefreshToken(token: string): void {
    const key = sha256(token);
    if (this.state.refreshTokens[key]) {
      delete this.state.refreshTokens[key];
      this.save();
    }
  }
}

/** In-memory map with per-entry expiry. */
export class TtlMap<V> {
  private readonly map = new Map<string, { value: V; expiresAt: number }>();
  private readonly timer: NodeJS.Timeout;

  constructor(private readonly maxEntries = 10_000) {
    this.timer = setInterval(() => this.sweep(), 60_000);
    this.timer.unref();
  }

  set(key: string, value: V, ttlSeconds: number): void {
    if (this.map.size >= this.maxEntries) this.sweep();
    if (this.map.size >= this.maxEntries) {
      const oldest = this.map.keys().next().value;
      if (oldest !== undefined) this.map.delete(oldest);
    }
    this.map.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
  }

  get(key: string): V | undefined {
    const e = this.map.get(key);
    if (!e) return undefined;
    if (e.expiresAt < Date.now()) {
      this.map.delete(key);
      return undefined;
    }
    return e.value;
  }

  take(key: string): V | undefined {
    const v = this.get(key);
    this.map.delete(key);
    return v;
  }

  private sweep(): void {
    const now = Date.now();
    for (const [k, v] of this.map) if (v.expiresAt < now) this.map.delete(k);
  }
}
