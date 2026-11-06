/**
 * The authenticated caller and the access policy mapping callers to Proton accounts.
 */

import type { AccountConfig } from '../config.js';

export interface Principal {
  /** Stable subject identifier ("local" for stdio, the OIDC `sub`, or "api-key:<name>"). */
  sub: string;
  email?: string;
  name?: string;
  groups: string[];
  via: 'local' | 'oidc' | 'api-key';
}

export const LOCAL_PRINCIPAL: Principal = { sub: 'local', groups: [], via: 'local', name: 'local user' };

export function matchesRule(pattern: string, p: Principal): boolean {
  const pat = pattern.trim().toLowerCase();
  if (!pat) return false;
  if (pat === '*') return true;
  if (pat.startsWith('group:')) return p.groups.some(g => g.toLowerCase() === pat.slice(6));
  if (pat.startsWith('sub:')) return p.sub.toLowerCase() === pat.slice(4);
  const email = p.email?.toLowerCase();
  if (!email) return false;
  if (pat.startsWith('*@')) return email.endsWith(pat.slice(1));
  if (pat.startsWith('@')) return email.endsWith(pat);
  return email === pat;
}

/** The rule that grants a principal its own accounts: its email, or its subject when it has none. */
export function ownRule(p: Principal): string {
  return p.email ?? `sub:${p.sub}`;
}

export interface AccountSource {
  list(): AccountConfig[];
}

export interface PolicyOptions {
  /** Global allow-list for accounts without their own `users`. Also who may add accounts (self-service). */
  allowedUsers: string[];
  /** Who administers every account from the web interface. */
  adminUsers: string[];
  /** Let allowed users add their own Proton accounts in the web interface. */
  selfService: boolean;
}

export class AccessPolicy {
  private readonly source: AccountSource;
  private readonly opts: PolicyOptions;

  constructor(accounts: AccountSource | AccountConfig[], options: PolicyOptions | string[]) {
    this.source = Array.isArray(accounts) ? { list: () => accounts } : accounts;
    this.opts = Array.isArray(options) ? { allowedUsers: options, adminUsers: options, selfService: true } : options;
  }

  /** Accounts the principal may use, in configuration order. */
  accountsFor(p: Principal): AccountConfig[] {
    const all = this.source.list();
    if (p.via === 'local') return all;
    return all.filter(acc => {
      const rules = acc.users && acc.users.length > 0 ? acc.users : this.opts.allowedUsers;
      return rules.some(rule => matchesRule(rule, p));
    });
  }

  /** The account used when a tool call does not name one: the caller's own address if configured, else the first allowed. */
  defaultAccountFor(p: Principal): AccountConfig | undefined {
    const allowed = this.accountsFor(p);
    const own = p.email ? allowed.find(a => a.email === p.email!.toLowerCase()) : undefined;
    return own ?? allowed[0];
  }

  isAdmin(p: Principal): boolean {
    return p.via === 'local' || this.opts.adminUsers.some(rule => matchesRule(rule, p));
  }

  /** May add Proton accounts for themselves in the web interface. */
  canSelfService(p: Principal): boolean {
    return this.isAdmin(p) || (this.opts.selfService && this.opts.allowedUsers.some(rule => matchesRule(rule, p)));
  }

  /** May sign in to the server at all (MCP clients or web interface). */
  mayConnect(p: Principal): boolean {
    return this.accountsFor(p).length > 0 || this.canSelfService(p);
  }

  /** True when no access rule at all is configured (every remote caller would be refused). */
  hasNoRules(): boolean {
    return (
      this.opts.allowedUsers.length === 0 &&
      this.opts.adminUsers.length === 0 &&
      this.source.list().every(a => !a.users || a.users.length === 0)
    );
  }
}
