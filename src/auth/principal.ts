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

function matches(pattern: string, p: Principal): boolean {
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

export class AccessPolicy {
  constructor(
    private readonly accounts: AccountConfig[],
    private readonly globalAllowList: string[]
  ) {}

  /** Accounts the principal may use, in configuration order. */
  accountsFor(p: Principal): AccountConfig[] {
    if (p.via === 'local') return this.accounts;
    return this.accounts.filter(acc => {
      const rules = acc.users && acc.users.length > 0 ? acc.users : this.globalAllowList;
      return rules.some(rule => matches(rule, p));
    });
  }

  /** The account used when a tool call does not name one: the caller's own address if configured, else the first allowed. */
  defaultAccountFor(p: Principal): AccountConfig | undefined {
    const allowed = this.accountsFor(p);
    const own = p.email ? allowed.find(a => a.email === p.email!.toLowerCase()) : undefined;
    return own ?? allowed[0];
  }

  /** True when no access rule at all is configured (every remote caller would be refused). */
  hasNoRules(): boolean {
    return this.globalAllowList.length === 0 && this.accounts.every(a => !a.users || a.users.length === 0);
  }
}
