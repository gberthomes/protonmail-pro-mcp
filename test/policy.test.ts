import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import type { AccountConfig } from '../src/config.js';
import { AccessPolicy, LOCAL_PRINCIPAL, type Principal } from '../src/auth/principal.js';
import { principalFromClaims } from '../src/auth/oidc.js';

const ep = { host: '127.0.0.1', port: 1, security: 'none' as const, rejectUnauthorized: false };
const acc = (id: string, email: string, users?: string[]): AccountConfig => ({ id, email, username: email, password: 'x', imap: ep, smtp: ep, users });

const accounts = [acc('perso', 'me@proton.me'), acc('shop', 'shop@pm.me', ['group:sales', 'boss@corp.test']), acc('team', 'team@pm.me', ['*@corp.test'])];
const user = (email: string | undefined, groups: string[] = []): Principal => ({ sub: email ?? 'anon', email, groups, via: 'oidc' });

describe('AccessPolicy', () => {
  const policy = new AccessPolicy(accounts, ['me@proton.me']);

  it('gives the local (stdio) user every account', () => {
    assert.equal(policy.accountsFor(LOCAL_PRINCIPAL).length, 3);
  });

  it('applies the global allow-list to accounts without their own rules', () => {
    assert.deepEqual(policy.accountsFor(user('me@proton.me')).map(a => a.id), ['perso']);
  });

  it('matches emails, domains and groups', () => {
    assert.deepEqual(policy.accountsFor(user('boss@corp.test')).map(a => a.id), ['shop', 'team']);
    assert.deepEqual(policy.accountsFor(user('dev@corp.test', ['sales'])).map(a => a.id), ['shop', 'team']);
    assert.deepEqual(policy.accountsFor(user('x@evil.test')).map(a => a.id), []);
    assert.deepEqual(policy.accountsFor(user(undefined, ['sales'])).map(a => a.id), ['shop']);
  });

  it("defaults to the caller's own mailbox when it has one", () => {
    const p = new AccessPolicy([acc('a', 'a@pm.me', ['*']), acc('b', 'b@pm.me', ['*'])], []);
    assert.equal(p.defaultAccountFor(user('b@pm.me'))?.id, 'b');
    assert.equal(p.defaultAccountFor(user('c@pm.me'))?.id, 'a');
  });

  it('flags a configuration that would refuse everybody', () => {
    assert.equal(new AccessPolicy([acc('a', 'a@pm.me')], []).hasNoRules(), true);
  });
});

describe('roles', () => {
  const policy = new AccessPolicy(accounts, { allowedUsers: ['*@corp.test'], adminUsers: ['group:admins'], selfService: true });

  it('separates administrators from self-service users', () => {
    assert.equal(policy.isAdmin(user('dev@corp.test', ['admins'])), true);
    assert.equal(policy.isAdmin(user('dev@corp.test')), false);
    assert.equal(policy.canSelfService(user('dev@corp.test')), true);
    assert.equal(policy.canSelfService(user('x@evil.test')), false);
    assert.equal(policy.isAdmin(LOCAL_PRINCIPAL), true);
  });

  it('lets allowed users sign in before they own any mailbox', () => {
    const empty = new AccessPolicy([], { allowedUsers: ['*@corp.test'], adminUsers: [], selfService: true });
    assert.equal(empty.mayConnect(user('new@corp.test')), true);
    assert.equal(empty.mayConnect(user('x@evil.test')), false);
    const noSelf = new AccessPolicy([], { allowedUsers: ['*@corp.test'], adminUsers: [], selfService: false });
    assert.equal(noSelf.mayConnect(user('new@corp.test')), false);
  });
});

describe('principalFromClaims', () => {
  it('ignores unverified email addresses', () => {
    assert.equal(principalFromClaims({ sub: '1', email: 'me@proton.me', email_verified: false }, 'groups').email, undefined);
    assert.equal(principalFromClaims({ sub: '1', email: 'Me@Proton.me' }, 'groups').email, 'me@proton.me');
  });

  it('reads nested group claims (Keycloak realm roles)', () => {
    const p = principalFromClaims({ sub: '1', realm_access: { roles: ['mail', 'admin'] } }, 'realm_access.roles');
    assert.deepEqual(p.groups, ['mail', 'admin']);
  });
});
