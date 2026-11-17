/**
 * Web interface API of the Bridge Manager + MCP integration, against the
 * scripted Bridge: sign a Proton account in over HTTP, see it appear as an MCP
 * mailbox, manage it, and check no secret leaks into responses.
 */

import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

import { AccessPolicy } from '../src/auth/principal.js';
import { BridgeAccountMetaStore, BridgeAccountSource } from '../src/bridge-manager/accounts-source.js';
import { BridgeManager } from '../src/bridge-manager/manager.js';
import { loadConfig } from '../src/config.js';
import { startHttp, type RunningHttpServer } from '../src/http.js';
import { AccountRegistry } from '../src/mail/account.js';
import { AccountDirectory } from '../src/mail/directory.js';
import { FakeBridge } from './helpers/fake-bridge.js';

describe('Bridge Manager web API', () => {
  let bridge: FakeBridge;
  let manager: BridgeManager;
  let app: RunningHttpServer;
  let registry: AccountRegistry;
  let base = '';
  let dataDir = '';

  before(async () => {
    bridge = new FakeBridge();
    await bridge.start();
    dataDir = mkdtempSync(join(tmpdir(), 'bm-api-'));
    for (const k of Object.keys(process.env)) if (k.startsWith('PROTONMAIL_') || k.startsWith('OIDC_') || k.startsWith('MCP_') || k.startsWith('MAIL_OAUTH')) delete process.env[k];
    Object.assign(process.env, { MCP_DATA_DIR: dataDir, HOST: '127.0.0.1' });
    const config = loadConfig(['--http']);
    const probe = createServer();
    const port = await new Promise<number>(r => probe.listen(0, '127.0.0.1', () => r((probe.address() as AddressInfo).port)));
    probe.close();
    config.http.port = port;
    config.http.publicUrl = new URL(`http://127.0.0.1:${port}`);
    base = config.http.publicUrl.origin;

    const directory = new AccountDirectory(config.accounts, config.dataDir);
    manager = new BridgeManager([{ id: 'main', settingsDir: bridge.settingsDir }], { auth: { stepTimeoutMs: 500 } });
    const source = new BridgeAccountSource(manager, new BridgeAccountMetaStore(dataDir), () => directory.ownIds(), () => directory.ownEmails());
    directory.addSource(source);
    await source.start(true);
    registry = new AccountRegistry(directory);
    const policy = new AccessPolicy(directory, { allowedUsers: [], adminUsers: [], selfService: true });
    app = await startHttp(config, { registry, policy, directory, bridgeManager: manager, bridgeSource: source });
  });

  after(async () => {
    await app?.close();
    await registry?.closeAll();
    await manager?.close();
    await bridge?.stop();
    rmSync(dataDir, { recursive: true, force: true });
  });

  const call = async (path: string, method = 'GET', body?: unknown, csrf = true) => {
    const res = await fetch(`${base}/admin/api/bridge${path}`, {
      method,
      headers: { ...(csrf ? { 'x-pmcp': '1' } : {}), ...(body ? { 'content-type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined
    });
    const text = await res.text();
    return { status: res.status, text, data: text ? (JSON.parse(text) as Record<string, any>) : null };
  };

  it('reports the instance and an empty Bridge', async () => {
    const r = await call('/instances');
    assert.equal(r.data!.instances[0].running, true);
    assert.equal(r.data!.instances[0].version, '3.27.2');
    assert.deepEqual((await call('/instances/main/accounts')).data!.accounts, []);
  });

  it('signs a Proton account in step by step and exposes it to the MCP', async () => {
    assert.equal((await call('/auth-sessions', 'POST', { username: 'both@pm.me', password: 'proton-secret-pw' }, false)).status, 403, 'CSRF header required');

    let r = await call('/auth-sessions', 'POST', { username: 'both@pm.me', password: 'proton-secret-pw' });
    assert.equal(r.status, 201);
    assert.equal(r.data!.state, 'TOTP_REQUIRED');
    const sid = r.data!.id as string;
    r = await call(`/auth-sessions/${sid}/totp`, 'POST', { code: '123456' });
    assert.equal(r.data!.state, 'MAILBOX_PASSWORD_REQUIRED');
    r = await call(`/auth-sessions/${sid}/mailbox-password`, 'POST', { password: 'mailbox-pw' });
    assert.equal(r.data!.state, 'CONNECTED');
    assert.equal(r.data!.account.username, 'both@pm.me');
    assert.ok(!r.text.includes('proton-secret-pw') && !r.text.includes('mailbox-pw'));

    const accounts = await call('/instances/main/accounts');
    assert.equal(accounts.data!.accounts[0].mailboxId, 'both');
    assert.ok(!accounts.text.includes('bridge-generated'), 'the Bridge password is never sent to the browser');

    const client = new Client({ name: 'bm-api', version: '1.0.0' });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`)));
    const res = (await client.callTool({ name: 'list_accounts', arguments: {} })) as { content: Array<{ text: string }> };
    const listed = JSON.parse(res.content[0]!.text) as { accounts: Array<{ id: string; email: string }> };
    assert.deepEqual(listed.accounts.map(a => a.email), ['both@pm.me']);
    await client.close();

    for (const f of readdirSync(dataDir)) assert.ok(!readFileSync(join(dataDir, f), 'utf8').includes('bridge-generated'), `no Bridge password on disk (${f})`);
  });

  it('replaces a sign-in the same person left unfinished, and scopes sessions', async () => {
    const first = await call('/auth-sessions', 'POST', { username: 'totp@pm.me', password: 'p' });
    assert.equal(first.data!.state, 'TOTP_REQUIRED');
    const second = await call('/auth-sessions', 'POST', { username: 'twopw@pm.me', password: 'p' });
    assert.equal(second.status, 201);
    assert.equal((await call(`/auth-sessions/${first.data!.id}`)).data!.state, 'CANCELLED');
    assert.equal((await call('/auth-sessions/not-a-session', 'GET')).status, 404);
    assert.equal((await call(`/auth-sessions/${second.data!.id}/cancel`, 'POST', {})).data!.state, 'CANCELLED');
  });

  it('signs out and removes accounts with an explicit confirmation', async () => {
    assert.equal((await call('/instances/main/accounts/both@pm.me/logout', 'POST', {})).status, 204);
    assert.equal((await call('/instances/main/accounts')).data!.accounts[0].state, 'SIGNED_OUT');
    assert.equal((await call('/instances/main/accounts/both@pm.me', 'DELETE', { confirm: 'nope' })).status, 400);
    assert.equal((await call('/instances/main/accounts/both@pm.me', 'DELETE', { confirm: 'both@pm.me' })).status, 204);
    assert.deepEqual((await call('/instances/main/accounts')).data!.accounts, []);
  });
});

