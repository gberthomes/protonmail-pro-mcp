/**
 * End-to-end tests: real IMAP (hoodiecrow, STARTTLS + self-signed cert, like
 * Proton Bridge), real SMTP capture, a mock OIDC provider, the full OAuth flow
 * through the built-in authorization server, and the official MCP v2 client
 * over Streamable HTTP (2026-07-28 and 2025 eras), legacy SSE and stdio.
 */

import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';

import express from 'express';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { SMTPServer } from 'smtp-server';
import { simpleParser } from 'mailparser';
// @ts-expect-error untyped test dependency
import hoodiecrow from 'hoodiecrow-imap';
import { Client, SSEClientTransport, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

import { loadConfig } from '../src/config.js';
import { startHttp, type RunningHttpServer } from '../src/http.js';
import { AccessPolicy } from '../src/auth/principal.js';
import { AccountRegistry } from '../src/mail/account.js';
import { AccountDirectory } from '../src/mail/directory.js';
import { MailOAuth } from '../src/mail/oauth.js';

// Works for node:http servers and for test servers that wrap one in `.server`.
const listen = (srv: Server | { listen: Server['listen']; server: Server }, host = '127.0.0.1') =>
  new Promise<number>(resolve => {
    const inner = 'address' in srv ? srv : srv.server;
    srv.listen(0, host, () => resolve((inner.address() as AddressInfo).port));
  });

function imapServer(user: string, pass: string, subjectPrefix: string) {
  const msg = (i: number, extra = '') =>
    `From: Sender ${i} <sender${i}@example.com>\r\nTo: ${user}@example.test\r\nSubject: ${subjectPrefix} message ${i}\r\nMessage-ID: <m${i}.${subjectPrefix}@example.com>\r\nDate: Fri, 0${i} Oct 2026 10:00:00 +0000\r\n${extra}\r\nBody of message ${i} for ${subjectPrefix}.`;
  return hoodiecrow({
    plugins: ['STARTTLS', 'ID', 'ENABLE', 'UIDPLUS', 'MOVE', 'SPECIAL-USE', 'NAMESPACE', 'UNSELECT', 'LITERALPLUS'],
    users: { [user]: { password: pass } },
    storage: {
      INBOX: {
        messages: [
          { raw: msg(1), flags: ['\\Seen'] },
          { raw: msg(2) },
          {
            raw:
              `From: Carol <carol@example.com>\r\nTo: ${user}@example.test\r\nCc: dave@example.com\r\nSubject: ${subjectPrefix} with attachment\r\nMessage-ID: <att.${subjectPrefix}@example.com>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="b1"\r\n\r\n` +
              `--b1\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n--b1\r\nContent-Type: text/plain; name="notes.txt"\r\nContent-Disposition: attachment; filename="notes.txt"\r\nContent-Transfer-Encoding: base64\r\n\r\n${Buffer.from('hello attachment').toString('base64')}\r\n--b1--\r\n`
          }
        ]
      },
      '': {
        separator: '/',
        folders: {
          Sent: { 'special-use': '\\Sent' },
          Drafts: { 'special-use': '\\Drafts' },
          Trash: { 'special-use': '\\Trash' },
          Spam: { 'special-use': '\\Junk' },
          Archive: { 'special-use': '\\Archive' },
          Folders: { flags: ['\\Noselect'], folders: {} },
          Labels: { flags: ['\\Noselect'], folders: {} }
        }
      }
    }
  });
}

// ------------------------------------------------------------------ mock OIDC provider

async function mockIdp(user: { sub: string; email: string; groups: string[] }) {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
  const codes = new Map<string, { nonce: string; challenge: string; redirect: string }>();
  const app = express();
  app.use(express.urlencoded({ extended: false }));
  let base = '';
  const state = { tokenRequests: 0, lastAuthHeader: '' };
  app.get('/.well-known/openid-configuration', (_req, res) => {
    res.json({
      issuer: base,
      authorization_endpoint: `${base}/auth`,
      token_endpoint: `${base}/token`,
      jwks_uri: `${base}/jwks`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256']
    });
  });
  app.get('/jwks', (_req, res) => {
    res.json({ keys: [jwk] });
  });
  app.get('/auth', (req, res) => {
    const q = req.query as Record<string, string>;
    assert.equal(q.client_id, 'upstream-client');
    assert.equal(q.code_challenge_method, 'S256');
    const code = randomBytes(8).toString('hex');
    codes.set(code, { nonce: q.nonce!, challenge: q.code_challenge!, redirect: q.redirect_uri! });
    const url = new URL(q.redirect_uri!);
    url.searchParams.set('code', code);
    url.searchParams.set('state', q.state!);
    url.searchParams.set('iss', base);
    res.redirect(url.href);
  });
  app.post('/token', async (req, res) => {
    state.tokenRequests++;
    state.lastAuthHeader = req.headers.authorization ?? '';
    const entry = codes.get(req.body.code);
    const verifier = String(req.body.code_verifier);
    if (!entry || createHash('sha256').update(verifier).digest('base64url') !== entry.challenge || req.body.redirect_uri !== entry.redirect) {
      res.status(400).json({ error: 'invalid_grant' });
      return;
    }
    const idToken = await new SignJWT({ email: user.email, email_verified: true, groups: user.groups, nonce: entry.nonce, name: 'Alice' })
      .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
      .setIssuer(base)
      .setAudience('upstream-client')
      .setSubject(user.sub)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
    res.json({ access_token: 'upstream-at', token_type: 'Bearer', id_token: idToken });
  });
  // Mailbox OAuth (stands in for Google): authorize → code → tokens with an ID token
  app.get('/mail-auth', (req, res) => {
    const q = req.query as Record<string, string>;
    assert.equal(q.client_id, 'mail-client');
    assert.match(q.scope!, /mail\.google\.com/);
    codes.set('mail-code', { nonce: '', challenge: q.code_challenge!, redirect: q.redirect_uri! });
    res.redirect(`${q.redirect_uri}?code=mail-code&state=${encodeURIComponent(q.state!)}`);
  });
  app.post('/mail-token', async (req, res) => {
    const entry = codes.get(req.body.code);
    if (!entry || createHash('sha256').update(String(req.body.code_verifier)).digest('base64url') !== entry.challenge) {
      res.status(400).json({ error: 'invalid_grant' });
      return;
    }
    const idToken = await new SignJWT({ email: 'boss@gmail.com', name: 'The Boss' }).setProtectedHeader({ alg: 'RS256' }).setSubject('g1').sign(privateKey);
    res.json({ access_token: 'g-access', refresh_token: 'g-refresh-secret', expires_in: 3600, id_token: idToken });
  });
  const server = createServer(app);
  const port = await listen(server);
  base = `http://127.0.0.1:${port}`;
  return { base, server, state };
}

// ------------------------------------------------------------------ browser-ish OAuth helper

async function oauthLogin(mcpBase: string) {
  const cookies = new Map<string, string>();
  const jar = (res: Response) => {
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(';');
      const i = pair!.indexOf('=');
      cookies.set(pair!.slice(0, i), pair!.slice(i + 1));
    }
  };
  const cookieHeader = () => [...cookies].map(([k, v]) => `${k}=${v}`).join('; ');

  // 1. discovery as a client would do it
  const unauth = await fetch(`${mcpBase}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' }, body: '{}' });
  assert.equal(unauth.status, 401);
  const challenge = unauth.headers.get('www-authenticate') ?? '';
  const prmUrl = /resource_metadata="([^"]+)"/.exec(challenge)?.[1];
  assert.ok(prmUrl, `resource_metadata in challenge: ${challenge}`);
  const prm = (await (await fetch(prmUrl!)).json()) as { resource: string; authorization_servers: string[] };
  assert.equal(prm.resource, `${mcpBase}/mcp`);
  const asMeta = (await (await fetch(`${prm.authorization_servers[0]}/.well-known/oauth-authorization-server`)).json()) as Record<string, string>;
  assert.equal(asMeta.client_id_metadata_document_supported, true);

  // 2. dynamic registration
  const redirectUri = 'http://127.0.0.1:65000/callback';
  const reg = (await (
    await fetch(asMeta.registration_endpoint!, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ redirect_uris: [redirectUri], client_name: 'E2E Client', token_endpoint_auth_method: 'none', application_type: 'native' })
    })
  ).json()) as { client_id: string };
  assert.ok(reg.client_id);

  // 3. authorize → consent page
  const verifier = randomBytes(32).toString('base64url');
  const authz = new URL(asMeta.authorization_endpoint!);
  authz.search = new URLSearchParams({
    response_type: 'code',
    client_id: reg.client_id,
    redirect_uri: redirectUri.replace('65000', '65001'), // loopback: any port
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    state: 'xyz',
    scope: 'mail',
    resource: `${mcpBase}/mcp`
  }).toString();
  const consent = await fetch(authz, { redirect: 'manual' });
  jar(consent);
  assert.equal(consent.status, 200);
  const html = await consent.text();
  assert.match(html, /E2E Client/);
  const txn = /name="txn" value="([^"]+)"/.exec(html)![1]!;
  const csrf = /name="csrf" value="([^"]+)"/.exec(html)![1]!;

  // 3b. a consent POST without the browser cookie must fail (confused-deputy protection)
  const forged = await fetch(`${mcpBase}/authorize/consent`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ txn, csrf, decision: 'approve' })
  });
  assert.equal(forged.status, 400);

  // 4. approve → IdP → callback → client redirect
  const approved = await fetch(`${mcpBase}/authorize/consent`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader(), origin: mcpBase },
    body: new URLSearchParams({ txn, csrf, decision: 'approve' })
  });
  jar(approved);
  assert.equal(approved.status, 302);
  const idpRedirect = await fetch(approved.headers.get('location')!, { redirect: 'manual' });
  assert.equal(idpRedirect.status, 302);
  const callback = await fetch(idpRedirect.headers.get('location')!, { redirect: 'manual', headers: { cookie: cookieHeader() } });
  assert.equal(callback.status, 302, await callback.clone().text());
  const final = new URL(callback.headers.get('location')!);
  assert.equal(final.port, '65001');
  assert.equal(final.searchParams.get('state'), 'xyz');
  assert.equal(final.searchParams.get('iss'), mcpBase);
  const code = final.searchParams.get('code')!;
  assert.ok(code, final.href);

  // 5. token exchange
  const tokenRes = await fetch(asMeta.token_endpoint!, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, code_verifier: verifier, client_id: reg.client_id, redirect_uri: redirectUri.replace('65000', '65001'), resource: `${mcpBase}/mcp` })
  });
  const tokens = (await tokenRes.json()) as { access_token: string; refresh_token: string; expires_in: number };
  assert.equal(tokenRes.status, 200, JSON.stringify(tokens));

  // code is single use
  const replay = await fetch(asMeta.token_endpoint!, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, code_verifier: verifier, client_id: reg.client_id })
  });
  assert.equal(replay.status, 400);

  // second authorization skips the consent page (remembered for this browser + client)
  const again = await fetch(authz, { redirect: 'manual', headers: { cookie: cookieHeader() } });
  assert.equal(again.status, 302);
  assert.ok(again.headers.get('location')!.startsWith('http://127.0.0.1'));

  return { ...tokens, clientId: reg.client_id, tokenEndpoint: asMeta.token_endpoint! };
}

function text(result: unknown): string {
  const r = result as { content: Array<{ type: string; text?: string }>; isError?: boolean };
  return r.content.map(c => c.text ?? '').join('\n');
}

function json<T = Record<string, unknown>>(result: unknown): T {
  const t = text(result);
  return JSON.parse(t.slice(t.indexOf('{'))) as T;
}

// ------------------------------------------------------------------ suite

describe('protonmail-pro-mcp end to end', () => {
  const sent: Array<{ from: string; to: string[]; raw: string }> = [];
  let imapA: { listen: Server['listen']; server: Server; close: () => void }, imapB: typeof imapA, smtp: SMTPServer, idp: Awaited<ReturnType<typeof mockIdp>>;
  let app: RunningHttpServer;
  let base: string;
  let registry: AccountRegistry;
  let dataDir: string;
  let tokens: Awaited<ReturnType<typeof oauthLogin>>;
  let imapPortA = 0, imapPortB = 0, smtpPort = 0;

  before(async () => {
    imapA = imapServer('alice', 'alice-bridge-pw', 'Alice');
    imapB = imapServer('bob', 'bob-bridge-pw', 'Bob');
    imapPortA = await listen(imapA);
    imapPortB = await listen(imapB);
    smtp = new SMTPServer({
      authOptional: false,
      allowInsecureAuth: true,
      disabledCommands: ['STARTTLS'],
      onAuth(auth, _s, cb) {
        if ((auth.username === 'alice' && auth.password === 'alice-bridge-pw') || (auth.username === 'bob' && auth.password === 'bob-bridge-pw')) cb(null, { user: auth.username });
        else cb(new Error('bad auth'));
      },
      onData(stream, session, cb) {
        const chunks: Buffer[] = [];
        stream.on('data', c => chunks.push(c));
        stream.on('end', () => {
          sent.push({ from: session.envelope.mailFrom ? session.envelope.mailFrom.address : '', to: session.envelope.rcptTo.map(r => r.address), raw: Buffer.concat(chunks).toString() });
          cb();
        });
      }
    });
    smtpPort = await new Promise<number>(resolve => smtp.listen(0, '127.0.0.1', () => resolve((smtp.server.address() as AddressInfo).port)));
    idp = await mockIdp({ sub: 'user-alice', email: 'alice@corp.test', groups: ['staff'] });

    dataDir = mkdtempSync(join(tmpdir(), 'pmcp-'));
    const env: Record<string, string> = {
      MCP_TRANSPORT: 'http',
      HOST: '127.0.0.1',
      PORT: '0',
      MCP_DATA_DIR: dataDir,
      OIDC_ISSUER: idp.base,
      OIDC_CLIENT_ID: 'upstream-client',
      OIDC_CLIENT_SECRET: 'upstream-secret',
      MCP_ALLOWED_USERS: '*@corp.test',
      MCP_ADMIN_USERS: 'group:admins',
      MAIL_OAUTH_GOOGLE_CLIENT_ID: 'mail-client',
      MAIL_OAUTH_GOOGLE_CLIENT_SECRET: 'mail-secret',
      MAIL_OAUTH_GOOGLE_AUTHORIZE_URL: `${idp.base}/mail-auth`,
      MAIL_OAUTH_GOOGLE_TOKEN_URL: `${idp.base}/mail-token`,
      // Bridge defaults used for accounts added in the web interface
      PROTONMAIL_IMAP_PORT: String(imapPortB),
      PROTONMAIL_SMTP_PORT: String(smtpPort),
      PROTONMAIL_SMTP_SECURITY: 'none',
      MCP_API_KEYS: `${'k'.repeat(32)}=robot@corp.test`,
      PROTONMAIL_ACCOUNTS: JSON.stringify([
        { id: 'alice', email: 'alice@alice.test', username: 'alice', password: 'alice-bridge-pw', displayName: 'Alice A', imap: { port: imapPortA }, smtp: { port: smtpPort, security: 'none' } },
        { id: 'bob', email: 'bob@bob.test', username: 'bob', password: 'bob-bridge-pw', imap: { port: imapPortB }, smtp: { port: smtpPort, security: 'none' }, users: ['group:admins'] }
      ])
    };
    Object.assign(process.env, env);
  });

  after(async () => {
    await app?.close();
    await registry?.closeAll();
    imapA?.close();
    imapB?.close();
    smtp?.close(() => undefined);
    idp?.server.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it('starts the HTTP server with OIDC', async () => {
    const config = loadConfig([]);
    // PORT=0 → discover the real port, then rebuild public URL for this run
    const probe = createServer();
    const port = await listen(probe);
    probe.close();
    config.http.port = port;
    config.http.publicUrl = new URL(`http://127.0.0.1:${port}`);
    config.http.allowedHosts.push('127.0.0.1');
    base = config.http.publicUrl.origin;
    const directory = new AccountDirectory(config.accounts, config.dataDir, config.auth.encryptionKey);
    const oauth = new MailOAuth(config.mailOAuth);
    registry = new AccountRegistry(directory, oauth);
    const policy = new AccessPolicy(directory, { allowedUsers: config.auth.allowedUsers, adminUsers: config.auth.adminUsers, selfService: config.auth.selfService });
    app = await startHttp(config, { registry, policy, directory, oauth });
    const health = await (await fetch(`${base}/healthz`)).json();
    assert.equal((health as { status: string }).status, 'ok');
  });

  it('rejects foreign Origin headers (DNS rebinding protection)', async () => {
    const res = await fetch(`${base}/mcp`, { method: 'POST', headers: { origin: 'https://evil.example', 'content-type': 'application/json' }, body: '{}' });
    assert.equal(res.status, 403);
  });

  it('completes the OAuth/OIDC flow (DCR, consent, PKCE, iss, single-use code)', async () => {
    tokens = await oauthLogin(base);
    assert.ok(tokens.access_token.split('.').length === 3);
    assert.match(idp.state.lastAuthHeader, /^Basic /);
  });

  it('rotates refresh tokens', async () => {
    const res = await fetch(tokens.tokenEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: tokens.clientId })
    });
    const next = (await res.json()) as { access_token: string; refresh_token: string };
    assert.equal(res.status, 200);
    const reuse = await fetch(tokens.tokenEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: tokens.clientId })
    });
    assert.equal(reuse.status, 400);
    tokens = { ...tokens, ...next };
  });

  const authedFetch = (token: string) => (url: string | URL, init?: RequestInit) =>
    fetch(url, { ...init, headers: { ...Object.fromEntries(new Headers(init?.headers).entries()), authorization: `Bearer ${token}` } });

  it('serves the 2026-07-28 stateless revision with per-user accounts', async () => {
    const client = new Client({ name: 'e2e-modern', version: '1.0.0' }, { versionNegotiation: { mode: { pin: '2026-07-28' } } });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { fetch: authedFetch(tokens.access_token) }));
    assert.equal(client.getProtocolEra(), 'modern');

    const { tools } = await client.listTools();
    const names = tools.map(t => t.name);
    for (const n of ['list_accounts', 'list_emails', 'get_email', 'search_emails', 'send_email', 'reply_email', 'delete_emails', 'get_attachment', 'create_draft']) {
      assert.ok(names.includes(n), `missing tool ${n}`);
    }
    const listEmails = tools.find(t => t.name === 'list_emails')!;
    assert.equal((listEmails.inputSchema.properties as Record<string, Record<string, unknown>>).account!['x-mcp-header'], 'Account');

    const accounts = json(await client.callTool({ name: 'list_accounts', arguments: {} }));
    assert.deepEqual((accounts.accounts as Array<{ id: string }>).map(a => a.id), ['alice'], 'alice@corp.test must only see the "alice" mailbox');

    const forbidden = await client.callTool({ name: 'list_emails', arguments: { account: 'bob' } });
    assert.equal(forbidden.isError, true);

    const list = json<{ total: number; messages: Array<{ uid: number; subject: string; seen: boolean; hasAttachments: boolean }> }>(
      await client.callTool({ name: 'list_emails', arguments: { limit: 10 } })
    );
    assert.equal(list.total, 3);
    assert.equal(list.messages[0]!.subject, 'Alice with attachment');
    assert.equal(list.messages[0]!.hasAttachments, true);

    const unread = json<{ total: number }>(await client.callTool({ name: 'list_emails', arguments: { unreadOnly: true } }));
    assert.equal(unread.total, 2);

    const found = json<{ messages: Array<{ uid: number }> }>(await client.callTool({ name: 'search_emails', arguments: { from: 'carol' } }));
    assert.equal(found.messages.length, 1);
    const attUid = found.messages[0]!.uid;

    const mail = json<{ text: string; attachments: Array<{ filename: string }>; cc: Array<{ address: string }> }>(
      await client.callTool({ name: 'get_email', arguments: { uid: attUid } })
    );
    assert.match(mail.text, /See attached/);
    assert.equal(mail.attachments[0]!.filename, 'notes.txt');

    const att = (await client.callTool({ name: 'get_attachment', arguments: { uid: attUid, index: 0 } })) as {
      content: Array<{ type: string; resource?: { blob: string } }>;
    };
    assert.equal(Buffer.from(att.content[1]!.resource!.blob, 'base64').toString(), 'hello attachment');

    const folders = json<{ folders: Array<{ path: string; specialUse?: string }> }>(await client.callTool({ name: 'list_folders', arguments: {} }));
    assert.ok(folders.folders.some(f => f.specialUse === '\\Trash'));

    await client.close();
  });

  it('organizes and sends mail (2025-era client over the same endpoint)', async () => {
    const client = new Client({ name: 'e2e-legacy', version: '1.0.0' });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { fetch: authedFetch(tokens.access_token) }));
    assert.equal(client.getProtocolEra(), 'legacy');

    const list = json<{ messages: Array<{ uid: number; subject: string; seen: boolean }> }>(await client.callTool({ name: 'list_emails', arguments: { account: 'alice@alice.test' } }));
    const target = list.messages.find(m => m.subject === 'Alice message 2')!;
    assert.equal(target.seen, false);

    await client.callTool({ name: 'mark_emails', arguments: { uids: [target.uid], read: true, starred: true } });
    const after = json<{ seen: boolean; flagged: boolean }>(await client.callTool({ name: 'get_email', arguments: { uid: target.uid } }));
    assert.equal(after.seen, true);
    assert.equal(after.flagged, true);

    const reply = await client.callTool({ name: 'reply_email', arguments: { uid: target.uid, body: 'Thanks!' } });
    assert.ok(!reply.isError, text(reply));
    const replied = sent.at(-1)!;
    assert.deepEqual(replied.to, ['sender2@example.com']);
    const parsedReply = await simpleParser(replied.raw);
    assert.equal(parsedReply.subject, 'Re: Alice message 2');
    assert.equal(parsedReply.inReplyTo, '<m2.Alice@example.com>');
    assert.match(parsedReply.text ?? '', /> Body of message 2/);
    assert.match(parsedReply.from?.text ?? '', /Alice A/);

    const send = await client.callTool({
      name: 'send_email',
      arguments: { to: 'x@example.com, y@example.com', subject: 'Hi', body: '<b>yo</b>', isHtml: true, attachments: [{ filename: 'a.txt', content: Buffer.from('A').toString('base64') }] }
    });
    assert.ok(!send.isError, text(send));
    const parsedSend = await simpleParser(sent.at(-1)!.raw);
    assert.deepEqual(sent.at(-1)!.to, ['x@example.com', 'y@example.com']);
    assert.equal(parsedSend.attachments[0]!.filename, 'a.txt');

    const draft = json<{ folder: string }>(await client.callTool({ name: 'create_draft', arguments: { to: 'z@example.com', subject: 'Draft', body: 'later' } }));
    assert.equal(draft.folder, 'Drafts');
    const drafts = json<{ messages: Array<{ subject: string; draft: boolean }> }>(await client.callTool({ name: 'list_emails', arguments: { folder: 'drafts' } }));
    assert.equal(drafts.messages[0]!.subject, 'Draft');

    const del = json<{ movedTo: string }>(await client.callTool({ name: 'delete_emails', arguments: { uids: target.uid } }));
    assert.equal(del.movedTo, 'Trash');
    const trash = json<{ total: number }>(await client.callTool({ name: 'list_emails', arguments: { folder: 'trash' } }));
    assert.equal(trash.total, 1);

    await client.close();
  });

  it('accepts static API keys and the deprecated HTTP+SSE transport', async () => {
    const key = 'k'.repeat(32);
    const client = new Client({ name: 'e2e-sse', version: '1.0.0' });
    await client.connect(new SSEClientTransport(new URL(`${base}/sse`), { fetch: authedFetch(key) as never }));
    const accounts = json(await client.callTool({ name: 'list_accounts', arguments: {} }));
    assert.equal((accounts.caller as { via: string }).via, 'api-key');
    assert.deepEqual((accounts.accounts as Array<{ id: string }>).map(a => a.id), ['alice']);
    await client.close();

    const bad = await fetch(`${base}/mcp`, { method: 'POST', headers: { authorization: 'Bearer nope', 'content-type': 'application/json' }, body: '{}' });
    assert.equal(bad.status, 401);
  });

  it('serves stdio with every account for the local user', async () => {
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: ['--import', 'tsx', 'src/index.ts', '--stdio'],
      env: { ...(process.env as Record<string, string>), MCP_TRANSPORT: 'stdio', LOG_LEVEL: 'warn' },
      stderr: 'pipe'
    });
    const client = new Client({ name: 'e2e-stdio', version: '1.0.0' }, { versionNegotiation: { mode: 'auto' } });
    await client.connect(transport);
    const accounts = json(await client.callTool({ name: 'list_accounts', arguments: {} }));
    assert.deepEqual((accounts.accounts as Array<{ id: string }>).map(a => a.id), ['alice', 'bob']);
    const bob = json<{ total: number }>(await client.callTool({ name: 'list_emails', arguments: { account: 'bob' } }));
    assert.equal(bob.total, 3);
    await client.close();
  });

  // ---------------------------------------------------------------- web interface

  it('signs in to the web interface with OIDC and manages accounts (self-service)', async () => {
    const cookies = new Map<string, string>();
    const jar = (res: Response) => {
      for (const c of res.headers.getSetCookie()) {
        const [pair] = c.split(';');
        const i = pair!.indexOf('=');
        cookies.set(pair!.slice(0, i), pair!.slice(i + 1));
      }
    };
    const cookie = () => [...cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    const call = async (path: string, init: { method?: string; body?: unknown; csrf?: boolean } = {}) => {
      const res = await fetch(`${base}/admin/api${path}`, {
        method: init.method ?? 'GET',
        headers: {
          cookie: cookie(),
          ...(init.csrf === false ? {} : { 'x-pmcp': '1' }),
          ...(init.body ? { 'content-type': 'application/json' } : {})
        },
        body: init.body ? JSON.stringify(init.body) : undefined
      });
      return { status: res.status, data: res.status === 204 ? null : ((await res.json().catch(() => null)) as Record<string, any>) };
    };

    const page = await fetch(`${base}/admin`);
    assert.equal(page.status, 200);
    assert.match(page.headers.get('content-security-policy') ?? '', /script-src 'self'/);
    assert.equal((await call('/me')).status, 401);

    // OIDC sign-in through the same /oauth/callback as MCP clients
    const start = await fetch(`${base}/admin/login`, { redirect: 'manual' });
    jar(start);
    const idp = await fetch(start.headers.get('location')!, { redirect: 'manual' });
    const back = await fetch(idp.headers.get('location')!, { redirect: 'manual', headers: { cookie: cookie() } });
    assert.equal(back.status, 302);
    assert.equal(back.headers.get('location'), '/admin');
    jar(back);

    const me = await call('/me');
    assert.equal(me.status, 200);
    assert.equal(me.data!.user.email, 'alice@corp.test');
    assert.equal(me.data!.admin, false);
    assert.equal(me.data!.selfService, true);
    assert.equal(me.data!.bridge, undefined, 'endpoints are hidden from non-admins');

    const listed = await call('/accounts');
    assert.deepEqual(listed.data!.accounts.map((a: { id: string }) => a.id), ['alice']);
    assert.equal(listed.data!.accounts[0].editable, false, 'configuration accounts are read-only');

    // CSRF header is mandatory for writes
    assert.equal((await call('/accounts', { method: 'POST', body: { email: 'x@y.test', password: 'p' }, csrf: false })).status, 403);

    // Test credentials before saving (non-admin: forced to the Bridge defaults, here bob's test server)
    const bad = await call('/accounts/test', { method: 'POST', body: { email: 'shared@bob.test', username: 'bob', password: 'wrong' } });
    assert.equal(bad.data!.imap.ok, false);
    const good = await call('/accounts/test', { method: 'POST', body: { email: 'shared@bob.test', username: 'bob', password: 'bob-bridge-pw' } });
    assert.equal(good.data!.imap.ok, true, JSON.stringify(good.data));
    assert.equal(good.data!.smtp.ok, true, JSON.stringify(good.data));

    // Non-admins cannot point an account at a private address (SSRF)…
    const privateHost = await call('/accounts', {
      method: 'POST',
      body: {
        email: 'shared@bob.test', username: 'bob', password: 'bob-bridge-pw', provider: 'custom',
        imap: { host: '10.0.0.1', port: 993, security: 'tls' }, smtp: { host: '10.0.0.1', port: 465, security: 'tls' }
      }
    });
    assert.equal(privateHost.status, 400);
    assert.match(privateHost.data!.error, /not a public mail server/);
    const plaintext = await call('/accounts', {
      method: 'POST',
      body: { email: 'shared@bob.test', password: 'x', provider: 'custom', imap: { host: '1.1.1.1', port: 143, security: 'none' }, smtp: { host: '1.1.1.1', port: 25, security: 'none' } }
    });
    assert.equal(plaintext.status, 400, 'plaintext refused for non-admins');

    // …but can use the server's Bridge (default when no server is given)
    const created = await call('/accounts', {
      method: 'POST',
      body: { email: 'shared@bob.test', username: 'bob', password: 'bob-bridge-pw', displayName: 'Shared', users: [] }
    });
    assert.equal(created.status, 201, JSON.stringify(created.data));
    assert.equal(created.data!.id, 'shared');
    assert.deepEqual(created.data!.users, ['alice@corp.test'], 'the owner keeps access');
    assert.ok(!readFileSync(join(dataDir, 'accounts.json'), 'utf8').includes('bob-bridge-pw'), 'password stored encrypted');

    assert.equal((await call('/accounts', { method: 'POST', body: { email: 'alice@alice.test', password: 'x' } })).status, 400, 'duplicate address refused');

    // Immediately usable from MCP, on the Bridge defaults
    const client = new Client({ name: 'e2e-after-ui', version: '1.0.0' });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { fetch: authedFetch(tokens.access_token) }));
    const accounts = json(await client.callTool({ name: 'list_accounts', arguments: {} }));
    assert.deepEqual((accounts.accounts as Array<{ id: string }>).map(a => a.id), ['alice', 'shared']);
    const inbox = json<{ total: number }>(await client.callTool({ name: 'list_emails', arguments: { account: 'shared' } }));
    assert.equal(inbox.total, 3);

    // Edit keeps the password, rename the display name
    const updated = await call('/accounts/shared', { method: 'PUT', body: { email: 'shared@bob.test', username: 'bob', displayName: 'Shared box', users: ['alice@corp.test'] } });
    assert.equal(updated.status, 200, JSON.stringify(updated.data));
    assert.equal((await call('/accounts/test', { method: 'POST', body: { savedId: 'shared' } })).data!.imap.ok, true);

    // Connected apps: the OAuth client from the earlier test, revocable
    const apps = await call('/apps');
    assert.equal(apps.data!.apps[0].clientName, 'E2E Client');
    assert.equal((await call(`/apps/${encodeURIComponent(tokens.clientId)}`, { method: 'DELETE' })).status, 204);
    const refresh = await fetch(tokens.tokenEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: tokens.clientId })
    });
    assert.equal(refresh.status, 400, 'revoked refresh token');

    assert.equal((await call('/accounts/shared', { method: 'DELETE' })).status, 204);
    const after = json(await client.callTool({ name: 'list_accounts', arguments: {} }));
    assert.deepEqual((after.accounts as Array<{ id: string }>).map(a => a.id), ['alice']);
    await client.close();

    // "Sign in with Google" for a mailbox: discovery offers it, the callback stores an encrypted refresh token
    const discovered = await call('/discover', { method: 'POST', body: { email: 'boss@gmail.com' } });
    assert.equal(discovered.data!.provider.id, 'gmail');
    assert.equal(discovered.data!.oauth, 'google');
    const oauthStart = await call('/oauth/start', { method: 'POST', body: { provider: 'google', draft: { email: 'boss@gmail.com', id: 'boss' } } });
    assert.equal(oauthStart.status, 200, JSON.stringify(oauthStart.data));
    const atGoogle = await fetch(oauthStart.data!.url, { redirect: 'manual' });
    const callback = await fetch(atGoogle.headers.get('location')!, { redirect: 'manual', headers: { cookie: cookie() } });
    assert.equal(callback.headers.get('location'), '/admin?connected=boss');
    const withOAuth = (await call('/accounts')).data!.accounts.find((a: { id: string }) => a.id === 'boss');
    assert.equal(withOAuth.provider, 'gmail');
    assert.equal(withOAuth.auth, 'oauth:google');
    assert.equal(withOAuth.displayName, 'The Boss');
    assert.equal(withOAuth.imap.host, 'imap.gmail.com');
    assert.ok(!readFileSync(join(dataDir, 'accounts.json'), 'utf8').includes('g-refresh-secret'), 'refresh token stored encrypted');
    const replay = await fetch(atGoogle.headers.get('location')!, { redirect: 'manual', headers: { cookie: cookie() } });
    assert.match(replay.headers.get('location') ?? '', /error=/, 'state is single-use');
    assert.equal((await call('/accounts/boss', { method: 'DELETE' })).status, 204);

    assert.equal((await call('/logout', { method: 'POST' })).status, 204);
  });
});
