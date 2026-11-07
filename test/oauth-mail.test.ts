/**
 * XOAUTH2 against real IMAP/SMTP test servers, refresh-token rotation, and
 * filing sent messages in "Sent" for servers that do not do it themselves.
 */

import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import express from 'express';
import { SMTPServer } from 'smtp-server';
// @ts-expect-error untyped test dependency
import hoodiecrow from 'hoodiecrow-imap';

import { MailAccount } from '../src/mail/account.js';
import { MailOAuth } from '../src/mail/oauth.js';

const port = (srv: Server) => (srv.address() as AddressInfo).port;
const listen = (srv: { listen: Server['listen'] }, inner: () => Server) =>
  new Promise<number>(resolve => srv.listen(0, '127.0.0.1', () => resolve(port(inner()))));

describe('OAuth mailboxes and Sent copies', () => {
  let imap: { listen: Server['listen']; server: Server; close(): void };
  let smtp: SMTPServer;
  let tokenServer: Server;
  let imapPort = 0, smtpPort = 0, tokenPort = 0;
  const smtpAuth: string[] = [];
  const tokenRequests: string[] = [];
  let currentAccessToken = 'access-1';

  before(async () => {
    imap = hoodiecrow({
      plugins: ['SASL-IR', 'XOAUTH2', 'ID', 'UIDPLUS', 'SPECIAL-USE', 'ENABLE'],
      users: { 'carol@gmail.test': { password: 'unused', xoauth2: { accessToken: 'access-2' } } },
      storage: { INBOX: { messages: [] }, '': { separator: '/', folders: { Sent: { 'special-use': '\\Sent' }, Trash: { 'special-use': '\\Trash' } } } }
    });
    imapPort = await listen(imap, () => imap.server);

    smtp = new SMTPServer({
      authMethods: ['XOAUTH2'],
      allowInsecureAuth: true,
      disabledCommands: ['STARTTLS'],
      onAuth(auth, _session, cb) {
        smtpAuth.push(`${auth.method}:${auth.username}:${auth.accessToken}`);
        if (auth.method === 'XOAUTH2' && auth.accessToken === currentAccessToken) cb(null, { user: auth.username });
        else cb(null, { data: { status: '401', schemes: 'bearer' } });
      },
      onData(stream, _s, cb) {
        stream.resume();
        stream.on('end', () => cb());
      }
    });
    smtpPort = await new Promise<number>(resolve => smtp.listen(0, '127.0.0.1', () => resolve((smtp.server.address() as AddressInfo).port)));

    // Token endpoint: refresh-1 → access-2 and a rotated refresh-2 (like Microsoft)
    const app = express();
    app.use(express.urlencoded({ extended: false }));
    app.post('/token', (req, res) => {
      tokenRequests.push(`${req.body.grant_type}:${req.body.refresh_token}:${req.body.client_id}`);
      if (req.body.refresh_token !== 'refresh-1' && req.body.refresh_token !== 'refresh-2') {
        res.status(400).json({ error: 'invalid_grant', error_description: 'revoked' });
        return;
      }
      currentAccessToken = 'access-2';
      res.json({ access_token: 'access-2', token_type: 'Bearer', expires_in: 3600, refresh_token: 'refresh-2' });
    });
    tokenServer = createServer(app);
    tokenPort = await listen(tokenServer, () => tokenServer);
  });

  after(() => {
    imap?.close();
    smtp?.close(() => undefined);
    tokenServer?.close();
  });

  const oauth = () =>
    new MailOAuth({
      google: {
        clientId: 'mail-client',
        clientSecret: 'mail-secret',
        authorizeUrl: 'https://accounts.example/auth',
        tokenUrl: `http://127.0.0.1:${tokenPort}/token`,
        scopes: ['https://mail.google.com/'],
        extraParams: {}
      }
    });

  const account = (refreshToken: string, rotated: string[], mailOAuth = oauth()) =>
    new MailAccount(
      {
        id: 'carol',
        email: 'carol@gmail.test',
        username: 'carol@gmail.test',
        password: '',
        provider: 'custom',
        saveSent: true,
        oauth: { provider: 'google', refreshToken },
        imap: { host: '127.0.0.1', port: imapPort, security: 'none', rejectUnauthorized: true },
        smtp: { host: '127.0.0.1', port: smtpPort, security: 'none', rejectUnauthorized: true }
      },
      { oauth: mailOAuth, onRefreshToken: t => rotated.push(t) }
    );

  it('connects IMAP and SMTP with XOAUTH2 and persists rotated refresh tokens', async () => {
    const rotated: string[] = [];
    const acc = account('refresh-1', rotated);
    const status = await acc.status();
    assert.deepEqual(status, { imap: { ok: true }, smtp: { ok: true } }, JSON.stringify(status));
    assert.deepEqual(rotated, ['refresh-2']);
    assert.deepEqual(tokenRequests, ['refresh_token:refresh-1:mail-client'], 'one refresh for both protocols (cached)');
    assert.ok(smtpAuth.includes('XOAUTH2:carol@gmail.test:access-2'));

    const sent = await acc.send({ to: ['dave@example.com'], subject: 'Hello', text: 'Hi Dave' });
    assert.deepEqual(sent.accepted, ['dave@example.com']);
    assert.equal(sent.savedToSent, 'Sent');
    const folder = await acc.listMessages('sent', { limit: 5, offset: 0 });
    assert.equal(folder.total, 1);
    assert.equal(folder.messages[0]!.subject, 'Hello');
    assert.equal(folder.messages[0]!.seen, true);
    await acc.close();
  });

  it('explains how to recover when access was revoked', async () => {
    const acc = account('revoked-token', []);
    const status = await acc.status();
    assert.equal(status.imap.ok, false);
    assert.match(status.imap.error!, /reconnect this account/);
    await acc.close();
  });
});
