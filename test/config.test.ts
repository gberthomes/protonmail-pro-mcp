import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { loadConfig } from '../src/config.js';

const saved = { ...process.env };
afterEach(() => {
  for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
  Object.assign(process.env, saved);
});

function withEnv(vars: Record<string, string>) {
  for (const k of Object.keys(process.env)) if (k.startsWith('PROTONMAIL_') || k.startsWith('MAIL_OAUTH_')) delete process.env[k];
  Object.assign(process.env, vars);
}

describe('account configuration', () => {
  it('applies provider presets and keeps the Bridge as default', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pmcp-cfg-'));
    const file = join(dir, 'c.json');
    writeFileSync(
      file,
      JSON.stringify({
        accounts: [
          { email: 'me@proton.me', password: 'b' },
          { id: 'g', email: 'me@gmail.com', provider: 'gmail', password: 'app' },
          { id: 'i', email: 'jane@icloud.com', provider: 'icloud', password: 'app' },
          { id: 'own', email: 'me@own.example', password: 'p', imap: { host: 'mail.own.example', port: 993, security: 'tls' }, smtp: { host: 'mail.own.example', port: 465, security: 'tls' } },
          { id: 'auto', email: 'me@auto.example', password: 'p', discover: true }
        ]
      })
    );
    withEnv({ PROTONMAIL_MCP_CONFIG: file });
    const accounts = loadConfig([]).accounts;
    rmSync(dir, { recursive: true, force: true });

    const [proton, gmail, icloud, own, auto] = accounts;
    assert.equal(proton!.provider, 'proton-bridge');
    assert.equal(proton!.imap.port, 1143);
    assert.equal(proton!.imap.rejectUnauthorized, false, 'Bridge certificate is self-signed');

    assert.equal(gmail!.imap.host, 'imap.gmail.com');
    assert.equal(gmail!.smtp.port, 465);
    assert.equal(gmail!.imap.rejectUnauthorized, true);
    assert.equal(gmail!.saveSent, false);

    assert.equal(icloud!.imap.username, 'jane', 'iCloud IMAP uses the local part');
    assert.equal(icloud!.smtp.username, 'jane@icloud.com');

    assert.equal(own!.provider, 'custom');
    assert.equal(own!.imap.rejectUnauthorized, true, 'certificates are verified for non-Bridge servers');

    assert.equal(auto!.discover, true);
  });

  it('reads per-account servers and OAuth clients from the environment', () => {
    withEnv({
      PROTONMAIL_ACCOUNT_WORK_EMAIL: 'me@corp.example',
      PROTONMAIL_ACCOUNT_WORK_PASSWORD: 'p',
      PROTONMAIL_ACCOUNT_WORK_IMAP_HOST: 'imap.corp.example',
      PROTONMAIL_ACCOUNT_WORK_IMAP_PORT: '993',
      PROTONMAIL_ACCOUNT_WORK_IMAP_SECURITY: 'ssl',
      PROTONMAIL_ACCOUNT_WORK_SMTP_HOST: 'smtp.corp.example',
      PROTONMAIL_ACCOUNT_WORK_SMTP_PORT: '587',
      PROTONMAIL_ACCOUNT_WORK_SAVE_SENT: 'true',
      MAIL_OAUTH_MICROSOFT_CLIENT_ID: 'ms-app',
      MAIL_OAUTH_MICROSOFT_TENANT: 'contoso.onmicrosoft.com'
    });
    const config = loadConfig([]);
    const work = config.accounts.find(a => a.id === 'work')!;
    assert.deepEqual([work.imap.host, work.imap.port, work.imap.security], ['imap.corp.example', 993, 'tls']);
    assert.equal(work.smtp.host, 'smtp.corp.example');
    assert.equal(work.saveSent, true);
    assert.equal(config.mailOAuth.google, undefined);
    assert.match(config.mailOAuth.microsoft!.tokenUrl, /contoso\.onmicrosoft\.com\/oauth2\/v2\.0\/token$/);
    assert.ok(config.mailOAuth.microsoft!.scopes.includes('https://outlook.office.com/IMAP.AccessAsUser.All'));
  });

  it('rejects unknown presets', () => {
    withEnv({ PROTONMAIL_ACCOUNT_X_EMAIL: 'a@b.example', PROTONMAIL_ACCOUNT_X_PASSWORD: 'p', PROTONMAIL_ACCOUNT_X_PROVIDER: 'nope' });
    assert.throws(() => loadConfig([]), /unknown provider/);
  });
});
