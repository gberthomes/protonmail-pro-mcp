/**
 * Proton Bridge Manager against a scripted gRPC Bridge (same protocol, TLS over
 * a Unix socket). Real Bridge checks live in bridge-integration.test.ts.
 */

import { after, afterEach, before, beforeEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { BridgeClient, BridgeSecurityError, readServerConfig, checkSocket } from '../src/bridge-manager/client.js';
import { compatibility } from '../src/bridge-manager/compat.js';
import { inspectInstance } from '../src/bridge-manager/instance.js';
import { BridgeManager } from '../src/bridge-manager/manager.js';
import { setLogLevel } from '../src/logger.js';
import { FakeBridge, selfSignedCert } from './helpers/fake-bridge.js';

const SECRETS = ['proton-secret-pw', '123456', 'mailbox-pw', 'bridge-generated-1', 'bridge-generated-2'];

/** Capture everything written to stderr (where the logger writes). */
function captureLogs(): { text: () => string; restore: () => void } {
  const chunks: string[] = [];
  const original = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((chunk: string | Uint8Array, ...rest: unknown[]) => {
    chunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString());
    return (original as (...a: unknown[]) => boolean)(chunk, ...rest);
  }) as typeof process.stderr.write;
  return { text: () => chunks.join(''), restore: () => (process.stderr.write = original) };
}

describe('Bridge Manager', () => {
  let bridge: FakeBridge;
  let manager: BridgeManager;
  let logs: ReturnType<typeof captureLogs>;
  const fast = { stepTimeoutMs: 400, ttlMs: 5000 };

  before(() => setLogLevel('debug'));

  beforeEach(async () => {
    bridge = new FakeBridge();
    await bridge.start();
    manager = new BridgeManager([{ id: 'main', settingsDir: bridge.settingsDir }], { auth: fast });
    logs = captureLogs();
  });

  afterEach(async () => {
    logs.restore();
    for (const s of SECRETS.concat(bridge.token)) assert.ok(!logs.text().includes(s), `secret "${s}" leaked into the logs`);
    await manager.close();
    await bridge.stop();
  });

  after(() => setLogLevel('warn'));

  // ---------------------------------------------------------------- phase 1

  it('reads version, keychain, ports and an empty account list', async () => {
    const report = await inspectInstance({ id: 'main', settingsDir: bridge.settingsDir }, { checkBinary: false });
    assert.equal(report.running, true);
    assert.equal(report.version, '3.27.2');
    assert.equal(report.compat.level, 'tested');
    assert.equal(report.keychain?.current, 'pass-app');
    assert.equal(report.mailServer?.imapPort, 1143);
    assert.deepEqual(report.accounts, { total: 0, connected: 0, signedOut: 0, locked: 0 });
    assert.ok(report.problems.some(p => p.code === 'no-account'));
    assert.deepEqual(await manager.accounts('main'), []);
  });

  it('detaches with StopEventStream (Bridge quits when the stream is cut)', async () => {
    await manager.onEvents('main', () => undefined);
    await manager.close();
    assert.equal(bridge.streamStops, 1);
    assert.equal(bridge.streamCancels, 0);
  });

  it('refuses a second frontend on the same Bridge, but read-only calls still work', async () => {
    await manager.onEvents('main', () => undefined);
    const readOnly = new BridgeManager([{ id: 'main', settingsDir: bridge.settingsDir }]);
    assert.deepEqual(await readOnly.accounts('main'), []);
    await assert.rejects(() => readOnly.startSignIn('main', 'plain@pm.me', 'proton-secret-pw', 'cli'), /already holds the Bridge event stream/);
    await readOnly.close();
    const other = await BridgeClient.connect(bridge.settingsDir);
    const failure = new Promise<Error>(resolve => other.once('streamError', resolve));
    other.startEvents();
    assert.match((await failure).message, /already holds the Bridge event stream/);
    await other.close();
  });

  // ---------------------------------------------------------------- security

  it('rejects a Bridge presenting another certificate than the published one (no token sent)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cert-'));
    const impostor = new FakeBridge();
    await impostor.start({ publishedCert: selfSignedCert(dir).cert });
    await assert.rejects(() => BridgeClient.connect(impostor.settingsDir, { timeoutMs: 2000 }).then(c => c.version()), /certificate|reach|handshake|failed/i);
    await impostor.stop();
  });

  it('refuses config files and sockets that someone else could have planted', async () => {
    const config = join(bridge.settingsDir, 'grpcServerConfig.json');
    assert.throws(() => readServerConfig(config, { uid: 4242 }), BridgeSecurityError);
    chmodSync(config, 0o666);
    assert.throws(() => readServerConfig(config), /writable by other users/);
    chmodSync(config, 0o644);
    chmodSync(bridge.settingsDir, 0o777);
    assert.throws(() => readServerConfig(config), /writable by other users/);
    chmodSync(bridge.settingsDir, 0o700);
    assert.throws(() => checkSocket(bridge.socketPath, { uid: 4242 }), /owned by uid/);
    const notASocket = join(bridge.root, 'run', 'fake');
    writeFileSync(notASocket, '');
    assert.throws(() => checkSocket(notASocket), /not a Unix socket/);
  });

  it('rejects calls without the server token', async () => {
    const config = join(bridge.settingsDir, 'grpcServerConfig.json');
    const original = readServerConfig(config);
    writeFileSync(config, JSON.stringify({ ...original, token: 'forged' }), { mode: 0o644 });
    const client = await BridgeClient.connect(bridge.settingsDir);
    await assert.rejects(() => client.version(), /invalid server token/);
    await client.close();
  });

  it('refuses state changes on untested Bridge versions unless allowed', async () => {
    bridge.version = '3.99.0';
    assert.equal(compatibility('3.99.0').level, 'untested');
    await assert.rejects(() => manager.startSignIn('main', 'plain@pm.me', 'proton-secret-pw', 'cli'), /has not been tested/);
    assert.deepEqual(await manager.accounts('main'), [], 'read-only calls still work');
    const permissive = new BridgeManager([{ id: 'main', settingsDir: bridge.settingsDir }], { allowUntested: true, auth: fast });
    await manager.close();
    const v = await permissive.startSignIn('main', 'plain@pm.me', 'proton-secret-pw', 'cli');
    assert.equal(v.state, 'CONNECTED');
    await permissive.close();
  });

  // ---------------------------------------------------------------- phase 2: sign-in

  it('signs in a first account and returns its own IMAP/SMTP credentials', async () => {
    const v = await manager.startSignIn('main', 'plain@pm.me', 'proton-secret-pw', { sub: 'admin', email: 'admin@corp' });
    assert.equal(v.state, 'CONNECTED');
    assert.deepEqual(v.account?.addresses, ['plain@pm.me', 'alias.plain@pm.me']);
    assert.equal(bridge.received[0]!.secret, 'proton-secret-pw', 'password sent base64-encoded as Bridge expects');
    assert.ok(!JSON.stringify(v).includes('proton-secret-pw'), 'the session never holds the password');
    const creds = await manager.credentials('main', 'plain@pm.me', 'cli');
    assert.equal(creds.password, 'bridge-generated-1');
    assert.equal(creds.imap.port, 1143);
    assert.match(logs.text(), /AUDIT|\[audit\] credentials of plain@pm\.me/);
  });

  it('handles TOTP with a retry, then the mailbox password', async () => {
    let v = await manager.startSignIn('main', 'both@pm.me', 'proton-secret-pw', 'cli');
    assert.equal(v.state, 'TOTP_REQUIRED');
    const auth = await manager.signIn('main');
    v = await auth.submitTotp(v.id, '000000');
    assert.equal(v.state, 'TOTP_REQUIRED');
    assert.equal(v.error?.code, 'tfa_error');
    v = await auth.submitTotp(v.id, '123456');
    assert.equal(v.state, 'MAILBOX_PASSWORD_REQUIRED');
    v = await auth.submitMailboxPassword(v.id, 'mailbox-pw');
    assert.equal(v.state, 'CONNECTED');
    assert.deepEqual(bridge.received.map(r => r.method), ['Login', 'Login2FA', 'Login2FA', 'Login2Passwords']);
  });

  it('gives up after too many wrong TOTP codes and aborts the sign-in in Bridge', async () => {
    let v = await manager.startSignIn('main', 'totp@pm.me', 'proton-secret-pw', 'cli');
    const auth = await manager.signIn('main');
    for (let i = 0; i < 3; i++) v = await auth.submitTotp(v.id, '999999');
    assert.equal(v.state, 'FAILED');
    assert.equal(v.error?.code, 'too-many-attempts');
    assert.deepEqual(bridge.aborts, ['totp@pm.me']);
    await assert.rejects(() => auth.submitTotp(v.id, '123456'), /FAILED/);
  });

  it('asks for human verification and retries with the verified token', async () => {
    let v = await manager.startSignIn('main', 'hv@pm.me', 'proton-secret-pw', 'cli');
    assert.equal(v.state, 'HV_REQUIRED');
    assert.match(v.hvUrl!, /^https:\/\/verify\.proton\.me\//);
    v = await (await manager.signIn('main')).retryAfterHumanVerification(v.id, 'proton-secret-pw');
    assert.equal(v.state, 'CONNECTED');
    assert.equal(bridge.received.at(-1)!.useHv, true);
  });

  it('reports FIDO-only accounts explicitly instead of pretending', async () => {
    const v = await manager.startSignIn('main', 'fido@pm.me', 'proton-secret-pw', 'cli');
    assert.equal(v.state, 'FIDO_REQUIRED');
    assert.equal(v.error?.code, 'fido-unsupported');
    assert.deepEqual(bridge.aborts, ['fido@pm.me']);
  });

  it('fails on a wrong password without echoing Bridge internals', async () => {
    const v = await manager.startSignIn('main', 'bad@pm.me', 'proton-secret-pw', 'cli');
    assert.equal(v.state, 'FAILED');
    assert.equal(v.error?.message, 'Incorrect Proton username or password.');
  });

  it('times out when Bridge does not answer, and aborts', async () => {
    const v = await manager.startSignIn('main', 'silent@pm.me', 'proton-secret-pw', 'cli');
    assert.equal(v.state, 'FAILED');
    assert.equal(v.error?.code, 'timeout');
    assert.deepEqual(bridge.aborts, ['silent@pm.me']);
  });

  it('expires and cancels sessions', async () => {
    const short = new BridgeManager([{ id: 'main', settingsDir: bridge.settingsDir }], { auth: { ttlMs: 150, stepTimeoutMs: 400 } });
    await manager.close();
    manager = short;
    const v = await short.startSignIn('main', 'totp@pm.me', 'proton-secret-pw', 'cli');
    const auth = await short.signIn('main');
    await new Promise(r => setTimeout(r, 250));
    assert.equal(auth.get(v.id).state, 'EXPIRED');
    const w = await short.startSignIn('main', 'totp@pm.me', 'proton-secret-pw', 'cli');
    assert.equal((await auth.cancel(w.id)).state, 'CANCELLED');
  });

  it('allows one sign-in at a time per Bridge (it has a single sign-in slot)', async () => {
    const first = await manager.startSignIn('main', 'totp@pm.me', 'proton-secret-pw', 'cli');
    assert.equal(first.state, 'TOTP_REQUIRED');
    await assert.rejects(() => manager.startSignIn('main', 'plain@pm.me', 'proton-secret-pw', 'cli'), (e: Error & { status?: number }) => e.status === 409);
    await (await manager.signIn('main')).cancel(first.id);
    assert.equal((await manager.startSignIn('main', 'plain@pm.me', 'proton-secret-pw', 'cli')).state, 'CONNECTED');
  });

  it('ignores login events about another account', async () => {
    bridge.strayEventBefore = { login: { tfaRequested: { username: 'someone-else@pm.me' } } };
    const v = await manager.startSignIn('main', 'plain@pm.me', 'proton-secret-pw', 'cli');
    assert.equal(v.state, 'CONNECTED');
    assert.match(logs.text(), /for another account/);
  });

  it('recognises an account that is already signed in', async () => {
    await manager.startSignIn('main', 'known@pm.me', 'proton-secret-pw', 'cli').catch(() => undefined);
    bridge.users.push({ id: 'user-known', username: 'known@pm.me', state: 'CONNECTED', password: 'bridge-generated-2', addresses: ['known@pm.me'] });
    const v = await manager.startSignIn('main', 'known@pm.me', 'proton-secret-pw', 'cli');
    assert.equal(v.state, 'CONNECTED');
    assert.equal(v.account?.alreadyConfigured, true);
  });

  // ---------------------------------------------------------------- phase 3: several accounts

  it('keeps several accounts apart and manages their lifecycle', async () => {
    assert.equal((await manager.startSignIn('main', 'plain@pm.me', 'proton-secret-pw', 'cli')).state, 'CONNECTED');
    const second = await manager.startSignIn('main', 'twopw@pm.me', 'proton-secret-pw', 'cli');
    assert.equal(second.state, 'MAILBOX_PASSWORD_REQUIRED');
    assert.equal((await manager.accounts('main')).length, 1, 'the first account is untouched while the second signs in');
    assert.equal((await (await manager.signIn('main')).submitMailboxPassword(second.id, 'mailbox-pw')).state, 'CONNECTED');
    assert.deepEqual(bridge.received.filter(r => r.method === 'Login').map(r => r.username), ['plain@pm.me', 'twopw@pm.me']);

    const accounts = await manager.accounts('main');
    assert.ok(accounts.every(a => !('password' in a)), 'account views never carry the Bridge password');
    const all = await manager.connectedCredentials('main');
    assert.equal(new Set(all.map(a => a.credentials.password)).size, all.length, 'each account has its own credentials');
    assert.equal(all.find(a => a.username === 'plain@pm.me')!.credentials.username, 'plain@pm.me');

    await manager.logout('main', 'plain@pm.me', 'cli');
    const after = await manager.accounts('main');
    assert.equal(after.find(a => a.username === 'plain@pm.me')!.state, 'SIGNED_OUT');
    await assert.rejects(() => manager.credentials('main', 'plain@pm.me', 'cli'), /SIGNED_OUT/);

    await assert.rejects(() => manager.remove('main', 'plain@pm.me', 'yes', 'cli'), /Type the account username/);
    await manager.remove('main', 'plain@pm.me', 'PLAIN@pm.me', 'cli');
    assert.ok(!(await manager.accounts('main')).some(a => a.username === 'plain@pm.me'));
    assert.match(logs.text(), /removed from main by cli/);
  });
});
