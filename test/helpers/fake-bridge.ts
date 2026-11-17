/**
 * A scripted stand-in for Proton Mail Bridge's gRPC control interface, served
 * like the real one: TLS with a self-signed certificate over a Unix socket,
 * announced in grpcServerConfig.json, every call checked against the token.
 *
 * Behaviour is driven by the username:
 *   plain@…     signs in directly
 *   totp@…      asks for a TOTP code (123456)
 *   twopw@…     asks for the mailbox password (mailbox-pw)
 *   both@…      TOTP then mailbox password
 *   hv@…        asks for human verification, succeeds when retried with useHvDetails
 *   fido@…      asks for a security key
 *   bad@…       wrong password
 *   silent@…    never answers
 *   known@…     already signed in
 */

import { execFileSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';

const PROTO = fileURLToPath(new URL('../../src/bridge-manager/proto/bridge-control.proto', import.meta.url));

export function selfSignedCert(dir: string, cn = '127.0.0.1'): { cert: string; key: string } {
  const key = join(dir, 'key.pem');
  const cert = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', key, '-out', cert, '-days', '1', '-subj', `/CN=${cn}`, '-addext', `subjectAltName=IP:${cn}`], { stdio: 'ignore' });
  const read = (p: string) => execFileSync('cat', [p]).toString();
  return { cert: read(cert), key: read(key) };
}

interface FakeUser {
  id: string;
  username: string;
  state: 'SIGNED_OUT' | 'LOCKED' | 'CONNECTED';
  password: string;
  addresses: string[];
}

export class FakeBridge {
  readonly root: string;
  readonly settingsDir: string;
  readonly socketPath: string;
  readonly token = `tok-${Math.random().toString(36).slice(2)}-secret`;
  version = '3.27.2';
  users: FakeUser[] = [];
  /** Decoded secrets received, to check base64 handling. */
  received: Array<{ method: string; username: string; secret: string; useHv?: boolean }> = [];
  aborts: string[] = [];
  streamStops = 0;
  streamCancels = 0;
  private server = new grpc.Server();
  private stream?: grpc.ServerWritableStream<unknown, unknown>;
  private pending?: { username: string; needsTotp: boolean; needsMailbox: boolean };
  private nextId = 1;
  /** Send this event before the real answer (to test event isolation). */
  strayEventBefore?: Record<string, unknown>;

  constructor() {
    this.root = mkdtempSync(join(tmpdir(), 'fb-'));
    this.settingsDir = join(this.root, 'config', 'protonmail', 'bridge-v3');
    mkdirSync(this.settingsDir, { recursive: true, mode: 0o700 });
    mkdirSync(join(this.root, 'run'), { mode: 0o700 });
    this.socketPath = join(this.root, 'run', 'bridge0001');
  }

  emit(event: Record<string, unknown>): void {
    this.stream?.write(event);
  }

  private login(username: string, event: Record<string, unknown>): void {
    if (this.strayEventBefore) {
      this.emit(this.strayEventBefore);
      this.strayEventBefore = undefined;
    }
    this.emit({ login: event });
    void username;
  }

  private finish(username: string): void {
    const existing = this.users.find(u => u.username === username);
    const user = existing ?? { id: `user-${this.nextId}`, username, state: 'CONNECTED' as const, password: `bridge-generated-${this.nextId++}`, addresses: [username, `alias.${username}`] };
    user.state = 'CONNECTED';
    if (!existing) this.users.push(user);
    this.pending = undefined;
    this.login(username, { finished: { userID: user.id, wasSignedOut: Boolean(existing) } });
  }

  async start(opts: { publishedCert?: string } = {}): Promise<void> {
    const pkg = protoLoader.loadSync(PROTO, { keepCase: true, longs: Number, enums: String, defaults: true, oneofs: true });
    const def = (grpc.loadPackageDefinition(pkg).grpc as grpc.GrpcObject).Bridge as grpc.ServiceClientConstructor;
    const auth = (call: { metadata: grpc.Metadata }) => call.metadata.get('server-token')[0] === this.token;
    const unary =
      (fn: (req: Record<string, unknown>) => unknown) =>
      (call: grpc.ServerUnaryCall<Record<string, unknown>, unknown>, cb: grpc.sendUnaryData<unknown>) => {
        if (!auth(call)) return cb({ code: grpc.status.UNAUTHENTICATED, details: 'invalid server token' });
        try {
          cb(null, fn(call.request));
        } catch (err) {
          cb({ code: grpc.status.NOT_FOUND, details: (err as Error).message });
        }
      };
    const secret = (req: Record<string, unknown>) => Buffer.from((req.password as Buffer).toString('utf8'), 'base64').toString('utf8');
    const userMsg = (u: FakeUser) => ({ ...u, password: Buffer.from(u.password), splitMode: false, usedBytes: 1, totalBytes: 2, avatarText: 'X' });

    this.server.addService(def.service, {
      GuiReady: unary(() => ({ showSplashScreen: false })),
      Version: unary(() => ({ value: this.version })),
      GoOs: unary(() => ({ value: 'linux' })),
      LogsPath: unary(() => ({ value: '/logs' })),
      Hostname: unary(() => ({ value: 'host' })),
      IsPortFree: unary(() => ({ value: true })),
      MailServerSettings: unary(() => ({ imapPort: 1143, smtpPort: 1025, useSSLForImap: false, useSSLForSmtp: false })),
      AvailableKeychains: unary(() => ({ keychains: ['pass-app'] })),
      CurrentKeychain: unary(() => ({ value: 'pass-app' })),
      GetUserList: unary(() => ({ users: this.users.map(userMsg) })),
      GetUser: unary(req => {
        const u = this.users.find(x => x.id === req.value);
        if (!u) throw new Error('no such user');
        return userMsg(u);
      }),
      LogoutUser: unary(req => {
        const u = this.users.find(x => x.id === req.value);
        if (u) u.state = 'SIGNED_OUT';
        return {};
      }),
      RemoveUser: unary(req => {
        this.users = this.users.filter(x => x.id !== req.value);
        return {};
      }),
      LoginAbort: unary(req => {
        this.aborts.push(String(req.username));
        this.pending = undefined;
        return {};
      }),
      Login: unary(req => {
        const username = String(req.username);
        const pw = secret(req);
        this.received.push({ method: 'Login', username, secret: pw, useHv: Boolean(req.useHvDetails) });
        const kind = username.split('@')[0];
        setTimeout(() => {
          if (kind === 'bad' || pw === 'wrong') return this.login(username, { error: { type: 'USERNAME_PASSWORD_ERROR', message: 'internal detail' } });
          if (kind === 'silent') return;
          if (kind === 'known') return this.login(username, { alreadyLoggedIn: { userID: this.users.find(u => u.username === username)?.id ?? 'user-known' } });
          if (kind === 'fido') return this.login(username, { fidoRequested: { username } });
          if (kind === 'hv' && !req.useHvDetails) return this.login(username, { hvRequested: { hvUrl: 'https://verify.proton.me/?methods=captcha&token=abc' } });
          this.pending = { username, needsTotp: kind === 'totp' || kind === 'both', needsMailbox: kind === 'twopw' || kind === 'both' };
          if (this.pending.needsTotp) return this.login(username, { tfaRequested: { username } });
          if (this.pending.needsMailbox) return this.login(username, { twoPasswordRequested: { username } });
          this.finish(username);
        }, 5);
        return {};
      }),
      Login2FA: unary(req => {
        const username = String(req.username);
        const code = secret(req);
        this.received.push({ method: 'Login2FA', username, secret: code });
        setTimeout(() => {
          if (!this.pending) return this.login(username, { error: { type: 'TFA_ABORT', message: 'Missing authentication' } });
          if (code !== '123456') return this.login(username, { error: { type: 'TFA_ERROR', message: '' } });
          if (this.pending.needsMailbox) return this.login(username, { twoPasswordRequested: { username } });
          this.finish(username);
        }, 5);
        return {};
      }),
      Login2Passwords: unary(req => {
        const username = String(req.username);
        const pw = secret(req);
        this.received.push({ method: 'Login2Passwords', username, secret: pw });
        setTimeout(() => {
          if (pw !== 'mailbox-pw') return this.login(username, { error: { type: 'TWO_PASSWORDS_ERROR', message: '' } });
          this.finish(username);
        }, 5);
        return {};
      }),
      RunEventStream: (call: grpc.ServerWritableStream<unknown, unknown>) => {
        if (!auth(call)) {
          call.emit('error', { code: grpc.status.UNAUTHENTICATED, details: 'invalid server token' });
          return;
        }
        if (this.stream) {
          call.emit('error', { code: grpc.status.ALREADY_EXISTS, details: 'the service is already streaming' });
          return;
        }
        this.stream = call;
        call.on('cancelled', () => {
          // The real Bridge quits in this case.
          if (this.stream === call) {
            this.streamCancels++;
            this.stream = undefined;
          }
        });
        this.emit({ app: { allUsersLoaded: {} } });
      },
      StopEventStream: unary(() => {
        this.streamStops++;
        const s = this.stream;
        this.stream = undefined;
        s?.end();
        return {};
      })
    });

    const pair = selfSignedCert(this.root);
    const creds = grpc.ServerCredentials.createSsl(null, [{ private_key: Buffer.from(pair.key), cert_chain: Buffer.from(pair.cert) }], false);
    await new Promise<void>((resolve, reject) => this.server.bindAsync(`unix://${this.socketPath}`, creds, err => (err ? reject(err) : resolve())));
    chmodSync(this.socketPath, 0o755);
    const config = { port: 0, cert: opts.publishedCert ?? pair.cert, token: this.token, fileSocketPath: this.socketPath };
    writeFileSync(join(this.settingsDir, 'grpcServerConfig.json'), JSON.stringify(config), { mode: 0o644 });
    writeFileSync(join(this.settingsDir, 'vault.enc'), 'x', { mode: 0o600 });
  }

  async stop(): Promise<void> {
    await new Promise<void>(resolve => this.server.tryShutdown(() => resolve()));
    rmSync(this.root, { recursive: true, force: true });
  }
}
