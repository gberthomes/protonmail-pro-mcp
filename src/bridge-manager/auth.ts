/**
 * Sign-in of a Proton account into an official Bridge, as a state machine.
 *
 *   CREATED → LOGIN_PENDING → TOTP_REQUIRED ─────────┐
 *                          → MAILBOX_PASSWORD_REQUIRED┤→ AUTHENTICATING → CONNECTED
 *                          → HV_REQUIRED (captcha, then password again)
 *                          → FIDO_REQUIRED (terminal: needs a key on the Bridge host)
 *   any → FAILED | CANCELLED | EXPIRED
 *
 * Bridge keeps a single sign-in in progress and its events carry no session
 * id (only the username, or the new user id at the end). The controller
 * therefore allows one session per instance at a time, checks the username of
 * every event, and ignores events nobody is waiting for.
 *
 * Secrets (Proton password, TOTP code, mailbox password) are passed straight to
 * Bridge and never stored on the session nor logged. Bridge keeps its own
 * session once the account is signed in.
 */

import { randomUUID } from 'node:crypto';

import { createLogger } from '../logger.js';
import type { BridgeEvent, BridgeUser } from './client.js';

const log = createLogger('bridge-auth');

export type AuthState =
  | 'CREATED'
  | 'LOGIN_PENDING'
  | 'TOTP_REQUIRED'
  | 'FIDO_REQUIRED'
  | 'HV_REQUIRED'
  | 'MAILBOX_PASSWORD_REQUIRED'
  | 'AUTHENTICATING'
  | 'CONNECTED'
  | 'FAILED'
  | 'CANCELLED'
  | 'EXPIRED';

const TERMINAL: AuthState[] = ['CONNECTED', 'FAILED', 'CANCELLED', 'EXPIRED', 'FIDO_REQUIRED'];

export interface AuthSessionView {
  id: string;
  instanceId: string;
  username: string;
  state: AuthState;
  createdAt: string;
  expiresAt: string;
  attempts: { totp: number; mailboxPassword: number };
  /** TOTP_REQUIRED: the account could also use a security key (not supported here). */
  fidoAlsoAccepted?: boolean;
  /** HV_REQUIRED: open this URL, solve the challenge, then submit the password again. */
  hvUrl?: string;
  error?: { code: string; message: string };
  account?: { id: string; username: string; addresses: string[]; alreadyConfigured: boolean };
}

/** What the controller needs from the Bridge adapter (lets tests use a fake). */
export interface BridgeAuthPort {
  login(username: string, password: string, useHvDetails?: boolean): Promise<void>;
  login2fa(username: string, code: string): Promise<void>;
  login2passwords(username: string, mailboxPassword: string): Promise<void>;
  loginAbort(username: string): Promise<void>;
  user(userId: string): Promise<BridgeUser>;
}

export class AuthError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string
  ) {
    super(message);
  }
}

export interface AuthOptions {
  /** Lifetime of a session (default 10 min). */
  ttlMs?: number;
  /** Maximum wait for Bridge's answer to one step (default 60 s). */
  stepTimeoutMs?: number;
  maxTotpAttempts?: number;
  maxMailboxPasswordAttempts?: number;
}

type LoginEvent = Extract<BridgeEvent, { kind: 'login' }>;

interface Session extends AuthSessionView {
  waiter?: { resolve(e: LoginEvent | undefined): void; timer: NodeJS.Timeout };
  expiry: NodeJS.Timeout;
}

const ERROR_TEXT: Record<string, string> = {
  USERNAME_PASSWORD_ERROR: 'Incorrect Proton username or password.',
  FREE_USER: 'Proton Mail Bridge requires a paid Proton plan.',
  CONNECTION_ERROR: 'Bridge could not reach Proton.',
  TFA_ERROR: 'Incorrect two-factor code.',
  TFA_ABORT: 'Two-factor authentication was aborted.',
  TWO_PASSWORDS_ERROR: 'Incorrect mailbox password.',
  TWO_PASSWORDS_ABORT: 'Mailbox password step was aborted.',
  HV_ERROR: 'Human verification failed or expired.',
  FIDO_PIN_INVALID: 'Invalid security key PIN.',
  FIDO_PIN_BLOCKED: 'Security key PIN blocked.',
  FIDO_ERROR: 'Security key authentication failed.'
};

export class AuthController {
  private readonly sessions = new Map<string, Session>();
  private active?: Session;
  private readonly ttlMs: number;
  private readonly stepTimeoutMs: number;
  private readonly maxTotp: number;
  private readonly maxMailbox: number;

  constructor(
    readonly instanceId: string,
    private readonly bridge: BridgeAuthPort,
    opts: AuthOptions = {}
  ) {
    this.ttlMs = opts.ttlMs ?? 10 * 60_000;
    this.stepTimeoutMs = opts.stepTimeoutMs ?? 60_000;
    this.maxTotp = opts.maxTotpAttempts ?? 3;
    this.maxMailbox = opts.maxMailboxPasswordAttempts ?? 3;
  }

  // ------------------------------------------------------------------ public API

  /** Id of the sign-in currently holding Bridge's slot, if any. */
  activeSessionId(): string | undefined {
    return this.active && !TERMINAL.includes(this.active.state) ? this.active.id : undefined;
  }

  get(id: string): AuthSessionView {
    return this.view(this.mustGet(id));
  }

  /** Start signing in an account. Only one sign-in per instance at a time. */
  async start(username: string, password: string): Promise<AuthSessionView> {
    const name = username.trim();
    if (!name || name.length > 254 || /[\s]/.test(name)) throw new AuthError(400, 'invalid-username', 'Invalid Proton username or address');
    if (!password) throw new AuthError(400, 'invalid-password', 'Password required');
    if (this.active && !TERMINAL.includes(this.active.state)) {
      throw new AuthError(409, 'busy', 'Another sign-in is in progress on this Bridge; finish or cancel it first');
    }
    const now = Date.now();
    const s: Session = {
      id: randomUUID(),
      instanceId: this.instanceId,
      username: name,
      state: 'CREATED',
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + this.ttlMs).toISOString(),
      attempts: { totp: 0, mailboxPassword: 0 },
      expiry: setTimeout(() => void this.expire(s), this.ttlMs)
    };
    s.expiry.unref();
    this.sessions.set(s.id, s);
    this.active = s;
    this.prune();
    log.info(`Sign-in ${s.id} started for ${name} on instance ${this.instanceId}`);
    await this.step(s, 'LOGIN_PENDING', () => this.bridge.login(name, password));
    return this.view(s);
  }

  async submitTotp(id: string, code: string): Promise<AuthSessionView> {
    const s = this.expect(id, 'TOTP_REQUIRED');
    if (!/^\d{6,8}$/.test(code.trim())) throw new AuthError(400, 'invalid-code', 'The two-factor code must be 6 to 8 digits');
    s.attempts.totp++;
    await this.step(s, 'AUTHENTICATING', () => this.bridge.login2fa(s.username, code.trim()));
    return this.view(s);
  }

  async submitMailboxPassword(id: string, mailboxPassword: string): Promise<AuthSessionView> {
    const s = this.expect(id, 'MAILBOX_PASSWORD_REQUIRED');
    if (!mailboxPassword) throw new AuthError(400, 'invalid-password', 'Mailbox password required');
    s.attempts.mailboxPassword++;
    await this.step(s, 'AUTHENTICATING', () => this.bridge.login2passwords(s.username, mailboxPassword));
    return this.view(s);
  }

  /** After solving the human verification challenge: Bridge needs the password again. */
  async retryAfterHumanVerification(id: string, password: string): Promise<AuthSessionView> {
    const s = this.expect(id, 'HV_REQUIRED');
    if (!password) throw new AuthError(400, 'invalid-password', 'Password required');
    s.hvUrl = undefined;
    await this.step(s, 'LOGIN_PENDING', () => this.bridge.login(s.username, password, true));
    return this.view(s);
  }

  async cancel(id: string): Promise<AuthSessionView> {
    const s = this.mustGet(id);
    if (!TERMINAL.includes(s.state)) {
      this.finish(s, 'CANCELLED');
      this.release(s);
      await this.abortBridge(s);
      log.info(`Sign-in ${s.id} cancelled`);
    }
    return this.view(s);
  }

  /** Feed Bridge events (from BridgeClient 'event'). */
  handleEvent(e: BridgeEvent): void {
    if (e.kind !== 'login') return;
    const s = this.active;
    if (!s || !s.waiter) {
      log.debug(`Ignoring login event "${e.type}": no sign-in is waiting for one`);
      return;
    }
    if ('username' in e && e.username && e.username.toLowerCase() !== s.username.toLowerCase()) {
      log.warn(`Ignoring login event "${e.type}" for another account (session ${s.id})`);
      return;
    }
    const { resolve, timer } = s.waiter;
    clearTimeout(timer);
    s.waiter = undefined;
    resolve(e);
  }

  /** Abort everything (instance shutting down or event stream lost). */
  async abortAll(reason: string): Promise<void> {
    const s = this.active;
    if (s && !TERMINAL.includes(s.state)) {
      s.error = { code: 'bridge-unavailable', message: reason };
      this.finish(s, 'FAILED');
      this.release(s);
    }
  }

  // ------------------------------------------------------------------ internals

  private mustGet(id: string): Session {
    const s = this.sessions.get(id);
    if (!s) throw new AuthError(404, 'not-found', 'Unknown or expired sign-in session');
    return s;
  }

  private expect(id: string, state: AuthState): Session {
    const s = this.mustGet(id);
    if (s.state !== state) throw new AuthError(409, 'wrong-state', `This sign-in is ${s.state}, not ${state}`);
    if (s.waiter) throw new AuthError(409, 'busy', 'A step of this sign-in is already in progress');
    return s;
  }

  private view(s: Session): AuthSessionView {
    const { waiter: _w, expiry: _e, ...rest } = s;
    return { ...rest, attempts: { ...s.attempts }, error: s.error ? { ...s.error } : undefined, account: s.account ? { ...s.account } : undefined };
  }

  /** Wake up a step waiting for Bridge (cancellation, expiry). */
  private release(s: Session): void {
    if (!s.waiter) return;
    const { resolve, timer } = s.waiter;
    clearTimeout(timer);
    s.waiter = undefined;
    resolve(undefined);
  }

  private waitForEvent(s: Session): Promise<LoginEvent | undefined> {
    return new Promise(resolve => {
      const timer = setTimeout(() => {
        s.waiter = undefined;
        resolve(undefined);
      }, this.stepTimeoutMs);
      timer.unref();
      s.waiter = { resolve, timer };
    });
  }

  /** Send one request to Bridge and apply the event it answers with. */
  private async step(s: Session, pending: AuthState, send: () => Promise<void>): Promise<void> {
    s.state = pending;
    s.error = undefined;
    const answer = this.waitForEvent(s);
    try {
      await send();
    } catch (err) {
      if (s.waiter) {
        clearTimeout(s.waiter.timer);
        s.waiter = undefined;
      }
      s.error = { code: 'bridge-error', message: err instanceof Error ? err.message : String(err) };
      this.finish(s, 'FAILED');
      return;
    }
    const event = await answer;
    if (TERMINAL.includes(s.state)) return; // cancelled, expired or aborted meanwhile
    if (!event) {
      s.error = { code: 'timeout', message: 'Bridge did not answer in time' };
      await this.abortBridge(s);
      this.finish(s, 'FAILED');
      return;
    }
    await this.apply(s, event);
  }

  private async apply(s: Session, e: LoginEvent): Promise<void> {
    switch (e.type) {
      case 'tfaRequested':
        s.state = 'TOTP_REQUIRED';
        return;
      case 'tfaOrFidoRequested':
        s.state = 'TOTP_REQUIRED';
        s.fidoAlsoAccepted = true;
        return;
      case 'fidoRequested':
      case 'fidoTouchRequested':
      case 'fidoPinRequired':
        s.error = {
          code: 'fido-unsupported',
          message: 'This account requires a FIDO2 security key plugged into the Bridge host, which the Manager cannot drive. Add a TOTP method to the account or sign in with Proton\'s own Bridge application.'
        };
        await this.abortBridge(s);
        this.finish(s, 'FIDO_REQUIRED');
        return;
      case 'twoPasswordRequested':
        s.state = 'MAILBOX_PASSWORD_REQUIRED';
        return;
      case 'hvRequested':
        s.state = 'HV_REQUIRED';
        s.hvUrl = e.hvUrl;
        return;
      case 'finished':
      case 'alreadyLoggedIn':
        await this.verify(s, e.userId, e.type === 'alreadyLoggedIn');
        return;
      case 'error':
        await this.onError(s, e.errorType, e.message);
        return;
      default:
        return;
    }
  }

  private async onError(s: Session, type: string, message: string): Promise<void> {
    const text = ERROR_TEXT[type] ?? 'Sign-in failed';
    // Bridge's message can contain internal details; keep ours, append Bridge's only for connection problems.
    s.error = { code: type.toLowerCase(), message: type === 'CONNECTION_ERROR' && message ? `${text} (${message})` : text };
    if (type === 'TFA_ERROR' && s.attempts.totp < this.maxTotp) {
      s.state = 'TOTP_REQUIRED';
      return;
    }
    if (type === 'TWO_PASSWORDS_ERROR' && s.attempts.mailboxPassword < this.maxMailbox) {
      s.state = 'MAILBOX_PASSWORD_REQUIRED';
      return;
    }
    if (type === 'TFA_ERROR' || type === 'TWO_PASSWORDS_ERROR') {
      s.error = { code: 'too-many-attempts', message: `${text} Too many attempts.` };
      await this.abortBridge(s);
    }
    this.finish(s, 'FAILED');
  }

  private async verify(s: Session, userId: string, alreadyConfigured: boolean): Promise<void> {
    s.state = 'AUTHENTICATING';
    for (let i = 0; i < 10; i++) {
      try {
        const u = await this.bridge.user(userId);
        if (u.state === 'CONNECTED') {
          s.account = { id: u.id, username: u.username, addresses: u.addresses, alreadyConfigured };
          this.finish(s, 'CONNECTED');
          log.info(`Sign-in ${s.id}: ${u.username} connected (user ${u.id})${alreadyConfigured ? ', already configured' : ''}`);
          return;
        }
      } catch {
        /* Bridge may need a moment to register the user */
      }
      await new Promise(r => setTimeout(r, 500));
    }
    s.error = { code: 'not-connected', message: 'Bridge reported success but the account is not connected' };
    this.finish(s, 'FAILED');
  }

  private async abortBridge(s: Session): Promise<void> {
    await this.bridge.loginAbort(s.username).catch(() => undefined);
  }

  private finish(s: Session, state: AuthState): void {
    s.state = state;
    clearTimeout(s.expiry);
    if (this.active === s) this.active = undefined;
    if (state === 'FAILED') log.info(`Sign-in ${s.id} failed: ${s.error?.code ?? 'unknown'}`);
  }

  private async expire(s: Session): Promise<void> {
    if (TERMINAL.includes(s.state)) return;
    s.error = { code: 'expired', message: 'The sign-in session expired' };
    this.finish(s, 'EXPIRED');
    this.release(s);
    await this.abortBridge(s);
    log.info(`Sign-in ${s.id} expired`);
  }

  /** Forget finished sessions after an hour. */
  private prune(): void {
    const limit = Date.now() - 60 * 60_000;
    for (const [id, s] of this.sessions) if (TERMINAL.includes(s.state) && Date.parse(s.createdAt) < limit) this.sessions.delete(id);
  }
}
