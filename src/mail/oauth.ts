/**
 * OAuth 2.0 for mailboxes (XOAUTH2 over IMAP/SMTP) at Google and Microsoft.
 *
 * Users click "Sign in with Google/Microsoft" in the web interface; the
 * refresh token is stored encrypted with the account and exchanged for
 * short-lived access tokens when a connection opens.
 */

import { createHash } from 'node:crypto';

import { decodeJwt } from 'jose';

import { createLogger } from '../logger.js';
import type { MailOAuthProviderId } from './providers.js';

const log = createLogger('mail-oauth');

export interface MailOAuthClient {
  clientId: string;
  clientSecret?: string;
  authorizeUrl: string;
  tokenUrl: string;
  scopes: string[];
  extraParams: Record<string, string>;
}

export type MailOAuthConfig = Partial<Record<MailOAuthProviderId, MailOAuthClient>>;

export const MAIL_OAUTH_LABELS: Record<MailOAuthProviderId, string> = { google: 'Google', microsoft: 'Microsoft' };

/** Build the provider clients from environment variables. */
export function mailOAuthFromEnv(env: (name: string) => string | undefined): MailOAuthConfig {
  const out: MailOAuthConfig = {};
  const googleId = env('MAIL_OAUTH_GOOGLE_CLIENT_ID');
  if (googleId) {
    out.google = {
      clientId: googleId,
      clientSecret: env('MAIL_OAUTH_GOOGLE_CLIENT_SECRET'),
      authorizeUrl: env('MAIL_OAUTH_GOOGLE_AUTHORIZE_URL') ?? 'https://accounts.google.com/o/oauth2/v2/auth',
      tokenUrl: env('MAIL_OAUTH_GOOGLE_TOKEN_URL') ?? 'https://oauth2.googleapis.com/token',
      scopes: ['https://mail.google.com/', 'openid', 'email'],
      extraParams: { access_type: 'offline', prompt: 'consent' }
    };
  }
  const msId = env('MAIL_OAUTH_MICROSOFT_CLIENT_ID');
  if (msId) {
    const tenant = env('MAIL_OAUTH_MICROSOFT_TENANT') ?? 'common';
    out.microsoft = {
      clientId: msId,
      clientSecret: env('MAIL_OAUTH_MICROSOFT_CLIENT_SECRET'),
      authorizeUrl: env('MAIL_OAUTH_MICROSOFT_AUTHORIZE_URL') ?? `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
      tokenUrl: env('MAIL_OAUTH_MICROSOFT_TOKEN_URL') ?? `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
      scopes: [
        'https://outlook.office.com/IMAP.AccessAsUser.All',
        'https://outlook.office.com/SMTP.Send',
        'offline_access',
        'openid',
        'email',
        'profile'
      ],
      extraParams: { prompt: 'select_account' }
    };
  }
  return out;
}

export interface TokenSet {
  accessToken: string;
  expiresAt: number;
  refreshToken?: string;
}

export class MailOAuth {
  private readonly cache = new Map<string, TokenSet>();
  private readonly inflight = new Map<string, Promise<TokenSet>>();

  constructor(private readonly clients: MailOAuthConfig) {}

  available(): MailOAuthProviderId[] {
    return (Object.keys(this.clients) as MailOAuthProviderId[]).filter(p => this.clients[p]);
  }

  private client(provider: MailOAuthProviderId): MailOAuthClient {
    const c = this.clients[provider];
    if (!c) throw new Error(`${MAIL_OAUTH_LABELS[provider]} sign-in is not configured on this server`);
    return c;
  }

  authorizationUrl(provider: MailOAuthProviderId, p: { redirectUri: string; state: string; codeChallenge: string; loginHint?: string }): string {
    const c = this.client(provider);
    const url = new URL(c.authorizeUrl);
    url.search = new URLSearchParams({
      response_type: 'code',
      client_id: c.clientId,
      redirect_uri: p.redirectUri,
      scope: c.scopes.join(' '),
      state: p.state,
      code_challenge: p.codeChallenge,
      code_challenge_method: 'S256',
      ...c.extraParams,
      ...(p.loginHint ? { login_hint: p.loginHint } : {})
    }).toString();
    return url.href;
  }

  private async token(provider: MailOAuthProviderId, params: Record<string, string>): Promise<Record<string, unknown>> {
    const c = this.client(provider);
    const body = new URLSearchParams({ client_id: c.clientId, ...params });
    if (c.clientSecret) body.set('client_secret', c.clientSecret);
    const res = await fetch(c.tokenUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body,
      signal: AbortSignal.timeout(15_000)
    });
    const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok || typeof data.access_token !== 'string') {
      const reason = `${data.error ?? res.status}${data.error_description ? `: ${data.error_description}` : ''}`;
      throw new Error(
        data.error === 'invalid_grant'
          ? `${MAIL_OAUTH_LABELS[provider]} access was revoked or expired — reconnect this account in the web interface (${reason})`
          : `${MAIL_OAUTH_LABELS[provider]} token request failed (${reason})`
      );
    }
    return data;
  }

  /** Authorization code → tokens + the mailbox address from the ID token. */
  async exchangeCode(provider: MailOAuthProviderId, code: string, codeVerifier: string, redirectUri: string): Promise<TokenSet & { email?: string; name?: string }> {
    const data = await this.token(provider, { grant_type: 'authorization_code', code, code_verifier: codeVerifier, redirect_uri: redirectUri });
    if (typeof data.refresh_token !== 'string') throw new Error(`${MAIL_OAUTH_LABELS[provider]} did not return a refresh token`);
    let email: string | undefined;
    let name: string | undefined;
    if (typeof data.id_token === 'string') {
      // Received directly from the token endpoint over TLS: no signature check needed (OIDC Core 3.1.3.7).
      const claims = decodeJwt(data.id_token);
      const raw = claims.email ?? claims.preferred_username ?? claims.upn;
      email = typeof raw === 'string' && raw.includes('@') ? raw.toLowerCase() : undefined;
      name = typeof claims.name === 'string' ? claims.name : undefined;
    }
    const set: TokenSet = {
      accessToken: data.access_token as string,
      expiresAt: Date.now() + Number(data.expires_in ?? 3600) * 1000,
      refreshToken: data.refresh_token
    };
    this.cache.set(this.key(data.refresh_token), set);
    return { ...set, email, name };
  }

  private key(refreshToken: string): string {
    return createHash('sha256').update(refreshToken).digest('base64url');
  }

  /**
   * A valid access token for a stored refresh token. `onRotate` receives a new
   * refresh token when the provider rotates it (Microsoft does on every refresh).
   */
  async accessToken(provider: MailOAuthProviderId, refreshToken: string, onRotate?: (next: string) => void): Promise<string> {
    const key = this.key(refreshToken);
    const cached = this.cache.get(key);
    if (cached && cached.expiresAt - 60_000 > Date.now()) return cached.accessToken;
    let pending = this.inflight.get(key);
    if (!pending) {
      pending = this.token(provider, { grant_type: 'refresh_token', refresh_token: refreshToken })
        .then(data => {
          const set: TokenSet = {
            accessToken: data.access_token as string,
            expiresAt: Date.now() + Number(data.expires_in ?? 3600) * 1000,
            refreshToken: typeof data.refresh_token === 'string' ? data.refresh_token : undefined
          };
          this.cache.set(key, set);
          if (set.refreshToken && set.refreshToken !== refreshToken) {
            this.cache.set(this.key(set.refreshToken), set);
            try {
              onRotate?.(set.refreshToken);
            } catch (err) {
              log.error('Failed to persist a rotated refresh token', err);
            }
          }
          return set;
        })
        .finally(() => this.inflight.delete(key));
      this.inflight.set(key, pending);
    }
    return (await pending).accessToken;
  }
}
