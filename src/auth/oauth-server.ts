/**
 * Built-in OAuth 2.1 authorization server that bridges MCP clients to any
 * upstream OpenID Connect provider.
 *
 * Why: most identity providers (Google, Entra ID, many self-hosted setups)
 * neither support Client ID Metadata Documents nor Dynamic Client Registration,
 * which MCP clients rely on to connect without manual setup. Here the
 * administrator registers ONE confidential client at their IdP; MCP clients
 * (Claude, ChatGPT, VS Code, Cursor, the Inspector, ...) register against this
 * server with CIMD or DCR, users sign in with the IdP, and this server issues
 * audience-bound access tokens for the MCP endpoint.
 *
 * Implements: RFC 8414 metadata, RFC 9728 protected resource metadata,
 * PKCE S256 (mandatory), RFC 8707 resource indicators, RFC 9207 `iss`,
 * Client ID Metadata Documents, RFC 7591 DCR (deprecated by MCP 2026-07-28,
 * kept for older clients), RFC 7009 revocation, refresh token rotation, and
 * the per-client consent required for proxies with a static upstream client.
 */

import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import express, { type Request, type Response, type Router } from 'express';
import { SignJWT, jwtVerify } from 'jose';
import { OAuthError, OAuthErrorCode, type AuthInfo } from '@modelcontextprotocol/server';

import type { AppConfig } from '../config.js';
import { createLogger } from '../logger.js';
import { fetchClientMetadataDocument, isMetadataDocumentClientId } from './cimd.js';
import { OidcProvider } from './oidc.js';
import { consentPage, messagePage } from './pages.js';
import { AccessPolicy, type Principal } from './principal.js';
import { AuthStore, randomToken, TtlMap, type RegisteredClient } from './store.js';

const log = createLogger('oauth');

export const MCP_SCOPE = 'mail';
const SUPPORTED_SCOPES = [MCP_SCOPE, 'offline_access'];
const BROWSER_COOKIE = 'pmcp_browser';
const CONSENT_COOKIE = 'pmcp_consent';

interface PendingAuthorization {
  client: RegisteredClient;
  redirectUri: string;
  state?: string;
  codeChallenge: string;
  scope: string;
  resource: string;
  browser: string;
  csrf: string;
  upstreamVerifier?: string;
  nonce?: string;
}

interface IssuedCode {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scope: string;
  resource: string;
  principal: Principal;
}

class TokenError extends Error {
  constructor(
    readonly error: string,
    description: string,
    readonly status = 400
  ) {
    super(description);
  }
}

function s256(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

/** RFC 8252 §7.3: loopback redirect URIs match on any port. */
function redirectMatches(requested: string, registered: string): boolean {
  if (requested === registered) return true;
  try {
    const a = new URL(requested);
    const b = new URL(registered);
    return (
      LOOPBACK.has(a.hostname) &&
      a.hostname === b.hostname &&
      a.protocol === b.protocol &&
      a.pathname === b.pathname &&
      a.search === b.search
    );
  } catch {
    return false;
  }
}

function validRedirectUri(uri: string): boolean {
  try {
    const u = new URL(uri);
    if (u.hash) return false;
    if (u.protocol === 'https:') return true;
    if (u.protocol === 'http:') return LOOPBACK.has(u.hostname);
    // Private-use URI schemes for native apps (e.g. cursor://, vscode://)
    return /^[a-z][a-z0-9+.-]*:$/.test(u.protocol) && !['javascript:', 'data:', 'file:', 'vbscript:'].includes(u.protocol);
  } catch {
    return false;
  }
}

function parseCookies(req: Request): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

/** Tiny fixed-window rate limiter keyed by client IP. */
function rateLimit(max: number, windowMs: number) {
  const hits = new Map<string, { count: number; reset: number }>();
  return (req: Request, res: Response, next: () => void) => {
    const key = req.ip ?? 'unknown';
    const now = Date.now();
    let e = hits.get(key);
    if (!e || e.reset < now) {
      e = { count: 0, reset: now + windowMs };
      hits.set(key, e);
      if (hits.size > 10_000) for (const [k, v] of hits) if (v.reset < now) hits.delete(k);
    }
    if (++e.count > max) {
      res.setHeader('Retry-After', Math.ceil((e.reset - now) / 1000));
      res.status(429).json({ error: 'too_many_requests', error_description: 'Rate limit exceeded' });
      return;
    }
    next();
  };
}

export class OAuthBridge {
  readonly issuer: string;
  readonly resources: string[];
  readonly upstream: OidcProvider;
  private readonly store: AuthStore;
  private readonly pending = new TtlMap<PendingAuthorization>();
  private readonly codes = new TtlMap<IssuedCode>();
  private readonly secure: boolean;

  constructor(
    private readonly config: AppConfig,
    private readonly policy: AccessPolicy,
    /** Canonical resource identifiers accepted as token audiences; the first is the primary MCP endpoint. */
    resources: string[]
  ) {
    if (!config.auth.oidc) throw new Error('OIDC configuration missing');
    this.issuer = config.http.publicUrl.origin;
    this.resources = resources;
    this.upstream = new OidcProvider(config.auth.oidc);
    this.store = new AuthStore(config.dataDir, config.auth.signingSecret);
    this.secure = config.http.publicUrl.protocol === 'https:';
  }

  private get callbackUrl(): string {
    return `${this.issuer}/oauth/callback`;
  }

  metadata() {
    const base = this.issuer;
    return {
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      registration_endpoint: this.config.auth.allowDynamicRegistration ? `${base}/register` : undefined,
      revocation_endpoint: `${base}/revoke`,
      scopes_supported: SUPPORTED_SCOPES,
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
      revocation_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
      client_id_metadata_document_supported: this.config.auth.allowClientIdMetadataDocuments,
      authorization_response_iss_parameter_supported: true,
      service_documentation: 'https://github.com/gberthomes/protonmail-pro-mcp#readme'
    };
  }

  // ------------------------------------------------------------------ clients

  private async client(clientId: string): Promise<RegisteredClient | undefined> {
    if (isMetadataDocumentClientId(clientId)) {
      if (!this.config.auth.allowClientIdMetadataDocuments) return undefined;
      return fetchClientMetadataDocument(clientId);
    }
    return this.store.getClient(clientId);
  }

  private async authenticateClient(req: Request): Promise<RegisteredClient> {
    let clientId: string | undefined = typeof req.body?.client_id === 'string' ? req.body.client_id : undefined;
    let secret: string | undefined = typeof req.body?.client_secret === 'string' ? req.body.client_secret : undefined;
    const header = req.headers.authorization;
    if (header?.toLowerCase().startsWith('basic ')) {
      const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
      const i = decoded.indexOf(':');
      if (i < 0) throw new TokenError('invalid_client', 'Malformed Basic credentials', 401);
      clientId = decodeURIComponent(decoded.slice(0, i));
      secret = decodeURIComponent(decoded.slice(i + 1));
    }
    if (!clientId) throw new TokenError('invalid_client', 'client_id is required', 401);
    const client = await this.client(clientId).catch(err => {
      throw new TokenError('invalid_client', `Unknown client: ${err instanceof Error ? err.message : err}`, 401);
    });
    if (!client) throw new TokenError('invalid_client', 'Unknown client', 401);
    if (client.client_secret) {
      if (!secret || !safeEqual(secret, client.client_secret)) throw new TokenError('invalid_client', 'Invalid client credentials', 401);
      if (client.client_secret_expires_at && client.client_secret_expires_at < Date.now() / 1000) {
        throw new TokenError('invalid_client', 'Client secret expired', 401);
      }
    }
    return client;
  }

  // ------------------------------------------------------------------ tokens

  private resolveResource(requested: unknown): string {
    if (requested === undefined || requested === '') return this.resources[0]!;
    const values = Array.isArray(requested) ? requested : [requested];
    if (values.length !== 1 || typeof values[0] !== 'string') throw new TokenError('invalid_target', 'Exactly one resource is supported');
    const value = values[0].replace(/\/+$/, '');
    const match = this.resources.find(r => r === value) ?? (value === this.issuer ? this.resources[0] : undefined);
    if (!match) throw new TokenError('invalid_target', `Unknown resource ${values[0]}`);
    return match;
  }

  private grantedScope(requested?: string): string {
    const asked = (requested ?? '').split(' ').filter(Boolean);
    const scopes = new Set([MCP_SCOPE, ...asked.filter(s => SUPPORTED_SCOPES.includes(s))]);
    return [...scopes].join(' ');
  }

  private async issueTokens(clientId: string, principal: Principal, scope: string, resource: string) {
    const ttl = this.config.auth.accessTokenTtl;
    const accessToken = await new SignJWT({
      client_id: clientId,
      scope,
      email: principal.email,
      name: principal.name,
      groups: principal.groups.length ? principal.groups : undefined,
      via: principal.via
    })
      .setProtectedHeader({ alg: 'HS256', typ: 'at+jwt' })
      .setIssuer(this.issuer)
      .setSubject(principal.sub)
      .setAudience(resource)
      .setIssuedAt()
      .setExpirationTime(`${ttl}s`)
      .setJti(randomToken(12))
      .sign(this.store.signingKey);
    const refreshToken = this.store.issueRefreshToken({
      clientId,
      principal,
      scope,
      resource,
      expiresAt: Math.floor(Date.now() / 1000) + this.config.auth.refreshTokenTtl
    });
    return { access_token: accessToken, token_type: 'Bearer', expires_in: ttl, refresh_token: refreshToken, scope };
  }

  /** OAuthTokenVerifier for requireBearerAuth. */
  async verifyAccessToken(token: string): Promise<AuthInfo> {
    try {
      const { payload } = await jwtVerify(token, this.store.signingKey, { issuer: this.issuer, typ: 'at+jwt', algorithms: ['HS256'] });
      const aud = [payload.aud ?? []].flat();
      const resource = aud.find(a => this.resources.includes(a));
      if (!resource) throw new Error('audience');
      const principal: Principal = {
        sub: payload.sub!,
        email: typeof payload.email === 'string' ? payload.email : undefined,
        name: typeof payload.name === 'string' ? payload.name : undefined,
        groups: Array.isArray(payload.groups) ? (payload.groups as string[]) : [],
        via: payload.via === 'api-key' ? 'api-key' : 'oidc'
      };
      return {
        token,
        clientId: String(payload.client_id ?? ''),
        scopes: String(payload.scope ?? '').split(' ').filter(Boolean),
        expiresAt: payload.exp,
        resource: new URL(resource),
        extra: { principal }
      };
    } catch {
      throw new OAuthError(OAuthErrorCode.InvalidToken, 'Invalid or expired access token');
    }
  }

  // ------------------------------------------------------------------ consent cookie

  private signConsent(ids: string[]): string {
    const payload = Buffer.from(JSON.stringify(ids)).toString('base64url');
    const mac = createHmac('sha256', this.store.cookieKey).update(payload).digest('base64url');
    return `${payload}.${mac}`;
  }

  private readConsent(req: Request): string[] {
    const raw = parseCookies(req)[CONSENT_COOKIE];
    if (!raw) return [];
    const [payload, mac] = raw.split('.');
    if (!payload || !mac) return [];
    const expected = createHmac('sha256', this.store.cookieKey).update(payload).digest('base64url');
    if (!safeEqual(mac, expected)) return [];
    try {
      const ids = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as unknown;
      return Array.isArray(ids) ? ids.filter((x): x is string => typeof x === 'string') : [];
    } catch {
      return [];
    }
  }

  private cookie(res: Response, name: string, value: string, maxAgeSeconds: number): void {
    res.cookie(name, value, {
      httpOnly: true,
      secure: this.secure,
      sameSite: 'lax',
      path: '/',
      maxAge: maxAgeSeconds * 1000
    });
  }

  private browserId(req: Request, res: Response): string {
    const existing = parseCookies(req)[BROWSER_COOKIE];
    if (existing && /^[A-Za-z0-9_-]{20,}$/.test(existing)) return existing;
    const id = randomToken(24);
    this.cookie(res, BROWSER_COOKIE, id, 60 * 60 * 24 * 365);
    return id;
  }

  // ------------------------------------------------------------------ helpers

  private redirectWithError(res: Response, p: { redirectUri: string; state?: string }, error: string, description: string): void {
    const url = new URL(p.redirectUri);
    url.searchParams.set('error', error);
    url.searchParams.set('error_description', description);
    if (p.state !== undefined) url.searchParams.set('state', p.state);
    url.searchParams.set('iss', this.issuer);
    res.redirect(302, url.href);
  }

  private async goUpstream(res: Response, txnId: string, txn: PendingAuthorization): Promise<void> {
    txn.upstreamVerifier = randomToken(32);
    txn.nonce = randomToken(16);
    this.pending.set(txnId, txn, 600);
    const url = await this.upstream.authorizationUrl({
      redirectUri: this.callbackUrl,
      state: txnId,
      nonce: txn.nonce,
      codeChallenge: s256(txn.upstreamVerifier)
    });
    res.redirect(302, url);
  }

  private sendTokenError(res: Response, err: unknown): void {
    if (err instanceof TokenError) {
      if (err.status === 401) res.setHeader('WWW-Authenticate', 'Basic realm="oauth"');
      res.status(err.status).json({ error: err.error, error_description: err.message });
      return;
    }
    log.error('token endpoint failure', err);
    res.status(500).json({ error: 'server_error', error_description: 'Internal error' });
  }

  // ------------------------------------------------------------------ router

  router(): Router {
    const r = express.Router();
    const form = express.urlencoded({ extended: false, limit: '64kb' });
    const noStore = (_req: Request, res: Response, next: () => void) => {
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');
      next();
    };

    r.get('/.well-known/oauth-authorization-server', (_req, res) => {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.json(this.metadata());
    });

    // ---- authorization endpoint
    r.get('/authorize', rateLimit(60, 60_000), noStore, async (req, res) => {
      const q = req.query as Record<string, string | undefined>;
      let client: RegisteredClient | undefined;
      try {
        client = q.client_id ? await this.client(q.client_id) : undefined;
      } catch (err) {
        res.status(400).send(messagePage('Unknown application', `The client could not be verified: ${err instanceof Error ? err.message : err}`));
        return;
      }
      if (!client) {
        res.status(400).send(messagePage('Unknown application', 'This client_id is not registered with this server. Reconnect the application.'));
        return;
      }
      let redirectUri = q.redirect_uri;
      if (redirectUri === undefined) {
        if (client.redirect_uris.length !== 1) {
          res.status(400).send(messagePage('Invalid request', 'redirect_uri is required.'));
          return;
        }
        redirectUri = client.redirect_uris[0]!;
      } else if (!client.redirect_uris.some(reg => redirectMatches(redirectUri!, reg))) {
        res.status(400).send(messagePage('Invalid request', 'This redirect_uri is not registered for the client.'));
        return;
      }
      const target = { redirectUri, state: q.state };
      if (q.response_type !== 'code') return this.redirectWithError(res, target, 'unsupported_response_type', 'Only response_type=code is supported');
      if (!q.code_challenge || q.code_challenge_method !== 'S256') {
        return this.redirectWithError(res, target, 'invalid_request', 'PKCE with code_challenge_method=S256 is required');
      }
      let resource: string;
      try {
        resource = this.resolveResource(q.resource);
      } catch (err) {
        return this.redirectWithError(res, target, 'invalid_target', err instanceof Error ? err.message : 'invalid resource');
      }

      const browser = this.browserId(req, res);
      const txnId = randomToken(24);
      const txn: PendingAuthorization = {
        client,
        redirectUri,
        state: q.state,
        codeChallenge: q.code_challenge,
        scope: this.grantedScope(q.scope),
        resource,
        browser,
        csrf: randomToken(16)
      };

      if (this.readConsent(req).includes(client.client_id)) {
        try {
          await this.goUpstream(res, txnId, txn);
        } catch (err) {
          log.error('upstream redirect failed', err);
          this.redirectWithError(res, target, 'temporarily_unavailable', 'Identity provider unavailable');
        }
        return;
      }

      this.pending.set(txnId, txn, 600);
      const redirect = new URL(redirectUri);
      res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'");
      res.setHeader('X-Frame-Options', 'DENY');
      res.send(
        consentPage({
          clientName: client.client_name ?? (client.metadata_document ? new URL(client.client_id).hostname : 'Unnamed MCP client'),
          clientId: client.client_id,
          redirectHost: redirect.protocol.startsWith('http') ? redirect.host : `${redirect.protocol}//${redirect.host}`,
          verifiedDomain: client.metadata_document ? new URL(client.client_id).hostname : undefined,
          serverName: 'Proton Mail MCP',
          txn: txnId,
          csrf: txn.csrf
        })
      );
    });

    r.post('/authorize/consent', rateLimit(60, 60_000), form, noStore, async (req, res) => {
      const txnId = String(req.body?.txn ?? '');
      const txn = this.pending.get(txnId);
      const browser = parseCookies(req)[BROWSER_COOKIE];
      if (!txn || !browser || !safeEqual(browser, txn.browser) || !safeEqual(String(req.body?.csrf ?? ''), txn.csrf)) {
        res.status(400).send(messagePage('Request expired', 'This authorization request expired or was opened in another browser. Start the connection again.'));
        return;
      }
      if (req.body?.decision !== 'approve') {
        this.pending.take(txnId);
        return this.redirectWithError(res, txn, 'access_denied', 'The user declined the request');
      }
      const approved = [txn.client.client_id, ...this.readConsent(req).filter(id => id !== txn.client.client_id)].slice(0, 20);
      this.cookie(res, CONSENT_COOKIE, this.signConsent(approved), 60 * 60 * 24 * 365);
      try {
        await this.goUpstream(res, txnId, txn);
      } catch (err) {
        log.error('upstream redirect failed', err);
        this.redirectWithError(res, txn, 'temporarily_unavailable', 'Identity provider unavailable');
      }
    });

    // ---- upstream IdP callback
    r.get('/oauth/callback', rateLimit(60, 60_000), noStore, async (req, res) => {
      const q = req.query as Record<string, string | undefined>;
      const txn = q.state ? this.pending.take(q.state) : undefined;
      const browser = parseCookies(req)[BROWSER_COOKIE];
      if (!txn || !txn.upstreamVerifier || !txn.nonce) {
        res.status(400).send(messagePage('Request expired', 'This sign-in expired. Start the connection again from your MCP client.'));
        return;
      }
      if (!browser || !safeEqual(browser, txn.browser)) {
        res.status(400).send(messagePage('Wrong browser', 'Finish the sign-in in the browser where you started it.'));
        return;
      }
      if (q.error) return this.redirectWithError(res, txn, q.error === 'access_denied' ? 'access_denied' : 'server_error', q.error_description ?? q.error);
      if (!q.code) return this.redirectWithError(res, txn, 'server_error', 'Identity provider returned no code');

      let principal: Principal;
      try {
        principal = await this.upstream.completeLogin({
          code: q.code,
          redirectUri: this.callbackUrl,
          codeVerifier: txn.upstreamVerifier,
          nonce: txn.nonce,
          iss: q.iss
        });
      } catch (err) {
        log.warn('upstream login failed', err instanceof Error ? err.message : err);
        return this.redirectWithError(res, txn, 'access_denied', 'Sign-in with the identity provider failed');
      }

      const accounts = this.policy.accountsFor(principal);
      if (accounts.length === 0) {
        log.warn(`Denied ${principal.email ?? principal.sub}: no Proton account is granted to this user`);
        return this.redirectWithError(res, txn, 'access_denied', `${principal.email ?? principal.sub} is not allowed to use any mailbox on this server`);
      }
      log.info(`Authorized ${principal.email ?? principal.sub} for client ${txn.client.client_name ?? txn.client.client_id} (${accounts.length} account(s))`);

      const code = randomToken(32);
      this.codes.set(code, { clientId: txn.client.client_id, redirectUri: txn.redirectUri, codeChallenge: txn.codeChallenge, scope: txn.scope, resource: txn.resource, principal }, 300);
      const url = new URL(txn.redirectUri);
      url.searchParams.set('code', code);
      if (txn.state !== undefined) url.searchParams.set('state', txn.state);
      url.searchParams.set('iss', this.issuer);
      res.redirect(302, url.href);
    });

    // ---- token endpoint
    r.post('/token', rateLimit(120, 60_000), form, express.json({ limit: '64kb' }), noStore, async (req, res) => {
      res.setHeader('Access-Control-Allow-Origin', '*');
      try {
        const client = await this.authenticateClient(req);
        const body = req.body as Record<string, unknown>;
        if (body.grant_type === 'authorization_code') {
          const code = typeof body.code === 'string' ? this.codes.take(body.code) : undefined;
          if (!code || code.clientId !== client.client_id) throw new TokenError('invalid_grant', 'Invalid or expired authorization code');
          if (body.redirect_uri !== undefined && body.redirect_uri !== code.redirectUri) throw new TokenError('invalid_grant', 'redirect_uri mismatch');
          if (typeof body.code_verifier !== 'string' || !safeEqual(s256(body.code_verifier), code.codeChallenge)) {
            throw new TokenError('invalid_grant', 'PKCE verification failed');
          }
          const resource = body.resource !== undefined ? this.resolveResource(body.resource) : code.resource;
          if (resource !== code.resource) throw new TokenError('invalid_target', 'resource differs from the authorization request');
          res.json(await this.issueTokens(client.client_id, code.principal, code.scope, resource));
          return;
        }
        if (body.grant_type === 'refresh_token') {
          const rec = typeof body.refresh_token === 'string' ? this.store.peekRefreshToken(body.refresh_token) : undefined;
          if (!rec || rec.clientId !== client.client_id) throw new TokenError('invalid_grant', 'Invalid refresh token');
          this.store.consumeRefreshToken(body.refresh_token as string);
          if (rec.expiresAt < Date.now() / 1000) throw new TokenError('invalid_grant', 'Refresh token expired');
          if (this.policy.accountsFor(rec.principal).length === 0) throw new TokenError('invalid_grant', 'Access to this server was revoked');
          const resource = body.resource !== undefined ? this.resolveResource(body.resource) : rec.resource;
          res.json(await this.issueTokens(client.client_id, rec.principal, rec.scope, resource));
          return;
        }
        throw new TokenError('unsupported_grant_type', 'Supported grants: authorization_code, refresh_token');
      } catch (err) {
        this.sendTokenError(res, err);
      }
    });

    // ---- revocation (RFC 7009)
    r.post('/revoke', rateLimit(60, 60_000), form, express.json({ limit: '16kb' }), async (req, res) => {
      res.setHeader('Access-Control-Allow-Origin', '*');
      try {
        const client = await this.authenticateClient(req);
        const token = typeof req.body?.token === 'string' ? req.body.token : undefined;
        const rec = token ? this.store.peekRefreshToken(token) : undefined;
        if (rec && rec.clientId === client.client_id) this.store.revokeRefreshToken(token!);
        res.status(200).end();
      } catch (err) {
        this.sendTokenError(res, err);
      }
    });

    // ---- dynamic client registration (RFC 7591, deprecated in MCP 2026-07-28 but still widely used)
    if (this.config.auth.allowDynamicRegistration) {
      r.post('/register', rateLimit(20, 60 * 60_000), express.json({ limit: '32kb' }), noStore, (req, res) => {
        res.setHeader('Access-Control-Allow-Origin', '*');
        const md = (req.body ?? {}) as Record<string, unknown>;
        const redirectUris = md.redirect_uris;
        if (!Array.isArray(redirectUris) || redirectUris.length === 0 || redirectUris.length > 10 || !redirectUris.every(u => typeof u === 'string' && validRedirectUri(u))) {
          res.status(400).json({ error: 'invalid_redirect_uri', error_description: 'redirect_uris must be https, loopback http, or a private-use scheme' });
          return;
        }
        const method = (md.token_endpoint_auth_method as string | undefined) ?? 'client_secret_basic';
        if (!['none', 'client_secret_basic', 'client_secret_post'].includes(method)) {
          res.status(400).json({ error: 'invalid_client_metadata', error_description: `Unsupported token_endpoint_auth_method ${method}` });
          return;
        }
        const grantTypes = Array.isArray(md.grant_types) ? (md.grant_types as string[]) : ['authorization_code', 'refresh_token'];
        if (!grantTypes.includes('authorization_code') || grantTypes.some(g => !['authorization_code', 'refresh_token'].includes(g))) {
          res.status(400).json({ error: 'invalid_client_metadata', error_description: 'Supported grant_types: authorization_code, refresh_token' });
          return;
        }
        const appType = md.application_type === 'native' ? 'native' : md.application_type === 'web' ? 'web' : undefined;
        const client: RegisteredClient = {
          client_id: randomToken(18),
          client_secret: method === 'none' ? undefined : randomToken(32),
          client_id_issued_at: Math.floor(Date.now() / 1000),
          client_secret_expires_at: method === 'none' ? undefined : 0,
          redirect_uris: redirectUris as string[],
          client_name: typeof md.client_name === 'string' ? md.client_name.slice(0, 200) : undefined,
          client_uri: typeof md.client_uri === 'string' ? md.client_uri : undefined,
          logo_uri: typeof md.logo_uri === 'string' ? md.logo_uri : undefined,
          token_endpoint_auth_method: method as RegisteredClient['token_endpoint_auth_method'],
          grant_types: grantTypes,
          response_types: ['code'],
          application_type: appType,
          scope: this.grantedScope(typeof md.scope === 'string' ? md.scope : undefined)
        };
        this.store.saveClient(client);
        log.info(`Registered client "${client.client_name ?? client.client_id}" via DCR`);
        res.status(201).json(client);
      });
    }

    return r;
  }

  close(): void {
    this.store.flushNow();
  }
}
