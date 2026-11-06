/**
 * Upstream OpenID Connect provider (Keycloak, Authentik, Authelia, Zitadel,
 * Pocket ID, Google, Microsoft Entra ID, Auth0, Okta, ...).
 */

import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from 'jose';

import type { OidcConfig } from '../config.js';
import { createLogger } from '../logger.js';
import type { Principal } from './principal.js';

const log = createLogger('oidc');

export interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri: string;
  end_session_endpoint?: string;
  code_challenge_methods_supported?: string[];
  authorization_response_iss_parameter_supported?: boolean;
  [key: string]: unknown;
}

const strip = (s: string) => s.replace(/\/+$/, '');

export class OidcProvider {
  private discovery?: Promise<OidcDiscovery>;
  private jwks?: ReturnType<typeof createRemoteJWKSet>;

  constructor(readonly cfg: OidcConfig) {}

  async metadata(): Promise<OidcDiscovery> {
    if (!this.discovery) {
      this.discovery = (async () => {
        const url = `${strip(this.cfg.issuer)}/.well-known/openid-configuration`;
        const res = await fetch(url, { signal: AbortSignal.timeout(10_000), headers: { accept: 'application/json' } });
        if (!res.ok) throw new Error(`OIDC discovery failed: ${url} returned HTTP ${res.status}`);
        const doc = (await res.json()) as OidcDiscovery;
        if (strip(doc.issuer) !== strip(this.cfg.issuer)) {
          throw new Error(`OIDC discovery issuer mismatch: configured ${this.cfg.issuer}, provider says ${doc.issuer}`);
        }
        log.info(`Discovered OIDC provider ${doc.issuer}`);
        return doc;
      })().catch(err => {
        this.discovery = undefined;
        throw err;
      });
    }
    return this.discovery;
  }

  private async keys(): Promise<JWTVerifyGetKey> {
    const md = await this.metadata();
    this.jwks ??= createRemoteJWKSet(new URL(md.jwks_uri), { cooldownDuration: 30_000, cacheMaxAge: 10 * 60_000 });
    const jwks = this.jwks;
    const secret = this.cfg.clientSecret ? new TextEncoder().encode(this.cfg.clientSecret) : undefined;
    return (header, token) => {
      // A few providers sign ID tokens with the client secret (HS256).
      if (header.alg?.startsWith('HS')) {
        if (!secret) throw new Error('HS-signed ID token but no client secret configured');
        return secret;
      }
      return jwks(header, token);
    };
  }

  async authorizationUrl(params: { redirectUri: string; state: string; nonce: string; codeChallenge: string }): Promise<string> {
    const md = await this.metadata();
    const url = new URL(md.authorization_endpoint);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', this.cfg.clientId);
    url.searchParams.set('redirect_uri', params.redirectUri);
    url.searchParams.set('scope', this.cfg.scopes.join(' '));
    url.searchParams.set('state', params.state);
    url.searchParams.set('nonce', params.nonce);
    url.searchParams.set('code_challenge', params.codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    return url.href;
  }

  /** Exchange the upstream code, verify the ID token and build the principal. */
  async completeLogin(params: { code: string; redirectUri: string; codeVerifier: string; nonce: string; iss?: string }): Promise<Principal> {
    const md = await this.metadata();
    if (params.iss !== undefined && strip(params.iss) !== strip(md.issuer)) {
      throw new Error('Authorization response "iss" does not match the identity provider (RFC 9207)');
    }

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: params.code,
      redirect_uri: params.redirectUri,
      code_verifier: params.codeVerifier
    });
    const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' };
    if (this.cfg.tokenAuthMethod === 'client_secret_basic' && this.cfg.clientSecret) {
      headers.authorization = `Basic ${Buffer.from(`${encodeURIComponent(this.cfg.clientId)}:${encodeURIComponent(this.cfg.clientSecret)}`).toString('base64')}`;
    } else {
      body.set('client_id', this.cfg.clientId);
      if (this.cfg.tokenAuthMethod === 'client_secret_post' && this.cfg.clientSecret) body.set('client_secret', this.cfg.clientSecret);
    }
    const res = await fetch(md.token_endpoint, { method: 'POST', headers, body, signal: AbortSignal.timeout(15_000) });
    const tokens = (await res.json().catch(() => ({}))) as { id_token?: string; access_token?: string; error?: string; error_description?: string };
    if (!res.ok || !tokens.id_token) {
      throw new Error(`Identity provider token exchange failed: ${tokens.error ?? res.status} ${tokens.error_description ?? ''}`.trim());
    }

    const { payload } = await jwtVerify(tokens.id_token, await this.keys(), {
      issuer: md.issuer,
      audience: this.cfg.clientId,
      clockTolerance: 60
    });
    if (payload.nonce !== params.nonce) throw new Error('ID token nonce mismatch');

    let claims: Record<string, unknown> = { ...payload };
    const needsUserinfo = !claims.email || claims[this.cfg.groupsClaim] === undefined;
    if (needsUserinfo && md.userinfo_endpoint && tokens.access_token) {
      try {
        const ui = await fetch(md.userinfo_endpoint, {
          headers: { authorization: `Bearer ${tokens.access_token}`, accept: 'application/json' },
          signal: AbortSignal.timeout(10_000)
        });
        if (ui.ok) {
          const info = (await ui.json()) as Record<string, unknown>;
          if (info.sub === payload.sub) claims = { ...info, ...claims, ...(claims.email ? {} : { email: info.email, email_verified: info.email_verified }) };
          if (claims[this.cfg.groupsClaim] === undefined && info[this.cfg.groupsClaim] !== undefined) claims[this.cfg.groupsClaim] = info[this.cfg.groupsClaim];
        }
      } catch (err) {
        log.warn('userinfo request failed', err instanceof Error ? err.message : err);
      }
    }
    return principalFromClaims(claims, this.cfg.groupsClaim);
  }

  /** oidc-resource mode: verify an access token issued by the upstream provider for this server. */
  async verifyAccessToken(token: string, audience: string): Promise<{ payload: JWTPayload; principal: Principal }> {
    const md = await this.metadata();
    const { payload } = await jwtVerify(token, await this.keys(), { issuer: md.issuer, audience, clockTolerance: 30 });
    return { payload, principal: principalFromClaims(payload as Record<string, unknown>, this.cfg.groupsClaim) };
  }
}

function readPath(obj: Record<string, unknown>, path: string): unknown {
  // Supports nested claims such as "realm_access.roles" (Keycloak).
  return path.split('.').reduce<unknown>((acc, key) => (acc && typeof acc === 'object' ? (acc as Record<string, unknown>)[key] : undefined), obj);
}

export function principalFromClaims(claims: Record<string, unknown>, groupsClaim: string): Principal {
  const sub = typeof claims.sub === 'string' ? claims.sub : undefined;
  if (!sub) throw new Error('Token has no "sub" claim');
  // Never trust an address the provider explicitly marks as unverified.
  const email =
    typeof claims.email === 'string' && claims.email_verified !== false && claims.email_verified !== 'false'
      ? claims.email.toLowerCase()
      : undefined;
  const rawGroups = readPath(claims, groupsClaim);
  const groups = Array.isArray(rawGroups)
    ? rawGroups.filter((g): g is string => typeof g === 'string')
    : typeof rawGroups === 'string'
      ? rawGroups.split(/[ ,]+/).filter(Boolean)
      : [];
  const name = typeof claims.name === 'string' ? claims.name : typeof claims.preferred_username === 'string' ? claims.preferred_username : undefined;
  return { sub, email, name, groups, via: 'oidc' };
}
