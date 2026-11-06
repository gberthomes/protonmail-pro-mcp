/**
 * HTTP(S) serving.
 *
 * - POST /mcp      Streamable HTTP. Serves the stateless 2026-07-28 revision
 *                  per request and 2025-era clients (initialize handshake)
 *                  statelessly from the same endpoint.
 * - GET  /sse      Deprecated HTTP+SSE transport (2024-11-05) for old clients,
 *   POST /messages enabled unless MCP_LEGACY_SSE=false.
 * - OAuth:         RFC 9728 protected resource metadata, and with MCP_AUTH=oidc
 *                  the built-in authorization server bridging to your IdP.
 */

import { readFileSync } from 'node:fs';
import { createServer as createHttpServer, type Server as NodeServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { timingSafeEqual } from 'node:crypto';

import type { NextFunction, Request, Response } from 'express';
import { createMcpExpressApp, getOAuthProtectedResourceMetadataUrl, requireBearerAuth } from '@modelcontextprotocol/express';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { createMcpHandler, localhostAllowedOrigins, OAuthError, OAuthErrorCode, type AuthInfo, type OAuthTokenVerifier } from '@modelcontextprotocol/server';
import { SSEServerTransport } from '@modelcontextprotocol/server-legacy/sse';

import { OidcProvider } from './auth/oidc.js';
import { MCP_SCOPE, OAuthBridge } from './auth/oauth-server.js';
import { LOCAL_PRINCIPAL, type Principal } from './auth/principal.js';
import { isLoopbackHost, type AppConfig } from './config.js';
import { createLogger } from './logger.js';
import { buildServer, type ServerDeps } from './server.js';
import { VERSION } from './version.js';

const log = createLogger('http');

export interface RunningHttpServer {
  server: NodeServer;
  close(): Promise<void>;
}

function principalOf(auth: AuthInfo | undefined): Principal {
  const p = auth?.extra?.principal as Principal | undefined;
  return p ?? LOCAL_PRINCIPAL;
}

export async function startHttp(config: AppConfig, deps: ServerDeps): Promise<RunningHttpServer> {
  const { http, auth } = config;
  const base = http.publicUrl.origin;
  const mcpUrl = new URL('/mcp', base);
  const sseUrl = new URL('/sse', base);

  const authEnabled = auth.mode !== 'none' || auth.apiKeys.size > 0;
  if (!authEnabled && !isLoopbackHost(http.host) && process.env.MCP_ALLOW_UNAUTHENTICATED !== 'true') {
    throw new Error(
      `Refusing to serve mailboxes on ${http.host} without authentication. Configure OIDC (OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET) or MCP_API_KEYS, ` +
        'or bind to 127.0.0.1. Set MCP_ALLOW_UNAUTHENTICATED=true only behind an authenticating reverse proxy.'
    );
  }
  if (authEnabled && deps.policy.hasNoRules() && auth.mode !== 'none') {
    log.warn('No access rule configured (MCP_ALLOWED_USERS or per-account "users"): every OIDC login will be refused.');
  }

  const app = createMcpExpressApp({
    host: http.host,
    allowedHosts: http.allowedHosts,
    allowedOrigins: [...localhostAllowedOrigins(), http.publicUrl.hostname, ...http.allowedOrigins],
    jsonLimit: '30mb'
  });
  app.disable('x-powered-by');
  app.set('trust proxy', http.trustProxy);

  // CORS for browser-based MCP clients (Origin itself is validated above).
  app.use((req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin;
    if (origin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Expose-Headers', 'WWW-Authenticate, Mcp-Session-Id, MCP-Protocol-Version');
      if (req.method === 'OPTIONS') {
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] ?? 'authorization, content-type');
        res.setHeader('Access-Control-Max-Age', '600');
        res.status(204).end();
        return;
      }
    }
    next();
  });

  // ---------------------------------------------------------------- auth

  let bridge: OAuthBridge | undefined;
  let upstream: OidcProvider | undefined;
  let authorizationServers: string[] = [];
  let scopesSupported: string[] | undefined;

  if (auth.mode === 'oidc') {
    bridge = new OAuthBridge(config, deps.policy, [mcpUrl.href, sseUrl.href]);
    app.use(bridge.router());
    authorizationServers = [bridge.issuer];
    scopesSupported = [MCP_SCOPE];
    // Fail fast on a misconfigured IdP, but do not prevent startup if it is briefly unreachable.
    bridge.upstream.metadata().catch(err => log.error('Identity provider discovery failed (will retry on first login)', err instanceof Error ? err.message : err));
  } else if (auth.mode === 'oidc-resource') {
    upstream = new OidcProvider(auth.oidc!);
    const md = await upstream.metadata();
    authorizationServers = [md.issuer];
    scopesSupported = auth.oidc!.scopes;
  }

  const apiKeys = [...auth.apiKeys.entries()].map(([k, who]) => ({ key: Buffer.from(k), who }));

  const verifier: OAuthTokenVerifier = {
    async verifyAccessToken(token: string): Promise<AuthInfo> {
      const candidate = Buffer.from(token);
      for (const { key, who } of apiKeys) {
        if (candidate.length === key.length && timingSafeEqual(candidate, key)) {
          const principal: Principal = { sub: `api-key:${who}`, email: who.includes('@') ? who.toLowerCase() : undefined, name: who, groups: [], via: 'api-key' };
          return { token, clientId: `api-key:${who}`, scopes: [MCP_SCOPE], expiresAt: Math.floor(Date.now() / 1000) + 3600, extra: { principal } };
        }
      }
      if (bridge) return bridge.verifyAccessToken(token);
      if (upstream) {
        const audience = auth.oidc!.audience ?? mcpUrl.href;
        try {
          const { payload, principal } = await upstream.verifyAccessToken(token, audience);
          if (deps.policy.accountsFor(principal).length === 0) throw new Error('no account');
          return {
            token,
            clientId: String(payload.client_id ?? payload.azp ?? ''),
            scopes: String(payload.scope ?? '').split(' ').filter(Boolean),
            expiresAt: payload.exp,
            extra: { principal }
          };
        } catch {
          throw new OAuthError(OAuthErrorCode.InvalidToken, 'Invalid or expired access token');
        }
      }
      throw new OAuthError(OAuthErrorCode.InvalidToken, 'Invalid access token');
    }
  };

  const protect = (resource: URL) =>
    authEnabled
      ? requireBearerAuth({
          verifier,
          requiredScopes: bridge ? [MCP_SCOPE] : undefined,
          resourceMetadataUrl: authorizationServers.length ? getOAuthProtectedResourceMetadataUrl(resource) : undefined
        })
      : (_req: Request, _res: Response, next: NextFunction) => next();

  // RFC 9728 protected resource metadata (path-aware + root fallback).
  if (authorizationServers.length) {
    const prm = (resource: URL) => (_req: Request, res: Response) => {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.json({
        resource: resource.href,
        authorization_servers: authorizationServers,
        scopes_supported: scopesSupported,
        bearer_methods_supported: ['header'],
        resource_name: 'Proton Mail MCP',
        resource_documentation: 'https://github.com/gberthomes/protonmail-pro-mcp#readme'
      });
    };
    app.get('/.well-known/oauth-protected-resource/mcp', prm(mcpUrl));
    app.get('/.well-known/oauth-protected-resource/sse', prm(sseUrl));
    app.get('/.well-known/oauth-protected-resource', prm(mcpUrl));
  }

  // ---------------------------------------------------------------- misc routes

  app.get('/healthz', (_req, res) => {
    res.json({ status: 'ok', version: VERSION });
  });

  app.get('/', (_req, res) => {
    res.json({
      name: 'protonmail-pro-mcp',
      version: VERSION,
      mcp: mcpUrl.href,
      legacySse: http.legacySse ? sseUrl.href : undefined,
      auth: auth.mode === 'none' ? (apiKeys.length ? 'api-key' : 'none') : auth.mode,
      accounts: deps.registry.all().length
    });
  });

  // ---------------------------------------------------------------- Streamable HTTP

  const handler = createMcpHandler(({ authInfo }) => buildServer(principalOf(authInfo), deps), {
    onerror: err => log.debug('MCP request rejected', err.message)
  });
  const node = toNodeHandler(handler, { onerror: err => log.error('MCP handler error', err) });
  app.all('/mcp', protect(mcpUrl), (req: Request, res: Response) => {
    res.setHeader('X-Accel-Buffering', 'no');
    void node(req, res, req.body);
  });

  // ---------------------------------------------------------------- deprecated HTTP+SSE

  const sseSessions = new Map<string, { transport: SSEServerTransport; sub: string }>();
  if (http.legacySse) {
    app.get('/sse', protect(sseUrl), async (req: Request, res: Response) => {
      const principal = principalOf(req.auth);
      res.setHeader('X-Accel-Buffering', 'no');
      const transport = new SSEServerTransport('/messages', res);
      sseSessions.set(transport.sessionId, { transport, sub: principal.sub });
      transport.onclose = () => sseSessions.delete(transport.sessionId);
      const keepAlive = setInterval(() => {
        if (!res.writableEnded) res.write(':\n\n');
      }, 25_000);
      res.on('close', () => clearInterval(keepAlive));
      try {
        await buildServer(principal, deps).connect(transport);
      } catch (err) {
        log.error('SSE session failed', err);
        sseSessions.delete(transport.sessionId);
      }
    });
    app.post('/messages', protect(sseUrl), async (req: Request, res: Response) => {
      const id = typeof req.query.sessionId === 'string' ? req.query.sessionId : undefined;
      const session = id ? sseSessions.get(id) : undefined;
      if (!session) {
        res.status(404).json({ error: 'Unknown or expired SSE session' });
        return;
      }
      if (session.sub !== principalOf(req.auth).sub) {
        res.status(403).json({ error: 'This SSE session belongs to another user' });
        return;
      }
      await session.transport.handlePostMessage(req, res, req.body);
    });
  }

  // ---------------------------------------------------------------- listen

  const server =
    http.tlsCertFile && http.tlsKeyFile
      ? createHttpsServer({ cert: readFileSync(http.tlsCertFile), key: readFileSync(http.tlsKeyFile), minVersion: 'TLSv1.2' }, app)
      : createHttpServer(app);
  server.headersTimeout = 65_000;
  server.requestTimeout = 0; // long-lived SSE streams

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(http.port, http.host, () => resolve());
  });

  const scheme = http.tlsCertFile ? 'https' : 'http';
  log.info(`Listening on ${scheme}://${http.host}:${http.port} — public MCP endpoint ${mcpUrl.href}`);
  log.info(`Auth: ${auth.mode}${apiKeys.length ? ` + ${apiKeys.length} API key(s)` : ''}; accounts: ${deps.registry.all().map(a => a.id).join(', ') || 'none'}`);
  if (http.publicUrl.protocol !== 'https:' && !isLoopbackHost(http.publicUrl.hostname)) {
    log.warn('PUBLIC_URL is not HTTPS: MCP clients will refuse OAuth. Use TLS_CERT_FILE/TLS_KEY_FILE or a TLS reverse proxy.');
  }

  return {
    server,
    async close() {
      for (const s of sseSessions.values()) await s.transport.close().catch(() => undefined);
      await handler.close().catch(() => undefined);
      bridge?.close();
      await new Promise<void>(resolve => server.close(() => resolve()));
    }
  };
}
