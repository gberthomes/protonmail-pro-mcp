/**
 * Web interface (/admin): sign in with the OIDC provider, add and test Proton
 * accounts, decide who may use them, connect MCP clients, revoke connected apps.
 *
 * Plain HTML/CSS/JS served from /public — no build step, no framework.
 */

import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import express, { type NextFunction, type Request, type Response, type Router } from 'express';
import * as z from 'zod/v4';

import type { OAuthBridge } from '../auth/oauth-server.js';
import { LOCAL_PRINCIPAL, ownRule, type AccessPolicy, type Principal } from '../auth/principal.js';
import type { AppConfig, Endpoint } from '../config.js';
import { createLogger } from '../logger.js';
import { ProtonAccount } from '../mail/account.js';
import { ACCOUNT_ID_PATTERN, type AccountDirectory, type AccountEntry, type AccountInput } from '../mail/directory.js';
import { VERSION } from '../version.js';

const log = createLogger('admin');

export interface AdminDeps {
  config: AppConfig;
  directory: AccountDirectory;
  policy: AccessPolicy;
  bridge?: OAuthBridge;
  /** Serve without sign-in (server bound to loopback without authentication). */
  localMode: boolean;
}

const PUBLIC_DIR = fileURLToPath(new URL('../../public/admin/', import.meta.url));

const endpointSchema = z.object({
  host: z.string().trim().min(1).max(253).regex(/^[A-Za-z0-9.:[\]_-]+$/, 'Invalid host'),
  port: z.coerce.number().int().min(1).max(65535),
  security: z.enum(['starttls', 'tls', 'none']),
  verifyTls: z.boolean().default(false)
});

const accountSchema = z.object({
  id: z.string().trim().toLowerCase().optional(),
  email: z.email().trim().toLowerCase(),
  displayName: z.string().trim().max(100).optional(),
  username: z.string().trim().max(254).optional(),
  password: z.string().max(500).optional(),
  imap: endpointSchema.optional(),
  smtp: endpointSchema.optional(),
  users: z.array(z.string().trim().min(1).max(254)).max(100).optional()
});

type AccountBody = z.infer<typeof accountSchema>;

declare module 'express-serve-static-core' {
  interface Request {
    adminPrincipal?: Principal;
  }
}

function slugify(email: string): string {
  return (
    email
      .split('@')[0]!
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 32) || 'account'
  );
}

function toEndpoint(e: z.infer<typeof endpointSchema>, base: Endpoint): Endpoint {
  return { host: e.host, port: e.port, security: e.security, rejectUnauthorized: e.verifyTls, ca: e.host === base.host ? base.ca : undefined };
}

function endpointView(e: Endpoint) {
  return { host: e.host, port: e.port, security: e.security, verifyTls: e.rejectUnauthorized };
}

export function adminRouter(deps: AdminDeps): Router {
  const { config, directory, policy, bridge, localMode } = deps;
  const r = express.Router();
  const base = config.http.publicUrl.origin;
  const signInAvailable = Boolean(bridge) || localMode;

  if (!existsSync(PUBLIC_DIR)) log.warn(`Web interface assets not found in ${PUBLIC_DIR}`);

  const securityHeaders = (_req: Request, res: Response, next: NextFunction) => {
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    );
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'same-origin');
    next();
  };

  r.use('/admin/assets', securityHeaders, express.static(PUBLIC_DIR, { index: false, maxAge: '1h', fallthrough: false }));

  r.get(['/admin', '/admin/'], securityHeaders, (_req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.sendFile('index.html', { root: PUBLIC_DIR });
  });

  r.get('/admin/login', async (req, res) => {
    if (localMode) return res.redirect(302, '/admin');
    if (!bridge) {
      res.status(404).send('Web sign-in requires MCP_AUTH=oidc');
      return;
    }
    try {
      await bridge.beginAdminLogin(req, res, '/admin');
    } catch (err) {
      log.error('cannot start web sign-in', err);
      res.status(503).send('Identity provider unavailable');
    }
  });

  // ------------------------------------------------------------------ API

  const api = express.Router();
  api.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    // CSRF: browsers cannot send this header cross-site without a CORS preflight, which Origin validation refuses.
    if (req.method !== 'GET' && req.headers['x-pmcp'] !== '1') {
      res.status(403).json({ error: 'Missing X-PMCP header' });
      return;
    }
    next();
  });

  api.use(async (req, res, next) => {
    const principal = localMode ? LOCAL_PRINCIPAL : bridge ? await bridge.readAdminSession(req) : undefined;
    if (!principal) {
      res.status(401).json({ error: 'Sign in required', login: signInAvailable ? '/admin/login' : undefined });
      return;
    }
    if (!policy.mayConnect(principal)) {
      res.status(403).json({ error: 'You are not allowed to use this server' });
      return;
    }
    req.adminPrincipal = principal;
    next();
  });

  const me = (req: Request) => req.adminPrincipal!;
  const isAdmin = (req: Request) => policy.isAdmin(me(req));
  const canEdit = (req: Request, a: AccountEntry) => a.source === 'ui' && (isAdmin(req) || a.owner === me(req).sub);

  const view = (req: Request, a: AccountEntry) => {
    const admin = isAdmin(req);
    return {
      id: a.id,
      email: a.email,
      displayName: a.displayName,
      username: a.username,
      source: a.source,
      owner: a.ownerEmail ?? (a.owner && a.owner !== me(req).sub ? a.owner : undefined),
      mine: a.owner === me(req).sub,
      users: a.users ?? [],
      usesGlobalRules: !a.users || a.users.length === 0,
      imap: admin ? endpointView(a.imap) : undefined,
      smtp: admin ? endpointView(a.smtp) : undefined,
      editable: canEdit(req, a),
      usable: policy.accountsFor(me(req)).some(x => x.id === a.id)
    };
  };

  const visible = (req: Request) => {
    const usable = new Set(policy.accountsFor(me(req)).map(a => a.id));
    return directory.list().filter(a => isAdmin(req) || usable.has(a.id) || a.owner === me(req).sub);
  };

  /** Turn a request body into a validated account, applying non-admin restrictions. */
  const toInput = (req: Request, body: AccountBody, existing?: AccountEntry): AccountInput => {
    const admin = isAdmin(req);
    const p = me(req);
    let id = body.id || existing?.id || slugify(body.email);
    if (!existing && !body.id) {
      const taken = new Set(directory.list().map(a => a.id));
      for (let i = 2; taken.has(id); i++) id = `${slugify(body.email)}-${i}`;
    }
    if (!ACCOUNT_ID_PATTERN.test(id)) throw new Error('The id may only contain a-z, 0-9, "-" and "_" (max 40)');
    const conflict = directory.isTaken(id, body.email, existing?.id);
    if (conflict) throw new Error(conflict);

    let users = body.users ?? existing?.users ?? (p.via === 'local' ? [] : [ownRule(p)]);
    if (!admin && p.via !== 'local') {
      // Non-admins always keep access to their own accounts.
      if (!users.some(u => u.toLowerCase() === ownRule(p).toLowerCase())) users = [ownRule(p), ...users];
    }
    users = [...new Set(users.map(u => u.trim()).filter(Boolean))];

    const imap = admin && body.imap ? toEndpoint(body.imap, config.bridge.imap) : (existing?.imap ?? config.bridge.imap);
    const smtp = admin && body.smtp ? toEndpoint(body.smtp, config.bridge.smtp) : (existing?.smtp ?? config.bridge.smtp);
    return {
      id,
      email: body.email,
      displayName: body.displayName || undefined,
      username: body.username || body.email,
      password: body.password || undefined,
      imap,
      smtp,
      users
    };
  };

  const parse = (req: Request, res: Response): AccountBody | undefined => {
    const parsed = accountSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.issues.map(i => `${i.path.join('.') || 'body'}: ${i.message}`).join('; ') });
      return undefined;
    }
    return parsed.data;
  };

  const testLimiter = new Map<string, { n: number; reset: number }>();
  const allowTest = (sub: string) => {
    const now = Date.now();
    const e = testLimiter.get(sub);
    if (!e || e.reset < now) {
      testLimiter.set(sub, { n: 1, reset: now + 60_000 });
      return true;
    }
    return ++e.n <= 20;
  };

  const runTest = async (cfg: AccountInput & { password: string }) => {
    const probe = new ProtonAccount({ ...cfg });
    let timer: NodeJS.Timeout | undefined;
    try {
      return await Promise.race([
        probe.status(),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error('Timed out after 20 s')), 20_000);
        })
      ]);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { imap: { ok: false, error: message }, smtp: { ok: false, error: message } };
    } finally {
      clearTimeout(timer);
      await probe.close();
    }
  };

  api.get('/me', (req, res) => {
    const p = me(req);
    res.json({
      version: VERSION,
      user: { sub: p.sub, email: p.email, name: p.name, via: p.via },
      admin: isAdmin(req),
      selfService: policy.canSelfService(p),
      local: localMode,
      authMode: config.auth.mode,
      mcpUrl: `${base}/mcp`,
      sseUrl: config.http.legacySse ? `${base}/sse` : undefined,
      bridge: isAdmin(req) ? { imap: endpointView(config.bridge.imap), smtp: endpointView(config.bridge.smtp) } : undefined,
      ownRule: ownRule(p),
      appsSupported: Boolean(bridge)
    });
  });

  api.get('/accounts', (req, res) => {
    res.json({ accounts: visible(req).map(a => view(req, a)) });
  });

  api.post('/accounts', (req, res) => {
    if (!policy.canSelfService(me(req))) {
      res.status(403).json({ error: 'You may not add accounts' });
      return;
    }
    const body = parse(req, res);
    if (!body) return;
    try {
      const created = directory.create(toInput(req, body), { sub: me(req).sub, email: me(req).email });
      res.status(201).json(view(req, created));
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
    }
  });

  api.put('/accounts/:id', (req, res) => {
    const existing = directory.get(String(req.params.id));
    if (!existing || !canEdit(req, existing)) {
      res.status(404).json({ error: 'Account not found or read-only' });
      return;
    }
    const body = parse(req, res);
    if (!body) return;
    try {
      res.json(view(req, directory.update(existing.id, toInput(req, body, existing))));
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
    }
  });

  api.delete('/accounts/:id', (req, res) => {
    const existing = directory.get(String(req.params.id));
    if (!existing || !canEdit(req, existing)) {
      res.status(404).json({ error: 'Account not found or read-only' });
      return;
    }
    directory.remove(existing.id);
    res.status(204).end();
  });

  /** Test credentials before saving (or a saved account when only its id is given). */
  api.post('/accounts/test', async (req, res) => {
    if (!allowTest(me(req).sub)) {
      res.status(429).json({ error: 'Too many tests, wait a minute' });
      return;
    }
    const savedId = typeof req.body?.savedId === 'string' ? req.body.savedId : undefined;
    const saved = savedId ? directory.get(savedId) : undefined;
    if (savedId) {
      const allowed = saved && (canEdit(req, saved) || isAdmin(req) || policy.accountsFor(me(req)).some(a => a.id === saved.id));
      if (!allowed) {
        res.status(404).json({ error: 'Account not found' });
        return;
      }
      if (!req.body?.email) {
        res.json(await runTest({ ...saved, users: saved.users ?? [] }));
        return;
      }
    }
    const body = parse(req, res);
    if (!body) return;
    const password = body.password || (saved && canEdit(req, saved) ? saved.password : undefined);
    if (!password) {
      res.status(400).json({ error: 'Enter the Bridge password to test the connection' });
      return;
    }
    const admin = isAdmin(req);
    res.json(
      await runTest({
        id: 'test',
        email: body.email,
        username: body.username || body.email,
        password,
        displayName: body.displayName,
        imap: admin && body.imap ? toEndpoint(body.imap, config.bridge.imap) : (saved?.imap ?? config.bridge.imap),
        smtp: admin && body.smtp ? toEndpoint(body.smtp, config.bridge.smtp) : (saved?.smtp ?? config.bridge.smtp),
        users: []
      })
    );
  });

  api.get('/apps', (req, res) => {
    res.json({ apps: bridge ? bridge.connectedApps(me(req).sub) : [] });
  });

  api.delete('/apps/:clientId', (req, res) => {
    const n = bridge ? bridge.revokeApp(me(req).sub, String(req.params.clientId)) : 0;
    res.status(n ? 204 : 404).end();
  });

  api.post('/logout', (_req, res) => {
    bridge?.clearAdminSession(res);
    res.status(204).end();
  });

  r.use('/admin/api', express.json({ limit: '64kb' }), api);
  return r;
}
