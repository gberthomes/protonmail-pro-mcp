/**
 * Web interface (/admin): sign in with the OIDC provider, add mailboxes (Proton
 * through Bridge, Gmail, Outlook, iCloud, any IMAP server — with
 * autodiscovery and "Sign in with Google/Microsoft"), test them, decide who may
 * use them, connect MCP clients, revoke connected apps.
 *
 * Plain HTML/CSS/JS served from /public — no build step, no framework.
 */

import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import express, { type NextFunction, type Request, type Response, type Router } from 'express';
import * as z from 'zod/v4';

import type { OAuthBridge } from '../auth/oauth-server.js';
import { LOCAL_PRINCIPAL, ownRule, type AccessPolicy, type Principal } from '../auth/principal.js';
import { randomToken, TtlMap } from '../auth/store.js';
import type { AccountConfig, AppConfig, Endpoint } from '../config.js';
import { createLogger } from '../logger.js';
import { MailAccount } from '../mail/account.js';
import { ACCOUNT_ID_PATTERN, type AccountDirectory, type AccountEntry, type AccountInput } from '../mail/directory.js';
import { discover } from '../mail/discovery.js';
import { MAIL_OAUTH_LABELS, type MailOAuth } from '../mail/oauth.js';
import { providerById, PROVIDERS, type MailOAuthProviderId } from '../mail/providers.js';
import { resolvePublic } from '../net.js';
import { VERSION } from '../version.js';

const log = createLogger('admin');

export interface AdminDeps {
  config: AppConfig;
  directory: AccountDirectory;
  policy: AccessPolicy;
  bridge?: OAuthBridge;
  oauth?: MailOAuth;
  /** Serve without sign-in (server bound to loopback without authentication). */
  localMode: boolean;
}

const PUBLIC_DIR = fileURLToPath(new URL('../../public/admin/', import.meta.url));

const endpointSchema = z.object({
  host: z.string().trim().min(1).max(253).regex(/^[A-Za-z0-9.:[\]_-]+$/, 'Invalid host'),
  port: z.coerce.number().int().min(1).max(65535),
  security: z.enum(['starttls', 'tls', 'none']),
  verifyTls: z.boolean().default(true),
  username: z.string().trim().max(254).optional()
});

const accountSchema = z.object({
  id: z.string().trim().toLowerCase().optional(),
  email: z.email().trim().toLowerCase(),
  displayName: z.string().trim().max(100).optional(),
  username: z.string().trim().max(254).optional(),
  password: z.string().max(500).optional(),
  provider: z.string().max(40).optional(),
  saveSent: z.boolean().optional(),
  imap: endpointSchema.optional(),
  smtp: endpointSchema.optional(),
  users: z.array(z.string().trim().min(1).max(254)).max(100).optional()
});

type AccountBody = z.infer<typeof accountSchema>;

interface PendingMailOAuth {
  sub: string;
  provider: MailOAuthProviderId;
  verifier: string;
  /** Account being reconnected, or the settings of the account to create. */
  accountId?: string;
  draft: Partial<AccountBody>;
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string
  ) {
    super(message);
  }
}

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

function endpointView(e: Endpoint) {
  return { host: e.host, port: e.port, security: e.security, verifyTls: e.rejectUnauthorized, username: e.username };
}

const s256 = (v: string) => createHash('sha256').update(v).digest('base64url');

export function adminRouter(deps: AdminDeps): Router {
  const { config, directory, policy, bridge, oauth, localMode } = deps;
  const r = express.Router();
  const base = config.http.publicUrl.origin;
  const signInAvailable = Boolean(bridge) || localMode;
  const oauthCallback = `${base}/admin/oauth/mail/callback`;
  const pendingOAuth = new TtlMap<PendingMailOAuth>();

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

  const sessionPrincipal = async (req: Request): Promise<Principal | undefined> =>
    localMode ? LOCAL_PRINCIPAL : bridge ? await bridge.readAdminSession(req) : undefined;

  const isAdminP = (p: Principal) => policy.isAdmin(p);

  // ------------------------------------------------------------------ account settings

  /** Build validated settings from a request body, applying the non-admin restrictions. */
  const toInput = async (p: Principal, body: AccountBody, existing?: AccountEntry, opts: { forTest?: boolean } = {}): Promise<AccountInput> => {
    const admin = isAdminP(p);
    let id = body.id || existing?.id || slugify(body.email);
    if (!existing && !body.id) {
      const taken = new Set(directory.list().map(a => a.id));
      for (let i = 2; taken.has(id); i++) id = `${slugify(body.email)}-${i}`;
    }
    if (!ACCOUNT_ID_PATTERN.test(id)) throw new HttpError(400, 'The id may only contain a-z, 0-9, "-" and "_" (max 40)');
    const conflict = opts.forTest ? undefined : directory.isTaken(id, body.email, existing?.id);
    if (conflict) throw new HttpError(400, conflict);

    let users = body.users ?? existing?.users ?? (p.via === 'local' ? [] : [ownRule(p)]);
    if (!admin && p.via !== 'local' && !users.some(u => u.toLowerCase() === ownRule(p).toLowerCase())) users = [ownRule(p), ...users];
    users = [...new Set(users.map(u => u.trim()).filter(Boolean))];

    // Without a provider or servers, an account goes through the server's Proton Mail Bridge.
    const providerId = body.provider ?? existing?.provider ?? (body.imap ? 'custom' : 'proton-bridge');
    const preset = providerById(providerId);
    let imap: Endpoint;
    let smtp: Endpoint;
    let publicOnly = false;
    if (preset?.bridge) {
      // Proton accounts always go through the server's Bridge.
      imap = config.bridge.imap;
      smtp = config.bridge.smtp;
    } else {
      const toEndpoint = (e: z.infer<typeof endpointSchema> | undefined, fallback: Endpoint | undefined, kind: string): Endpoint => {
        if (!e) {
          if (fallback) return fallback;
          throw new HttpError(400, `${kind} server settings are required`);
        }
        return {
          host: e.host.toLowerCase(),
          port: e.port,
          security: e.security,
          rejectUnauthorized: admin ? e.verifyTls : true,
          username: e.username || undefined,
          ca: e.host === config.bridge.imap.host ? config.bridge.imap.ca : undefined
        };
      };
      imap = toEndpoint(body.imap, existing?.imap, 'IMAP');
      smtp = toEndpoint(body.smtp, existing?.smtp, 'SMTP');
      if (!admin) {
        // Non-administrators reach public mail servers only, over TLS, with verified certificates.
        for (const [kind, ep] of [['IMAP', imap], ['SMTP', smtp]] as const) {
          if (ep.security === 'none') throw new HttpError(400, `${kind}: an encrypted connection (TLS or STARTTLS) is required`);
          // Hosts of built-in presets are trusted constants; connections are still checked when they open.
          if (preset && (ep.host === preset.imap?.host || ep.host === preset.smtp?.host)) continue;
          try {
            await resolvePublic(ep.host);
          } catch {
            throw new HttpError(400, `${kind}: ${ep.host} is not a public mail server`);
          }
        }
        publicOnly = true;
      }
    }

    return {
      id,
      email: body.email,
      displayName: body.displayName || undefined,
      username: body.username || existing?.username || body.email,
      password: body.password || undefined,
      provider: preset?.id ?? 'custom',
      saveSent: body.saveSent ?? existing?.saveSent ?? preset?.saveSent ?? !preset?.bridge,
      publicOnly,
      imap,
      smtp,
      users
    };
  };

  const view = (p: Principal, a: AccountEntry) => {
    const admin = isAdminP(p);
    const mine = a.owner === p.sub;
    const editable = a.source === 'ui' && (admin || mine);
    const preset = providerById(a.provider ?? 'proton-bridge');
    return {
      id: a.id,
      email: a.email,
      displayName: a.displayName,
      username: a.username,
      source: a.source,
      provider: preset?.id ?? 'custom',
      providerName: preset?.name ?? 'IMAP',
      auth: a.oauth ? `oauth:${a.oauth.provider}` : 'password',
      saveSent: a.saveSent ?? !preset?.bridge,
      owner: a.ownerEmail ?? (a.owner && !mine ? a.owner : undefined),
      mine,
      users: a.users ?? [],
      // Server settings are shown to whoever may edit them (Bridge settings stay admin-only).
      imap: admin || (editable && !preset?.bridge) ? endpointView(a.imap) : undefined,
      smtp: admin || (editable && !preset?.bridge) ? endpointView(a.smtp) : undefined,
      editable,
      usable: policy.accountsFor(p).some(x => x.id === a.id)
    };
  };

  const canEdit = (p: Principal, a: AccountEntry) => a.source === 'ui' && (isAdminP(p) || a.owner === p.sub);

  const runTest = async (cfg: AccountConfig) => {
    const probe = new MailAccount({ ...cfg }, { oauth });
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

  // ------------------------------------------------------------------ mailbox OAuth (browser redirect)

  r.get('/admin/oauth/mail/callback', async (req, res) => {
    const q = req.query as Record<string, string | undefined>;
    const fail = (message: string) => res.redirect(302, `/admin?error=${encodeURIComponent(message)}`);
    const pending = q.state ? pendingOAuth.take(q.state) : undefined;
    const p = await sessionPrincipal(req);
    if (!pending || !p || p.sub !== pending.sub) return fail('This sign-in expired or was started in another browser. Try again.');
    if (q.error || !q.code) return fail(q.error_description ?? q.error ?? 'Sign-in cancelled');
    try {
      const tokens = await oauth!.exchangeCode(pending.provider, q.code, pending.verifier, oauthCallback);
      const existing = pending.accountId ? directory.get(pending.accountId) : undefined;
      if (pending.accountId && (!existing || !canEdit(p, existing))) return fail('Account not found');
      const email = existing?.email ?? tokens.email ?? pending.draft.email;
      if (!email) return fail('The provider did not return the mailbox address');
      const preset = PROVIDERS.find(x => x.oauth === pending.provider)!;
      const server = (s: NonNullable<typeof preset.imap>) => ({ host: s.host, port: s.port, security: s.security, verifyTls: true });
      const body: AccountBody = {
        ...pending.draft,
        email,
        displayName: pending.draft.displayName ?? existing?.displayName ?? tokens.name,
        username: email,
        provider: preset.id,
        imap: server(preset.imap!),
        smtp: server(preset.smtp!)
      };
      const input = await toInput(p, body, existing);
      input.oauth = { provider: pending.provider, refreshToken: tokens.refreshToken! };
      input.password = undefined;
      const saved = existing ? directory.update(existing.id, input) : directory.create(input, { sub: p.sub, email: p.email });
      log.info(`Mailbox ${saved.email} connected with ${MAIL_OAUTH_LABELS[pending.provider]}`);
      res.redirect(302, `/admin?connected=${encodeURIComponent(saved.id)}`);
    } catch (err) {
      log.warn('mailbox OAuth failed', err instanceof Error ? err.message : err);
      fail(err instanceof Error ? err.message : String(err));
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
    const principal = await sessionPrincipal(req);
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
  const isAdmin = (req: Request) => isAdminP(me(req));

  const visible = (req: Request) => {
    const usable = new Set(policy.accountsFor(me(req)).map(a => a.id));
    return directory.list().filter(a => isAdmin(req) || usable.has(a.id) || a.owner === me(req).sub);
  };

  const parse = (req: Request): AccountBody => {
    const parsed = accountSchema.safeParse(req.body);
    if (!parsed.success) throw new HttpError(400, parsed.error.issues.map(i => `${i.path.join('.') || 'body'}: ${i.message}`).join('; '));
    return parsed.data;
  };

  const handle =
    (fn: (req: Request, res: Response) => Promise<unknown> | unknown) =>
    async (req: Request, res: Response): Promise<void> => {
      try {
        await fn(req, res);
      } catch (err) {
        if (err instanceof HttpError) res.status(err.status).json({ error: err.message });
        else {
          log.error('web interface API error', err);
          res.status(500).json({ error: err instanceof Error ? err.message : 'Internal error' });
        }
      }
    };

  const limiter = new Map<string, { n: number; reset: number }>();
  const rate = (sub: string, kind: string, max: number) => {
    const key = `${kind}:${sub}`;
    const now = Date.now();
    const e = limiter.get(key);
    if (!e || e.reset < now) limiter.set(key, { n: 1, reset: now + 60_000 });
    else if (++e.n > max) throw new HttpError(429, 'Too many attempts, wait a minute');
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
      providers: PROVIDERS.map(x => ({
        id: x.id,
        name: x.name,
        bridge: Boolean(x.bridge),
        oauth: x.oauth && oauth?.available().includes(x.oauth) ? x.oauth : undefined,
        oauthOnly: Boolean(x.oauthOnly),
        appPasswordUrl: x.appPasswordUrl,
        saveSent: x.saveSent,
        imap: x.imap,
        smtp: x.smtp,
        username: x.username
      })),
      mailOAuth: oauth?.available() ?? [],
      oauthRedirectUri: oauthCallback,
      ownRule: ownRule(p),
      appsSupported: Boolean(bridge)
    });
  });

  api.post(
    '/discover',
    handle(async (req, res) => {
      rate(me(req).sub, 'discover', 20);
      const email = z.email().safeParse(String(req.body?.email ?? '').trim().toLowerCase());
      if (!email.success) throw new HttpError(400, 'Invalid email address');
      const result = await discover(email.data);
      const preset = providerById(result.provider.id);
      res.json({
        ...result,
        oauth: result.oauth && oauth?.available().includes(result.oauth) ? result.oauth : undefined,
        oauthSupported: result.oauth,
        appPasswordUrl: preset?.appPasswordUrl ?? result.appPasswordUrl
      });
    })
  );

  api.get('/accounts', (req, res) => {
    res.json({ accounts: visible(req).map(a => view(me(req), a)) });
  });

  api.post(
    '/accounts',
    handle(async (req, res) => {
      if (!policy.canSelfService(me(req))) throw new HttpError(403, 'You may not add accounts');
      const input = await toInput(me(req), parse(req));
      const created = directory.create(input, { sub: me(req).sub, email: me(req).email });
      res.status(201).json(view(me(req), created));
    })
  );

  const editableAccount = (req: Request) => {
    const existing = directory.get(String(req.params.id));
    if (!existing || !canEdit(me(req), existing)) throw new HttpError(404, 'Account not found or read-only');
    return existing;
  };

  api.put(
    '/accounts/:id',
    handle(async (req, res) => {
      const existing = editableAccount(req);
      res.json(view(me(req), directory.update(existing.id, await toInput(me(req), parse(req), existing))));
    })
  );

  api.delete(
    '/accounts/:id',
    handle((req, res) => {
      directory.remove(editableAccount(req).id);
      res.status(204).end();
    })
  );

  /** Test settings before saving, or a saved account when only its id is given. */
  api.post(
    '/accounts/test',
    handle(async (req, res) => {
      rate(me(req).sub, 'test', 20);
      const savedId = typeof req.body?.savedId === 'string' ? req.body.savedId : undefined;
      const saved = savedId ? directory.get(savedId) : undefined;
      if (savedId) {
        const allowed = saved && (canEdit(me(req), saved) || isAdmin(req) || policy.accountsFor(me(req)).some(a => a.id === saved.id));
        if (!allowed) throw new HttpError(404, 'Account not found');
        if (!req.body?.email) {
          res.json(await runTest(saved));
          return;
        }
      }
      const body = parse(req);
      const reuse = saved && canEdit(me(req), saved) ? saved : undefined;
      const input = await toInput(me(req), { ...body, id: saved?.id ?? 'test' }, reuse, { forTest: true });
      const password = body.password || reuse?.password;
      if (!password && !reuse?.oauth) throw new HttpError(400, 'Enter the password to test the connection');
      res.json(
        await runTest({
          ...input,
          email: body.email,
          username: body.username || body.email,
          password: password ?? '',
          oauth: body.password ? undefined : reuse?.oauth
        })
      );
    })
  );

  /** Start "Sign in with Google/Microsoft" for a new or existing mailbox. */
  api.post(
    '/oauth/start',
    handle((req, res) => {
      const provider = req.body?.provider as MailOAuthProviderId;
      if (!oauth || !oauth.available().includes(provider)) throw new HttpError(400, 'This sign-in method is not configured on this server');
      const accountId = typeof req.body?.accountId === 'string' ? req.body.accountId : undefined;
      if (accountId) {
        const existing = directory.get(accountId);
        if (!existing || !canEdit(me(req), existing)) throw new HttpError(404, 'Account not found');
      } else if (!policy.canSelfService(me(req))) throw new HttpError(403, 'You may not add accounts');
      const draft = accountSchema.partial().safeParse(req.body?.draft ?? {});
      const verifier = randomToken(32);
      const state = randomToken(24);
      pendingOAuth.set(state, { sub: me(req).sub, provider, verifier, accountId, draft: draft.success ? draft.data : {} }, 600);
      res.json({
        url: oauth.authorizationUrl(provider, {
          redirectUri: oauthCallback,
          state,
          codeChallenge: s256(verifier),
          loginHint: draft.success ? draft.data.email : undefined
        })
      });
    })
  );

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

