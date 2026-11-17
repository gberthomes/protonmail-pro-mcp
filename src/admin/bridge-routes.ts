/**
 * Web interface API for the Proton Bridge Manager (mounted under /admin/api/bridge).
 *
 * Inherits the admin API protections: OIDC session cookie (or loopback local
 * mode), Origin validation, X-PMCP header on writes (CSRF), no-store. Secrets
 * (Proton password, TOTP code, mailbox password) only travel in JSON request
 * bodies, are passed straight to Bridge and never logged or stored.
 *
 *   GET    /instances                              status of every instance (details for admins)
 *   GET    /instances/:id/accounts                 accounts you may see
 *   POST   /auth-sessions                          { instance, username, password }
 *   GET    /auth-sessions/:sid
 *   POST   /auth-sessions/:sid/totp                { code }
 *   POST   /auth-sessions/:sid/mailbox-password    { password }
 *   POST   /auth-sessions/:sid/hv                  { password }  (after the human verification)
 *   POST   /auth-sessions/:sid/cancel
 *   PUT    /instances/:id/accounts/:aid/sharing     { users }
 *   POST   /instances/:id/accounts/:aid/logout
 *   DELETE /instances/:id/accounts/:aid             { confirm: "<username>" }
 */

import express, { type Request, type Response, type Router } from 'express';

import { ownRule, type AccessPolicy, type Principal } from '../auth/principal.js';
import { createLogger } from '../logger.js';
import { AuthError, type AuthSessionView } from '../bridge-manager/auth.js';
import type { BridgeAccountSource } from '../bridge-manager/accounts-source.js';
import type { BridgeManager } from '../bridge-manager/manager.js';
import type { AccountEntry } from '../mail/directory.js';

const log = createLogger('admin-bridge');

export interface BridgeRouteDeps {
  manager: BridgeManager;
  source: BridgeAccountSource;
  policy: AccessPolicy;
  principal(req: Request): Principal;
}

export function bridgeRoutes(deps: BridgeRouteDeps): Router {
  const { manager, source, policy } = deps;
  const r = express.Router();
  /** Sign-in sessions belong to whoever started them. */
  const owners = new Map<string, { sub: string; instance: string; email?: string }>();
  const attempts = new Map<string, { n: number; reset: number }>();

  const isAdmin = (req: Request) => policy.isAdmin(deps.principal(req));

  const fail = (res: Response, err: unknown) => {
    if (err instanceof AuthError) res.status(err.status).json({ error: err.message, code: err.code });
    else {
      log.warn('bridge API error', err instanceof Error ? err.message : err);
      res.status(502).json({ error: err instanceof Error ? err.message : 'Bridge error', code: 'bridge-error' });
    }
  };

  const wrap =
    (fn: (req: Request, res: Response) => Promise<unknown>) =>
    (req: Request, res: Response): void => {
      fn(req, res).catch(err => fail(res, err));
    };

  const str = (v: unknown, field: string, max = 1024): string => {
    if (typeof v !== 'string' || !v || v.length > max) throw new AuthError(400, 'invalid-input', `${field} is required`);
    return v;
  };

  /** Accounts a principal may manage: admins all, others the ones they added. */
  const canManage = (p: Principal, instance: string, bridgeUserId: string) =>
    policy.isAdmin(p) || source.meta.get(instance, bridgeUserId)?.owner === p.sub;

  const session = (req: Request) => {
    const sid = String(req.params.sid);
    const o = owners.get(sid);
    if (!o || o.sub !== deps.principal(req).sub) throw new AuthError(404, 'not-found', 'Unknown or expired sign-in session');
    return { sid, instance: o.instance };
  };

  /** When a sign-in completes, record who added the account and refresh the mailboxes. */
  const settle = async (view: AuthSessionView, req: Request): Promise<AuthSessionView> => {
    if (view.state === 'CONNECTED' && view.account) {
      const p = deps.principal(req);
      const existing = source.meta.get(view.instanceId, view.account.id);
      if (!existing?.owner && p.via !== 'local') {
        source.meta.set(view.instanceId, view.account.id, { ...existing, owner: p.sub, ownerEmail: p.email, users: existing?.users ?? [ownRule(p)] });
      }
      await source.refresh();
    }
    return view;
  };

  r.get(
    '/instances',
    wrap(async (req, res) => {
      const reports = await Promise.all(manager.instances().map(i => manager.inspect(i.id, { checkBinary: isAdmin(req) })));
      res.json({
        instances: reports.map(rep =>
          isAdmin(req)
            ? rep
            : { id: rep.id, running: rep.running, version: rep.version, accounts: rep.accounts ? { total: rep.accounts.total } : undefined, problems: [] }
        )
      });
    })
  );

  r.get(
    '/instances/:id/accounts',
    wrap(async (req, res) => {
      const p = deps.principal(req);
      const id = String(req.params.id);
      const usable = new Set(
        (policy.accountsFor(p) as AccountEntry[]).filter(a => a.bridge?.instance === id).map(a => a.bridge!.userId)
      );
      const accounts = (await manager.accounts(id))
        .filter(a => policy.isAdmin(p) || usable.has(a.id) || source.meta.get(id, a.id)?.owner === p.sub)
        .map(a => {
          const meta = source.meta.get(id, a.id);
          const mailbox = source.list().find(m => m.bridge?.instance === id && m.bridge.userId === a.id);
          return { ...a, mailboxId: mailbox?.id, owner: meta?.ownerEmail, users: meta?.users ?? [], manageable: canManage(p, id, a.id) };
        });
      res.json({ accounts });
    })
  );

  r.post(
    '/auth-sessions',
    wrap(async (req, res) => {
      const p = deps.principal(req);
      if (!policy.canSelfService(p)) throw new AuthError(403, 'forbidden', 'You may not add accounts');
      const now = Date.now();
      const a = attempts.get(p.sub);
      if (!a || a.reset < now) attempts.set(p.sub, { n: 1, reset: now + 15 * 60_000 });
      else if (++a.n > 10) throw new AuthError(429, 'rate-limited', 'Too many sign-in attempts, try again later');
      const instance = typeof req.body?.instance === 'string' ? req.body.instance : manager.instances()[0]!.id;
      const username = str(req.body?.username, 'username', 254);
      const password = str(req.body?.password, 'password');
      // A sign-in the same person left unfinished (closed tab…) is replaced; someone else's is not.
      const controller = await manager.signIn(instance);
      const current = controller.activeSessionId();
      if (current && owners.get(current)?.sub === p.sub) await controller.cancel(current);
      const view = await manager.startSignIn(instance, username, password, { sub: p.sub, email: p.email });
      owners.set(view.id, { sub: p.sub, instance, email: p.email });
      res.status(201).json(await settle(view, req));
    })
  );

  r.get(
    '/auth-sessions/:sid',
    wrap(async (req, res) => {
      const { sid, instance } = session(req);
      res.json((await manager.signIn(instance)).get(sid));
    })
  );

  r.post(
    '/auth-sessions/:sid/totp',
    wrap(async (req, res) => {
      const { sid, instance } = session(req);
      res.json(await settle(await (await manager.signIn(instance)).submitTotp(sid, str(req.body?.code, 'code', 16)), req));
    })
  );

  r.post(
    '/auth-sessions/:sid/mailbox-password',
    wrap(async (req, res) => {
      const { sid, instance } = session(req);
      res.json(await settle(await (await manager.signIn(instance)).submitMailboxPassword(sid, str(req.body?.password, 'password')), req));
    })
  );

  r.post(
    '/auth-sessions/:sid/hv',
    wrap(async (req, res) => {
      const { sid, instance } = session(req);
      res.json(await settle(await (await manager.signIn(instance)).retryAfterHumanVerification(sid, str(req.body?.password, 'password')), req));
    })
  );

  r.post(
    '/auth-sessions/:sid/cancel',
    wrap(async (req, res) => {
      const { sid, instance } = session(req);
      res.json(await (await manager.signIn(instance)).cancel(sid));
    })
  );

  r.put(
    '/instances/:id/accounts/:aid/sharing',
    wrap(async (req, res) => {
      const p = deps.principal(req);
      const id = String(req.params.id);
      const account = await manager.account(id, String(req.params.aid));
      if (!canManage(p, id, account.id)) throw new AuthError(404, 'unknown-account', 'Account not found');
      const users = Array.isArray(req.body?.users) ? (req.body.users as unknown[]).filter((u): u is string => typeof u === 'string' && u.length <= 254).slice(0, 100) : undefined;
      if (!users) throw new AuthError(400, 'invalid-input', 'users must be a list');
      const meta = source.meta.get(id, account.id) ?? {};
      const own = meta.owner && !policy.isAdmin(p) ? [ownRule(p)] : [];
      source.meta.set(id, account.id, { ...meta, users: [...new Set([...own, ...users])] });
      await source.refresh();
      res.json({ users: source.meta.get(id, account.id)?.users });
    })
  );

  r.post(
    '/instances/:id/accounts/:aid/logout',
    wrap(async (req, res) => {
      const p = deps.principal(req);
      const id = String(req.params.id);
      const account = await manager.account(id, String(req.params.aid));
      if (!canManage(p, id, account.id)) throw new AuthError(404, 'unknown-account', 'Account not found');
      await manager.logout(id, account.id, { sub: p.sub, email: p.email });
      await source.refresh();
      res.status(204).end();
    })
  );

  r.delete(
    '/instances/:id/accounts/:aid',
    wrap(async (req, res) => {
      const p = deps.principal(req);
      const id = String(req.params.id);
      const account = await manager.account(id, String(req.params.aid));
      if (!canManage(p, id, account.id)) throw new AuthError(404, 'unknown-account', 'Account not found');
      await manager.remove(id, account.id, typeof req.body?.confirm === 'string' ? req.body.confirm : '', { sub: p.sub, email: p.email });
      source.meta.delete(id, account.id);
      await source.refresh();
      res.status(204).end();
    })
  );

  return r;
}
