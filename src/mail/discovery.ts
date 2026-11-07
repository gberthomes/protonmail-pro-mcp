/**
 * Mail server autodiscovery from an email address, following what desktop
 * clients do (Thunderbird first, then the Microsoft and RFC 6186 mechanisms):
 *
 *   1. built-in provider presets (offline, instant)
 *   2. autoconfig published by the domain (autoconfig.<domain>, /.well-known/autoconfig)
 *   3. the Mozilla ISPDB (autoconfig.thunderbird.net)
 *   4. MX records → provider presets or ISPDB for the MX domain (Google Workspace, Microsoft 365, OVH…)
 *   5. DNS SRV records (RFC 6186 / RFC 8314: _imaps, _imap, _submissions, _submission)
 *   6. Microsoft Autodiscover (POX)
 *   7. guessing imap./mail./smtp. hosts with a TLS handshake
 *
 * Every host contacted must resolve to a public address (SSRF), HTTP is
 * HTTPS-only with bounded size, time and redirects.
 */

import { resolveMx as dnsResolveMx, resolveSrv as dnsResolveSrv } from 'node:dns/promises';
import { connect as netConnect } from 'node:net';
import { connect as tlsConnect } from 'node:tls';

import { XMLParser } from 'fast-xml-parser';

import type { Endpoint, TransportSecurity } from '../config.js';
import { createLogger } from '../logger.js';
import { isPublicHost } from '../net.js';
import {
  providerForDomain,
  providerForMx,
  PROVIDERS,
  resolveUsername,
  type MailOAuthProviderId,
  type ProviderPreset,
  type UsernameStyle
} from './providers.js';

const log = createLogger('discovery');

export type DiscoverySource = 'preset' | 'autoconfig' | 'ispdb' | 'mx' | 'srv' | 'autodiscover' | 'guess' | 'none';

export interface DiscoveredServer {
  host: string;
  port: number;
  security: TransportSecurity;
  username: string;
}

export interface DiscoveryResult {
  email: string;
  found: boolean;
  source: DiscoverySource;
  provider: { id: string; name: string };
  imap?: DiscoveredServer;
  smtp?: DiscoveredServer;
  saveSent: boolean;
  oauth?: MailOAuthProviderId;
  oauthOnly?: boolean;
  appPasswordUrl?: string;
  /** Use the server's Proton Mail Bridge. */
  bridge?: boolean;
  durationMs: number;
  trace: string[];
}

export interface DiscoveryDeps {
  fetch: typeof fetch;
  resolveMx(domain: string): Promise<Array<{ exchange: string; priority: number }>>;
  resolveSrv(name: string): Promise<Array<{ name: string; port: number; priority: number; weight: number }>>;
  isPublicHost(host: string): Promise<boolean>;
  /** TLS handshake (tls=true) or TCP connect succeeds within the timeout. */
  probe(host: string, port: number, tls: boolean): Promise<boolean>;
  ispdbUrl: string;
  stepTimeoutMs: number;
}

export const defaultDeps: DiscoveryDeps = {
  fetch: (...args) => fetch(...args),
  resolveMx: d => dnsResolveMx(d),
  resolveSrv: n => dnsResolveSrv(n),
  isPublicHost,
  probe: (host, port, tls) =>
    new Promise(resolve => {
      const socket = tls ? tlsConnect({ host, port, servername: host, rejectUnauthorized: true }) : netConnect({ host, port });
      const done = (ok: boolean) => {
        socket.destroy();
        resolve(ok);
      };
      socket.setTimeout(4000, () => done(false));
      socket.once(tls ? 'secureConnect' : 'connect', () => done(true));
      socket.once('error', () => done(false));
    }),
  ispdbUrl: 'https://autoconfig.thunderbird.net/v1.1/',
  stepTimeoutMs: 6000
};

// ---------------------------------------------------------------------------- helpers

interface Candidate {
  source: DiscoverySource;
  name?: string;
  imap?: DiscoveredServer;
  smtp?: DiscoveredServer;
  oauth?: boolean;
  preset?: ProviderPreset;
}

const xml = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  removeNSPrefix: true,
  isArray: name => ['incomingServer', 'outgoingServer', 'authentication', 'domain', 'Protocol'].includes(name)
});

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T | undefined> {
  let timer: NodeJS.Timeout;
  return Promise.race([
    p.catch(() => undefined),
    new Promise<undefined>(resolve => {
      timer = setTimeout(() => resolve(undefined), ms);
    })
  ]).finally(() => clearTimeout(timer));
}

/** HTTPS-only fetch to public hosts, manual redirects (max 3), 256 KiB cap. */
async function safeFetch(deps: DiscoveryDeps, url: string, init: RequestInit = {}): Promise<string | undefined> {
  let current = new URL(url);
  for (let hop = 0; hop < 4; hop++) {
    if (current.protocol !== 'https:') return undefined;
    if (!(await deps.isPublicHost(current.hostname))) return undefined;
    const res = await deps.fetch(current, { ...init, redirect: 'manual', signal: AbortSignal.timeout(deps.stepTimeoutMs) });
    if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
      current = new URL(res.headers.get('location')!, current);
      continue;
    }
    if (!res.ok) return undefined;
    const text = await res.text();
    return text.length > 256 * 1024 ? undefined : text;
  }
  return undefined;
}

function expandUsername(template: string | undefined, email: string): string {
  if (!template) return email;
  const [local, domain] = email.split('@') as [string, string];
  return template.replace(/%EMAILADDRESS%/g, email).replace(/%EMAILLOCALPART%/g, local).replace(/%EMAILDOMAIN%/g, domain);
}

function socketToSecurity(socketType: unknown): TransportSecurity | undefined {
  const s = String(socketType ?? '').toUpperCase();
  if (s === 'SSL' || s === 'TLS') return 'tls';
  if (s === 'STARTTLS') return 'starttls';
  return undefined; // plain: never chosen automatically
}

function text(v: unknown): string | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v === 'object' && '#text' in (v as Record<string, unknown>)) return String((v as Record<string, unknown>)['#text']).trim();
  return String(v).trim();
}

/** Parse a Thunderbird autoconfig (clientConfig v1.1) document. */
export function parseAutoconfig(doc: string, email: string): Omit<Candidate, 'source'> | undefined {
  let parsed: Record<string, any>;
  try {
    parsed = xml.parse(doc);
  } catch {
    return undefined;
  }
  const provider = parsed.clientConfig?.emailProvider;
  if (!provider) return undefined;
  const pick = (servers: any[] | undefined, type: string): { server?: DiscoveredServer; oauth: boolean } => {
    const options = (servers ?? [])
      .filter(s => s?.['@_type'] === type)
      .map(s => ({ s, security: socketToSecurity(text(s.socketType)) }))
      .filter((x): x is { s: any; security: TransportSecurity } => Boolean(x.security && text(x.s.hostname)));
    options.sort((a, b) => (a.security === 'tls' ? 0 : 1) - (b.security === 'tls' ? 0 : 1));
    const best = options[0];
    if (!best) return { oauth: false };
    const auths = (best.s.authentication ?? []).map((a: unknown) => text(a));
    return {
      server: {
        host: text(best.s.hostname)!.toLowerCase(),
        port: Number(text(best.s.port)),
        security: best.security,
        username: expandUsername(text(best.s.username), email)
      },
      oauth: auths.includes('OAuth2')
    };
  };
  const imap = pick(provider.incomingServer, 'imap');
  const smtp = pick(provider.outgoingServer, 'smtp');
  if (!imap.server && !smtp.server) return undefined;
  return { name: text(provider.displayName) ?? text(provider.displayShortName), imap: imap.server, smtp: smtp.server, oauth: imap.oauth || smtp.oauth };
}

/** Parse a Microsoft Autodiscover (POX, responseschema 2006a) reply. */
export function parseAutodiscover(doc: string, email: string): { candidate?: Omit<Candidate, 'source'>; redirectUrl?: string } {
  let parsed: Record<string, any>;
  try {
    parsed = xml.parse(doc);
  } catch {
    return {};
  }
  const account = parsed.Autodiscover?.Response?.Account;
  if (!account) return {};
  if (text(account.Action) === 'redirectUrl' && text(account.RedirectUrl)) return { redirectUrl: text(account.RedirectUrl) };
  const server = (type: string, defaults: { tls: number; starttls: number }): DiscoveredServer | undefined => {
    const p = (account.Protocol ?? []).find((x: any) => text(x.Type)?.toUpperCase() === type);
    if (!p || !text(p.Server)) return undefined;
    const enc = text(p.Encryption)?.toUpperCase();
    const ssl = text(p.SSL)?.toLowerCase() !== 'off';
    const security: TransportSecurity | undefined = enc === 'TLS' ? 'starttls' : enc === 'SSL' ? 'tls' : ssl ? (Number(text(p.Port)) === defaults.starttls ? 'starttls' : 'tls') : undefined;
    if (!security) return undefined;
    return {
      host: text(p.Server)!.toLowerCase(),
      port: Number(text(p.Port)) || (security === 'tls' ? defaults.tls : defaults.starttls),
      security,
      username: text(p.LoginName) || email
    };
  };
  const imap = server('IMAP', { tls: 993, starttls: 143 });
  const smtp = server('SMTP', { tls: 465, starttls: 587 });
  return imap || smtp ? { candidate: { imap, smtp } } : {};
}

function fromPreset(preset: ProviderPreset, email: string): Omit<Candidate, 'source'> {
  const server = (s: ProviderPreset['imap'], style: UsernameStyle) =>
    s ? { host: s.host, port: s.port, security: s.security, username: resolveUsername(s.username ?? style, email) } : undefined;
  return { name: preset.name, imap: server(preset.imap, preset.username), smtp: server(preset.smtp, preset.username), preset };
}

/** "aspmx.l.google.com" → "google.com" (good enough for ISPDB lookups). */
export function registrableDomain(host: string): string {
  const labels = host.toLowerCase().replace(/\.$/, '').split('.');
  if (labels.length <= 2) return labels.join('.');
  const sld = labels[labels.length - 2]!;
  const take = ['co', 'com', 'net', 'org', 'gov', 'ac', 'edu'].includes(sld) && labels[labels.length - 1]!.length === 2 ? 3 : 2;
  return labels.slice(-take).join('.');
}

// ---------------------------------------------------------------------------- steps

async function stepAutoconfig(deps: DiscoveryDeps, email: string, domain: string): Promise<Candidate | undefined> {
  const q = `emailaddress=${encodeURIComponent(email)}`;
  for (const url of [`https://autoconfig.${domain}/mail/config-v1.1.xml?${q}`, `https://${domain}/.well-known/autoconfig/mail/config-v1.1.xml?${q}`]) {
    const doc = await safeFetch(deps, url).catch(() => undefined);
    const c = doc ? parseAutoconfig(doc, email) : undefined;
    if (c) return { ...c, source: 'autoconfig' };
  }
  return undefined;
}

async function stepIspdb(deps: DiscoveryDeps, email: string, domain: string, source: DiscoverySource = 'ispdb'): Promise<Candidate | undefined> {
  const doc = await safeFetch(deps, `${deps.ispdbUrl}${encodeURIComponent(domain)}`).catch(() => undefined);
  const c = doc ? parseAutoconfig(doc, email) : undefined;
  return c ? { ...c, source } : undefined;
}

async function stepMx(deps: DiscoveryDeps, email: string, domain: string, trace: string[]): Promise<Candidate | undefined> {
  const records = (await deps.resolveMx(domain).catch(() => [])).sort((a, b) => a.priority - b.priority);
  if (records.length === 0) return undefined;
  const hosts = records.map(r => r.exchange);
  trace.push(`mx: ${hosts.join(', ')}`);
  const preset = providerForMx(hosts);
  if (preset) return { ...fromPreset(preset, email), source: 'mx' };
  const mxDomain = registrableDomain(hosts[0]!);
  if (mxDomain === domain) return undefined;
  return stepIspdb(deps, email, mxDomain, 'mx');
}

async function stepSrv(deps: DiscoveryDeps, email: string, domain: string): Promise<Candidate | undefined> {
  const lookup = async (service: string, security: TransportSecurity): Promise<DiscoveredServer | undefined> => {
    const records = await deps.resolveSrv(`_${service}._tcp.${domain}`).catch(() => []);
    const best = records.filter(r => r.name && r.name !== '.').sort((a, b) => a.priority - b.priority || b.weight - a.weight)[0];
    return best ? { host: best.name.toLowerCase().replace(/\.$/, ''), port: best.port, security, username: email } : undefined;
  };
  const [imaps, imap, submissions, submission] = await Promise.all([
    lookup('imaps', 'tls'),
    lookup('imap', 'starttls'),
    lookup('submissions', 'tls'),
    lookup('submission', 'starttls')
  ]);
  const c = { imap: imaps ?? imap, smtp: submissions ?? submission };
  return c.imap || c.smtp ? { ...c, source: 'srv' } : undefined;
}

const AUTODISCOVER_REQUEST = (email: string) =>
  `<?xml version="1.0" encoding="utf-8"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>${email.replace(/[<>&"']/g, '')}</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>`;

async function stepAutodiscover(deps: DiscoveryDeps, email: string, domain: string): Promise<Candidate | undefined> {
  const post = (url: string) =>
    safeFetch(deps, url, { method: 'POST', headers: { 'content-type': 'text/xml; charset=utf-8' }, body: AUTODISCOVER_REQUEST(email) }).catch(() => undefined);
  for (const url of [`https://autodiscover.${domain}/autodiscover/autodiscover.xml`, `https://${domain}/autodiscover/autodiscover.xml`]) {
    const doc = await post(url);
    if (!doc) continue;
    let res = parseAutodiscover(doc, email);
    if (res.redirectUrl) {
      const redirected = await post(res.redirectUrl);
      res = redirected ? parseAutodiscover(redirected, email) : {};
    }
    if (res.candidate) return { ...res.candidate, source: 'autodiscover' };
  }
  return undefined;
}

async function stepGuess(deps: DiscoveryDeps, email: string, domain: string): Promise<Candidate | undefined> {
  const tryAll = async (options: Array<{ host: string; port: number; security: TransportSecurity }>) => {
    const results = await Promise.all(
      options.map(async o => ((await deps.isPublicHost(o.host)) && (await deps.probe(o.host, o.port, o.security === 'tls')) ? o : undefined))
    );
    const hit = results.find(Boolean);
    return hit ? { ...hit, username: email } : undefined;
  };
  const [imap, smtp] = await Promise.all([
    tryAll([
      { host: `imap.${domain}`, port: 993, security: 'tls' },
      { host: `mail.${domain}`, port: 993, security: 'tls' },
      { host: `imap.${domain}`, port: 143, security: 'starttls' }
    ]),
    tryAll([
      { host: `smtp.${domain}`, port: 465, security: 'tls' },
      { host: `mail.${domain}`, port: 465, security: 'tls' },
      { host: `smtp.${domain}`, port: 587, security: 'starttls' },
      { host: `mail.${domain}`, port: 587, security: 'starttls' }
    ])
  ]);
  return imap ? { imap, smtp, source: 'guess' } : undefined;
}

// ---------------------------------------------------------------------------- main

function finish(email: string, c: Candidate | undefined, started: number, trace: string[]): DiscoveryResult {
  const durationMs = Date.now() - started;
  if (!c || (!c.imap && !c.preset?.bridge)) {
    return { email, found: false, source: 'none', provider: { id: 'custom', name: 'IMAP' }, saveSent: true, durationMs, trace };
  }
  // Recognise well-known providers behind autoconfig/MX/SRV answers to inherit their quirks.
  const preset =
    c.preset ?? PROVIDERS.find(p => p.imap && c.imap && p.imap.host === c.imap.host);
  const smtp = c.smtp ?? (preset?.smtp ? fromPreset(preset, email).smtp : undefined);
  return {
    email,
    found: true,
    source: c.source,
    provider: preset ? { id: preset.id, name: preset.name } : { id: 'custom', name: c.name ?? 'IMAP' },
    imap: preset?.bridge ? undefined : c.imap,
    smtp: preset?.bridge ? undefined : smtp,
    saveSent: preset ? preset.saveSent : true,
    oauth: preset?.oauth,
    oauthOnly: preset?.oauthOnly,
    appPasswordUrl: preset?.appPasswordUrl,
    bridge: preset?.bridge,
    durationMs,
    trace
  };
}

export async function discover(emailInput: string, overrides: Partial<DiscoveryDeps> = {}): Promise<DiscoveryResult> {
  const deps = { ...defaultDeps, ...overrides };
  const started = Date.now();
  const email = emailInput.trim().toLowerCase();
  const domain = email.split('@')[1];
  const trace: string[] = [];
  if (!domain || !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) throw new Error('Invalid email address');

  const preset = providerForDomain(domain);
  if (preset) {
    trace.push(`preset: ${preset.id}`);
    return finish(email, { ...fromPreset(preset, email), source: 'preset' }, started, trace);
  }

  const timed = <T>(name: string, p: Promise<T>) =>
    withTimeout(p, deps.stepTimeoutMs * 2).then(r => {
      trace.push(`${name}: ${r ? 'found' : 'nothing'}`);
      return r;
    });

  // Run the network steps concurrently, keep the most authoritative answer.
  const [autoconfig, ispdb, mx, srv, autodiscover] = await Promise.all([
    timed('autoconfig', stepAutoconfig(deps, email, domain)),
    timed('ispdb', stepIspdb(deps, email, domain)),
    timed('mx', stepMx(deps, email, domain, trace)),
    timed('srv', stepSrv(deps, email, domain)),
    timed('autodiscover', stepAutodiscover(deps, email, domain))
  ]);
  let best = [autoconfig, ispdb, mx, srv, autodiscover].find(c => c?.imap || c?.preset?.bridge);
  if (!best) best = await timed('guess', stepGuess(deps, email, domain));

  const result = finish(email, best, started, trace);
  log.info(`Discovery for @${domain}: ${result.found ? `${result.source} → ${result.provider.name} (${result.imap?.host ?? 'bridge'})` : 'nothing found'} in ${result.durationMs} ms`);
  return result;
}

/** Turn a discovery result into account settings (Bridge endpoints for Proton). */
export function settingsFromDiscovery(
  result: DiscoveryResult,
  bridge: { imap: Endpoint; smtp: Endpoint }
): { provider: string; imap: Endpoint; smtp: Endpoint; saveSent: boolean } | undefined {
  if (result.bridge) return { provider: 'proton-bridge', imap: bridge.imap, smtp: bridge.smtp, saveSent: false };
  if (!result.imap || !result.smtp) return undefined;
  const ep = (s: DiscoveredServer): Endpoint => ({
    host: s.host,
    port: s.port,
    security: s.security,
    rejectUnauthorized: true,
    username: s.username === result.email ? undefined : s.username
  });
  return { provider: result.provider.id, imap: ep(result.imap), smtp: ep(result.smtp), saveSent: result.saveSent };
}
