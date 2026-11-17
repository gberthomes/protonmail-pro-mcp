import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { discover, parseAutoconfig, parseAutodiscover, registrableDomain, settingsFromDiscovery, type DiscoveryDeps } from '../src/mail/discovery.js';

const AUTOCONFIG = `<?xml version="1.0"?>
<clientConfig version="1.1">
  <emailProvider id="example.org">
    <domain>example.org</domain>
    <displayName>Example Mail</displayName>
    <incomingServer type="pop3"><hostname>pop.example.org</hostname><port>995</port><socketType>SSL</socketType><username>%EMAILADDRESS%</username></incomingServer>
    <incomingServer type="imap"><hostname>imap.example.org</hostname><port>143</port><socketType>STARTTLS</socketType><username>%EMAILLOCALPART%</username><authentication>password-cleartext</authentication></incomingServer>
    <incomingServer type="imap"><hostname>IMAP.example.org</hostname><port>993</port><socketType>SSL</socketType><username>%EMAILLOCALPART%</username><authentication>password-cleartext</authentication></incomingServer>
    <outgoingServer type="smtp"><hostname>smtp.example.org</hostname><port>587</port><socketType>STARTTLS</socketType><username>%EMAILADDRESS%</username></outgoingServer>
    <outgoingServer type="smtp"><hostname>smtp.example.org</hostname><port>25</port><socketType>plain</socketType><username>%EMAILADDRESS%</username></outgoingServer>
  </emailProvider>
</clientConfig>`;

const AUTODISCOVER = `<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account><AccountType>email</AccountType><Action>settings</Action>
      <Protocol><Type>IMAP</Type><Server>mail.host.example</Server><Port>993</Port><LoginName>joe@corp.example</LoginName><SSL>on</SSL></Protocol>
      <Protocol><Type>SMTP</Type><Server>mail.host.example</Server><Port>587</Port><Encryption>TLS</Encryption></Protocol>
    </Account>
  </Response>
</Autodiscover>`;

type Routes = Record<string, { status?: number; body?: string; location?: string }>;

/** Fake network: URL → response, DNS tables, and a probe set. */
function fakeDeps(routes: Routes, dns: { mx?: Record<string, string[]>; srv?: Record<string, [string, number][]>; privateHosts?: string[]; open?: string[] } = {}): Partial<DiscoveryDeps> & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    fetch: (async (input: URL | string) => {
      const url = String(input);
      calls.push(url);
      const route = routes[url] ?? Object.entries(routes).find(([k]) => url.startsWith(k))?.[1];
      if (!route) return new Response('not found', { status: 404 });
      return new Response(route.body ?? '', { status: route.status ?? 200, headers: route.location ? { location: route.location } : {} });
    }) as typeof fetch,
    resolveMx: async d => (dns.mx?.[d] ?? []).map((exchange, i) => ({ exchange, priority: i * 10 })),
    resolveSrv: async n => (dns.srv?.[n] ?? []).map(([name, port]) => ({ name, port, priority: 0, weight: 0 })),
    isPublicHost: async h => !(dns.privateHosts ?? []).some(p => h === p || h.endsWith(`.${p}`)),
    probe: async (host, port) => (dns.open ?? []).includes(`${host}:${port}`),
    ispdbUrl: 'https://ispdb.test/v1.1/',
    stepTimeoutMs: 500
  };
}

describe('autodiscovery', () => {
  it('answers well-known providers offline', async () => {
    const deps = fakeDeps({});
    const r = await discover('Jane@iCloud.com', deps);
    assert.equal(r.source, 'preset');
    assert.equal(r.provider.id, 'icloud');
    assert.equal(r.imap?.username, 'jane', 'iCloud IMAP logs in with the local part');
    assert.equal(r.smtp?.username, 'jane@icloud.com');
    assert.equal(deps.calls.length, 0);
  });

  it('routes Proton addresses to the Bridge', async () => {
    const r = await discover('me@pm.me', fakeDeps({}));
    assert.equal(r.bridge, true);
    const bridge = { host: '127.0.0.1', port: 1143, security: 'starttls' as const, rejectUnauthorized: false };
    assert.equal(settingsFromDiscovery(r, { imap: bridge, smtp: { ...bridge, port: 1025 } })?.imap.port, 1143);
  });

  it('reads the autoconfig published by the domain (prefers SSL, never plaintext)', async () => {
    const r = await discover('joe@example.org', fakeDeps({ 'https://autoconfig.example.org/mail/config-v1.1.xml': { body: AUTOCONFIG } }));
    assert.equal(r.source, 'autoconfig');
    assert.equal(r.provider.name, 'Example Mail');
    assert.deepEqual(r.imap, { host: 'imap.example.org', port: 993, security: 'tls', username: 'joe' });
    assert.deepEqual(r.smtp, { host: 'smtp.example.org', port: 587, security: 'starttls', username: 'joe@example.org' });
  });

  it('falls back to the Mozilla ISPDB', async () => {
    const r = await discover('joe@example.org', fakeDeps({ 'https://ispdb.test/v1.1/example.org': { body: AUTOCONFIG } }));
    assert.equal(r.source, 'ispdb');
  });

  it('recognises hosted domains from their MX records', async () => {
    const google = await discover('ceo@startup.example', fakeDeps({}, { mx: { 'startup.example': ['aspmx.l.google.com', 'alt1.aspmx.l.google.com'] } }));
    assert.equal(google.source, 'mx');
    assert.equal(google.provider.id, 'gmail');
    assert.equal(google.oauth, 'google');
    assert.equal(google.saveSent, false);

    const viaIspdb = await discover('joe@client.example', fakeDeps({ 'https://ispdb.test/v1.1/example.org': { body: AUTOCONFIG } }, { mx: { 'client.example': ['mx1.example.org'] } }));
    assert.equal(viaIspdb.source, 'mx');
    assert.equal(viaIspdb.imap?.host, 'imap.example.org');
  });

  it('uses RFC 6186 / RFC 8314 SRV records', async () => {
    const r = await discover('joe@srv.example', fakeDeps({}, { srv: { '_imaps._tcp.srv.example': [['imap.srv.example.', 993]], '_submission._tcp.srv.example': [['smtp.srv.example.', 587]] } }));
    assert.equal(r.source, 'srv');
    assert.deepEqual([r.imap?.host, r.imap?.port, r.imap?.security], ['imap.srv.example', 993, 'tls']);
    assert.deepEqual([r.smtp?.host, r.smtp?.security], ['smtp.srv.example', 'starttls']);
  });

  it('parses Microsoft Autodiscover and follows its redirectUrl', async () => {
    const redirect = `<Autodiscover><Response><Account><Action>redirectUrl</Action><RedirectUrl>https://ad.host.example/autodiscover/autodiscover.xml</RedirectUrl></Account></Response></Autodiscover>`;
    const r = await discover(
      'joe@corp.example',
      fakeDeps({
        'https://autodiscover.corp.example/autodiscover/autodiscover.xml': { body: redirect },
        'https://ad.host.example/autodiscover/autodiscover.xml': { body: AUTODISCOVER }
      })
    );
    assert.equal(r.source, 'autodiscover');
    assert.deepEqual(r.imap, { host: 'mail.host.example', port: 993, security: 'tls', username: 'joe@corp.example' });
    assert.equal(r.smtp?.security, 'starttls');
    assert.equal(parseAutodiscover('<nope/>', 'x@y.z').candidate, undefined);
  });

  it('guesses imap./smtp. hosts with a TLS handshake as a last resort', async () => {
    const r = await discover('joe@small.example', fakeDeps({}, { open: ['mail.small.example:993', 'smtp.small.example:587'] }));
    assert.equal(r.source, 'guess');
    assert.equal(r.imap?.host, 'mail.small.example');
    assert.equal(r.smtp?.port, 587);
  });

  it('never fetches from private addresses and caps redirects (SSRF)', async () => {
    const deps = fakeDeps(
      {
        'https://autoconfig.evil.example/mail/config-v1.1.xml': { status: 302, location: 'https://metadata.internal/latest' },
        'https://metadata.internal/latest': { body: AUTOCONFIG }
      },
      { privateHosts: ['metadata.internal', 'internal.example'] }
    );
    const r = await discover('joe@evil.example', deps);
    assert.equal(r.found, false);
    assert.ok(!deps.calls.includes('https://metadata.internal/latest'));
    const inside = fakeDeps({ 'https://autoconfig.internal.example/': { body: AUTOCONFIG } }, { privateHosts: ['internal.example'] });
    await discover('joe@internal.example', inside);
    assert.ok(!inside.calls.some(c => new URL(c).hostname.endsWith('internal.example')));
  });

  it('reports when nothing is found', async () => {
    const r = await discover('joe@nothing.example', fakeDeps({}));
    assert.equal(r.found, false);
    assert.equal(r.source, 'none');
  });

  it('helpers', () => {
    assert.equal(registrableDomain('aspmx.l.google.com'), 'google.com');
    assert.equal(registrableDomain('mx.example.co.uk'), 'example.co.uk');
    assert.equal(parseAutoconfig('<clientConfig/>', 'a@b.c'), undefined);
    assert.rejects(() => discover('not-an-email'));
  });
});
