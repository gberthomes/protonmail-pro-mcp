/**
 * Well-known mail providers. Used first by autodiscovery (instant, offline)
 * and offered as presets in the web interface. Anything not listed here is
 * found through autoconfig, the Mozilla ISPDB, MX/SRV records or Autodiscover.
 */

import type { TransportSecurity } from '../config.js';

export type UsernameStyle = 'email' | 'localpart';
export type MailOAuthProviderId = 'google' | 'microsoft';

export interface ServerPreset {
  host: string;
  port: number;
  security: TransportSecurity;
  username?: UsernameStyle;
}

export interface ProviderPreset {
  id: string;
  name: string;
  /** Email domains served by this provider. */
  domains: string[];
  /** MX host suffixes identifying custom domains hosted by this provider. */
  mx?: string[];
  imap?: ServerPreset;
  smtp?: ServerPreset;
  /** Default username style for both servers. */
  username: UsernameStyle;
  /** False when the provider already files messages sent over SMTP in "Sent". */
  saveSent: boolean;
  oauth?: MailOAuthProviderId;
  /** Password login is disabled by the provider (OAuth required). */
  oauthOnly?: boolean;
  /** Where users create an app-specific password. */
  appPasswordUrl?: string;
  /** Reached through the local Proton Mail Bridge (endpoints come from the server configuration). */
  bridge?: boolean;
}

export const PROVIDERS: ProviderPreset[] = [
  {
    id: 'proton-bridge',
    name: 'Proton Mail (Bridge)',
    domains: ['proton.me', 'protonmail.com', 'protonmail.ch', 'pm.me'],
    mx: ['protonmail.ch'],
    username: 'email',
    saveSent: false,
    bridge: true
  },
  {
    id: 'gmail',
    name: 'Gmail / Google Workspace',
    domains: ['gmail.com', 'googlemail.com'],
    mx: ['google.com', 'googlemail.com'],
    imap: { host: 'imap.gmail.com', port: 993, security: 'tls' },
    smtp: { host: 'smtp.gmail.com', port: 465, security: 'tls' },
    username: 'email',
    saveSent: false,
    oauth: 'google',
    appPasswordUrl: 'https://myaccount.google.com/apppasswords'
  },
  {
    id: 'microsoft',
    name: 'Outlook.com / Microsoft 365',
    domains: ['outlook.com', 'outlook.fr', 'hotmail.com', 'hotmail.fr', 'live.com', 'live.fr', 'msn.com'],
    mx: ['outlook.com', 'protection.outlook.com'],
    imap: { host: 'outlook.office365.com', port: 993, security: 'tls' },
    smtp: { host: 'smtp.office365.com', port: 587, security: 'starttls' },
    username: 'email',
    saveSent: false,
    oauth: 'microsoft',
    oauthOnly: true
  },
  {
    id: 'icloud',
    name: 'iCloud Mail',
    domains: ['icloud.com', 'me.com', 'mac.com'],
    imap: { host: 'imap.mail.me.com', port: 993, security: 'tls', username: 'localpart' },
    smtp: { host: 'smtp.mail.me.com', port: 587, security: 'starttls', username: 'email' },
    username: 'email',
    saveSent: true,
    appPasswordUrl: 'https://account.apple.com/account/manage'
  },
  {
    id: 'yahoo',
    name: 'Yahoo Mail',
    domains: ['yahoo.com', 'yahoo.fr', 'ymail.com', 'rocketmail.com'],
    imap: { host: 'imap.mail.yahoo.com', port: 993, security: 'tls' },
    smtp: { host: 'smtp.mail.yahoo.com', port: 465, security: 'tls' },
    username: 'email',
    saveSent: true,
    appPasswordUrl: 'https://login.yahoo.com/account/security'
  },
  {
    id: 'fastmail',
    name: 'Fastmail',
    domains: ['fastmail.com', 'fastmail.fm'],
    mx: ['messagingengine.com'],
    imap: { host: 'imap.fastmail.com', port: 993, security: 'tls' },
    smtp: { host: 'smtp.fastmail.com', port: 465, security: 'tls' },
    username: 'email',
    saveSent: true,
    appPasswordUrl: 'https://app.fastmail.com/settings/security/apps'
  },
  {
    id: 'orange',
    name: 'Orange',
    domains: ['orange.fr', 'wanadoo.fr'],
    imap: { host: 'imap.orange.fr', port: 993, security: 'tls' },
    smtp: { host: 'smtp.orange.fr', port: 465, security: 'tls' },
    username: 'email',
    saveSent: true
  },
  {
    id: 'free',
    name: 'Free',
    domains: ['free.fr'],
    imap: { host: 'imap.free.fr', port: 993, security: 'tls' },
    smtp: { host: 'smtp.free.fr', port: 465, security: 'tls' },
    username: 'localpart',
    saveSent: true
  },
  {
    id: 'ovh',
    name: 'OVHcloud (MX Plan)',
    domains: [],
    mx: ['mail.ovh.net', 'ovh.net'],
    imap: { host: 'ssl0.ovh.net', port: 993, security: 'tls' },
    smtp: { host: 'ssl0.ovh.net', port: 465, security: 'tls' },
    username: 'email',
    saveSent: true
  },
  {
    id: 'infomaniak',
    name: 'Infomaniak',
    domains: ['ik.me', 'ikmail.com'],
    mx: ['infomaniak.ch'],
    imap: { host: 'mail.infomaniak.com', port: 993, security: 'tls' },
    smtp: { host: 'mail.infomaniak.com', port: 465, security: 'tls' },
    username: 'email',
    saveSent: true
  }
];

export function providerById(id: string | undefined): ProviderPreset | undefined {
  return id ? PROVIDERS.find(p => p.id === id) : undefined;
}

export function providerForDomain(domain: string): ProviderPreset | undefined {
  const d = domain.toLowerCase();
  return PROVIDERS.find(p => p.domains.includes(d));
}

export function providerForMx(mxHosts: string[]): ProviderPreset | undefined {
  const hosts = mxHosts.map(h => h.toLowerCase().replace(/\.$/, ''));
  return PROVIDERS.find(p => p.mx?.some(suffix => hosts.some(h => h === suffix || h.endsWith(`.${suffix}`))));
}

export function resolveUsername(style: UsernameStyle | undefined, email: string): string {
  return style === 'localpart' ? email.split('@')[0]! : email;
}
