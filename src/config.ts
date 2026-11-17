/**
 * Configuration loading.
 *
 * Everything can be configured with environment variables (12-factor, Docker
 * friendly). Multi-account setups can additionally use a JSON file pointed to by
 * PROTONMAIL_MCP_CONFIG (or ./protonmail-mcp.json, or
 * ~/.config/protonmail-pro-mcp/config.json).
 *
 * Secrets accept a `*_FILE` variant (Docker/Kubernetes secrets).
 */

import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

import { createLogger } from './logger.js';
import { mailOAuthFromEnv, type MailOAuthConfig } from './mail/oauth.js';
import { providerById, resolveUsername, type MailOAuthProviderId, type ServerPreset } from './mail/providers.js';

const log = createLogger('config');

export type TransportSecurity = 'starttls' | 'tls' | 'none';

export interface Endpoint {
  host: string;
  port: number;
  security: TransportSecurity;
  /** Reject self-signed certificates. Proton Bridge uses a self-signed cert, so this defaults to false. */
  rejectUnauthorized: boolean;
  /** Optional PEM CA/certificate to trust (e.g. the Bridge certificate exported from its settings). */
  ca?: string;
  /** Login for this server when it differs from the account username (e.g. iCloud IMAP uses the local part). */
  username?: string;
}

export interface AccountConfig {
  /** Short, stable identifier used in tool calls (e.g. "perso", "work"). */
  id: string;
  /** Primary address of the account. */
  email: string;
  /** Display name used in the From header. */
  displayName?: string;
  /** IMAP/SMTP username (Bridge shows it in the mailbox configuration, usually the address). */
  username: string;
  /** Bridge-generated password, app password or IMAP password ("" for OAuth accounts). */
  password: string;
  /** XOAUTH2 instead of a password (accounts connected from the web interface). */
  oauth?: { provider: MailOAuthProviderId; refreshToken: string };
  /** Provider preset id ("proton-bridge", "gmail", "custom"…). */
  provider?: string;
  /** Append sent messages to the Sent folder (for servers that do not do it themselves). */
  saveSent?: boolean;
  /** Only connect to public addresses (accounts added by non-administrators). */
  publicOnly?: boolean;
  /** Resolve the IMAP/SMTP servers by autodiscovery at startup. */
  discover?: boolean;
  imap: Endpoint;
  smtp: Endpoint;
  /**
   * Who may use this account when the server runs over HTTP with authentication.
   * Patterns: "alice@example.com", "*@example.com", "group:mail-admins", "sub:<subject>", "*".
   * When omitted, the global MCP_ALLOWED_USERS list applies.
   */
  users?: string[];
}

export type AuthMode = 'none' | 'oidc' | 'oidc-resource';

export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret?: string;
  scopes: string[];
  groupsClaim: string;
  /** Token endpoint client authentication used with the upstream IdP. */
  tokenAuthMethod: 'client_secret_basic' | 'client_secret_post' | 'none';
  /** Expected audience of upstream access tokens (oidc-resource mode only). */
  audience?: string;
}

export interface HttpConfig {
  host: string;
  port: number;
  publicUrl: URL;
  tlsCertFile?: string;
  tlsKeyFile?: string;
  allowedHosts: string[];
  allowedOrigins: string[];
  trustProxy: string | boolean;
  legacySse: boolean;
  /** Serve the web interface at /admin. */
  webUi: boolean;
}

export interface AuthConfig {
  mode: AuthMode;
  oidc?: OidcConfig;
  /** Static API keys: key -> identity (email or name). */
  apiKeys: Map<string, string>;
  /** Global allow-list, applies to accounts that do not define `users`. */
  allowedUsers: string[];
  /** Administrators of the web interface (defaults to allowedUsers). */
  adminUsers: string[];
  /** Allowed users may add their own Proton accounts in the web interface. */
  selfService: boolean;
  /** Key encrypting Bridge passwords of accounts added in the web interface. */
  encryptionKey?: string;
  accessTokenTtl: number;
  refreshTokenTtl: number;
  allowDynamicRegistration: boolean;
  allowClientIdMetadataDocuments: boolean;
  /** Optional fixed signing secret (base64/hex/text, >= 32 bytes) for multi-instance deployments. */
  signingSecret?: string;
}

export interface AppConfig {
  transport: 'stdio' | 'http';
  /** OAuth clients for Gmail / Microsoft mailboxes. */
  mailOAuth: MailOAuthConfig;
  accounts: AccountConfig[];
  /** Bridge endpoints used for accounts that do not override them. */
  bridge: { imap: Endpoint; smtp: Endpoint };
  http: HttpConfig;
  auth: AuthConfig;
  dataDir: string;
}

interface FileAccount {
  id?: string;
  provider?: string;
  saveSent?: boolean;
  discover?: boolean;
  email?: string;
  displayName?: string;
  username?: string;
  password?: string;
  passwordFile?: string;
  passwordEnv?: string;
  imap?: Partial<Endpoint> & { caFile?: string };
  smtp?: Partial<Endpoint> & { caFile?: string };
  users?: string[];
}

interface FileConfig {
  bridge?: {
    imap?: Partial<Endpoint> & { caFile?: string };
    smtp?: Partial<Endpoint> & { caFile?: string };
  };
  accounts?: FileAccount[];
}

// ---------------------------------------------------------------------------
// helpers

function env(name: string): string | undefined {
  const direct = process.env[name];
  if (direct !== undefined && direct !== '') return direct;
  const file = process.env[`${name}_FILE`];
  if (file) return readFileSync(file, 'utf8').trim();
  return undefined;
}

function envBool(name: string, fallback: boolean): boolean {
  const v = env(name);
  if (v === undefined) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(v.toLowerCase());
}

function envInt(name: string, fallback: number): number {
  const v = env(name);
  if (v === undefined) return fallback;
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n)) throw new Error(`${name} must be an integer, got "${v}"`);
  return n;
}

function list(value: string | undefined): string[] {
  return (value ?? '')
    .split(/[,\n]/)
    .map(s => s.trim())
    .filter(Boolean);
}

function parseSecurity(value: string | undefined, fallback: TransportSecurity): TransportSecurity {
  if (!value) return fallback;
  const v = value.toLowerCase();
  if (v === 'starttls' || v === 'tls' || v === 'none') return v;
  if (v === 'ssl') return 'tls';
  throw new Error(`Invalid transport security "${value}" (expected starttls, tls or none)`);
}

function slug(value: string): string {
  return value
    .toLowerCase()
    .replace(/@.*/, '')
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'account';
}

function mergeEndpoint(
  base: Endpoint,
  override?: Partial<Endpoint> & { caFile?: string }
): Endpoint {
  if (!override) return base;
  const otherHost = override.host !== undefined && override.host !== base.host;
  return {
    host: override.host ?? base.host,
    port: override.port ?? base.port,
    security: override.security ? parseSecurity(override.security, base.security) : base.security,
    // Only the Bridge has a self-signed certificate: verify any other server unless told otherwise.
    rejectUnauthorized: override.rejectUnauthorized ?? (otherHost ? true : base.rejectUnauthorized),
    ca: override.caFile ? readFileSync(override.caFile, 'utf8') : (override.ca ?? (otherHost ? undefined : base.ca)),
    username: override.username
  };
}

/** PROTONMAIL_ACCOUNT_<X>_IMAP_HOST / _PORT / _SECURITY / _USERNAME / _TLS_VERIFY */
function endpointFromEnv(prefix: string): (Partial<Endpoint> & { caFile?: string }) | undefined {
  const host = env(`${prefix}HOST`);
  const port = env(`${prefix}PORT`);
  const security = env(`${prefix}SECURITY`);
  const username = env(`${prefix}USERNAME`);
  const verify = env(`${prefix}TLS_VERIFY`);
  if (!host && !port && !security && !username && !verify) return undefined;
  return {
    host,
    port: port ? Number.parseInt(port, 10) : undefined,
    security: security ? parseSecurity(security, 'tls') : undefined,
    username,
    rejectUnauthorized: verify ? envBool(`${prefix}TLS_VERIFY`, true) : undefined
  };
}

function defaultEndpoints(): { imap: Endpoint; smtp: Endpoint } {
  const caFile = env('PROTONMAIL_BRIDGE_CERT');
  const ca = caFile ? readFileSync(caFile, 'utf8') : undefined;
  // Bridge certificates are self-signed: trust them by default unless a CA is pinned.
  const rejectUnauthorized = envBool('PROTONMAIL_TLS_VERIFY', Boolean(ca));
  return {
    imap: {
      host: env('PROTONMAIL_IMAP_HOST') ?? '127.0.0.1',
      port: envInt('PROTONMAIL_IMAP_PORT', 1143),
      security: parseSecurity(env('PROTONMAIL_IMAP_SECURITY'), 'starttls'),
      rejectUnauthorized,
      ca
    },
    smtp: {
      host: env('PROTONMAIL_SMTP_HOST') ?? '127.0.0.1',
      port: envInt('PROTONMAIL_SMTP_PORT', 1025),
      security: parseSecurity(env('PROTONMAIL_SMTP_SECURITY'), 'starttls'),
      rejectUnauthorized,
      ca
    }
  };
}

function locateConfigFile(): string | undefined {
  const explicit = env('PROTONMAIL_MCP_CONFIG');
  if (explicit) {
    if (!existsSync(explicit)) throw new Error(`PROTONMAIL_MCP_CONFIG points to a missing file: ${explicit}`);
    return resolve(explicit);
  }
  const candidates = [
    resolve('protonmail-mcp.json'),
    join(process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config'), 'protonmail-pro-mcp', 'config.json')
  ];
  return candidates.find(p => existsSync(p));
}

// ---------------------------------------------------------------------------
// accounts

function loadAccounts(defaults: { imap: Endpoint; smtp: Endpoint }): AccountConfig[] {
  const accounts: AccountConfig[] = [];

  const add = (raw: FileAccount, origin: string, base = defaults) => {
    const username = raw.username ?? raw.email;
    const email = raw.email ?? raw.username;
    let password = raw.password;
    if (!password && raw.passwordFile) password = readFileSync(raw.passwordFile, 'utf8').trim();
    if (!password && raw.passwordEnv) password = env(raw.passwordEnv);
    if (!username || !email) throw new Error(`${origin}: an account needs "email" or "username"`);
    if (!password) throw new Error(`${origin}: account ${email} has no password (use password, passwordFile or passwordEnv)`);
    // A provider preset fills in the servers (explicit imap/smtp settings still win).
    const preset = providerById(raw.provider);
    if (raw.provider && !preset && raw.provider !== 'custom') throw new Error(`${origin}: unknown provider "${raw.provider}"`);
    const fromPreset = (s?: ServerPreset) =>
      s ? { host: s.host, port: s.port, security: s.security, username: s.username ? resolveUsername(s.username, email) : undefined } : undefined;
    const imapOverride = preset && !preset.bridge ? { ...fromPreset(preset.imap), ...raw.imap } : raw.imap;
    const smtpOverride = preset && !preset.bridge ? { ...fromPreset(preset.smtp), ...raw.smtp } : raw.smtp;
    accounts.push({
      id: raw.id ? slug(raw.id) : slug(email),
      email: email.toLowerCase(),
      displayName: raw.displayName,
      username: raw.username ?? (preset ? resolveUsername(preset.username, email) : username),
      password,
      imap: mergeEndpoint(base.imap, imapOverride),
      smtp: mergeEndpoint(base.smtp, smtpOverride),
      users: raw.users?.map(u => u.trim()).filter(Boolean),
      provider: preset?.id ?? (raw.imap?.host ? 'custom' : raw.discover ? undefined : 'proton-bridge'),
      saveSent: raw.saveSent ?? preset?.saveSent,
      discover: raw.discover && !raw.imap?.host && !preset
    });
  };

  // 1. JSON config file
  const file = locateConfigFile();
  if (file) {
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as FileConfig;
    const base = {
      imap: mergeEndpoint(defaults.imap, parsed.bridge?.imap),
      smtp: mergeEndpoint(defaults.smtp, parsed.bridge?.smtp)
    };
    for (const acc of parsed.accounts ?? []) add(acc, file, base);
    log.info(`Loaded ${parsed.accounts?.length ?? 0} account(s) from ${file}`);
  }

  // 2. PROTONMAIL_ACCOUNTS: inline JSON array
  const inline = env('PROTONMAIL_ACCOUNTS');
  if (inline) {
    const parsed = JSON.parse(inline) as FileAccount[];
    if (!Array.isArray(parsed)) throw new Error('PROTONMAIL_ACCOUNTS must be a JSON array');
    for (const acc of parsed) add(acc, 'PROTONMAIL_ACCOUNTS');
  }

  // 3. Indexed variables: PROTONMAIL_ACCOUNT_<N>_EMAIL / _USERNAME / _PASSWORD / _ID / _NAME / _USERS
  const indexes = new Set<string>();
  for (const key of Object.keys(process.env)) {
    const m = /^PROTONMAIL_ACCOUNT_([A-Z0-9]+)_(EMAIL|USERNAME)$/.exec(key);
    if (m) indexes.add(m[1]!);
  }
  for (const idx of [...indexes].sort()) {
    const p = `PROTONMAIL_ACCOUNT_${idx}_`;
    add(
      {
        id: env(`${p}ID`) ?? (/^\d+$/.test(idx) ? undefined : idx),
        email: env(`${p}EMAIL`),
        username: env(`${p}USERNAME`),
        password: env(`${p}PASSWORD`),
        displayName: env(`${p}NAME`),
        users: env(`${p}USERS`) ? list(env(`${p}USERS`)) : undefined,
        provider: env(`${p}PROVIDER`),
        discover: env(`${p}DISCOVER`) ? envBool(`${p}DISCOVER`, false) : undefined,
        saveSent: env(`${p}SAVE_SENT`) ? envBool(`${p}SAVE_SENT`, true) : undefined,
        imap: endpointFromEnv(`${p}IMAP_`),
        smtp: endpointFromEnv(`${p}SMTP_`)
      },
      p + '*'
    );
  }

  // 4. Historical single-account variables
  const username = env('PROTONMAIL_USERNAME');
  if (username) {
    add(
      {
        id: env('PROTONMAIL_ACCOUNT_ID'),
        email: env('PROTONMAIL_EMAIL') ?? username,
        username,
        password: env('PROTONMAIL_PASSWORD'),
        displayName: env('PROTONMAIL_DISPLAY_NAME'),
        users: env('PROTONMAIL_USERS') ? list(env('PROTONMAIL_USERS')) : undefined
      },
      'PROTONMAIL_USERNAME'
    );
  }

  // Ensure unique ids
  const seen = new Map<string, number>();
  for (const acc of accounts) {
    const n = seen.get(acc.id) ?? 0;
    seen.set(acc.id, n + 1);
    if (n > 0) acc.id = `${acc.id}-${n + 1}`;
  }
  return accounts;
}

// ---------------------------------------------------------------------------
// main loader

function isLoopback(host: string): boolean {
  return ['127.0.0.1', 'localhost', '::1', '[::1]'].includes(host);
}

export function loadConfig(argv: string[] = process.argv.slice(2)): AppConfig {
  const transportArg = argv.find(a => a === '--http' || a === '--stdio' || a === 'http' || a === 'stdio' || a === 'serve');
  const transport: 'stdio' | 'http' =
    transportArg === '--http' || transportArg === 'http' || transportArg === 'serve'
      ? 'http'
      : transportArg
        ? 'stdio'
        : (env('MCP_TRANSPORT') ?? 'stdio').toLowerCase() === 'http'
          ? 'http'
          : 'stdio';

  const bridge = defaultEndpoints();
  const accounts = loadAccounts(bridge);

  const port = envInt('PORT', envInt('MCP_PORT', 3000));
  const host = env('HOST') ?? env('MCP_HOST') ?? '127.0.0.1';
  const tlsCertFile = env('TLS_CERT_FILE');
  const tlsKeyFile = env('TLS_KEY_FILE');
  if (Boolean(tlsCertFile) !== Boolean(tlsKeyFile)) throw new Error('TLS_CERT_FILE and TLS_KEY_FILE must be set together');

  const publicUrlRaw =
    env('PUBLIC_URL') ?? `${tlsCertFile ? 'https' : 'http'}://${isLoopback(host) || host === '0.0.0.0' ? 'localhost' : host}:${port}`;
  const publicUrl = new URL(publicUrlRaw.replace(/\/+$/, ''));
  if (publicUrl.pathname !== '/' || publicUrl.search || publicUrl.hash) {
    throw new Error('PUBLIC_URL must be an origin without path, e.g. https://mail-mcp.example.com');
  }

  const trustProxyRaw = env('TRUST_PROXY') ?? 'loopback, linklocal, uniquelocal';
  const trustProxy = trustProxyRaw === 'true' ? true : trustProxyRaw === 'false' ? false : trustProxyRaw;

  const http: HttpConfig = {
    host,
    port,
    publicUrl,
    tlsCertFile,
    tlsKeyFile,
    allowedHosts: [...new Set([publicUrl.hostname, 'localhost', '127.0.0.1', '[::1]', ...list(env('MCP_ALLOWED_HOSTS'))])],
    allowedOrigins: list(env('MCP_ALLOWED_ORIGINS')),
    trustProxy,
    legacySse: envBool('MCP_LEGACY_SSE', true),
    webUi: envBool('MCP_WEB_UI', true)
  };

  // ---- auth
  const issuer = env('OIDC_ISSUER');
  const requestedMode = env('MCP_AUTH')?.toLowerCase();
  let mode: AuthMode;
  if (requestedMode === 'none' || requestedMode === 'oidc' || requestedMode === 'oidc-resource') mode = requestedMode;
  else if (requestedMode) throw new Error(`MCP_AUTH must be none, oidc or oidc-resource (got "${requestedMode}")`);
  else mode = issuer ? 'oidc' : 'none';

  let oidc: OidcConfig | undefined;
  if (mode !== 'none') {
    if (!issuer) throw new Error(`MCP_AUTH=${mode} requires OIDC_ISSUER`);
    const clientId = env('OIDC_CLIENT_ID');
    if (mode === 'oidc' && !clientId) throw new Error('MCP_AUTH=oidc requires OIDC_CLIENT_ID (and usually OIDC_CLIENT_SECRET)');
    const clientSecret = env('OIDC_CLIENT_SECRET');
    oidc = {
      issuer: issuer.replace(/\/+$/, ''),
      clientId: clientId ?? '',
      clientSecret,
      scopes: list(env('OIDC_SCOPES') ?? 'openid email profile').flatMap(s => s.split(/\s+/)),
      groupsClaim: env('OIDC_GROUPS_CLAIM') ?? 'groups',
      tokenAuthMethod: (env('OIDC_TOKEN_AUTH_METHOD') as OidcConfig['tokenAuthMethod'] | undefined) ??
        (clientSecret ? 'client_secret_basic' : 'none'),
      audience: env('OIDC_AUDIENCE')
    };
  }

  const apiKeys = new Map<string, string>();
  for (const entry of list(env('MCP_API_KEYS'))) {
    const sep = entry.lastIndexOf('=');
    const key = sep > 0 ? entry.slice(0, sep) : entry;
    const who = sep > 0 ? entry.slice(sep + 1) : 'api-key';
    if (key.length < 24) throw new Error('MCP_API_KEYS entries must be at least 24 characters long');
    apiKeys.set(key, who);
  }

  const auth: AuthConfig = {
    mode,
    oidc,
    apiKeys,
    allowedUsers: list(env('MCP_ALLOWED_USERS') ?? env('OIDC_ALLOWED_USERS')),
    adminUsers: list(env('MCP_ADMIN_USERS') ?? env('MCP_ALLOWED_USERS') ?? env('OIDC_ALLOWED_USERS')),
    selfService: envBool('MCP_SELF_SERVICE', true),
    encryptionKey: env('MCP_ENCRYPTION_KEY'),
    accessTokenTtl: envInt('MCP_ACCESS_TOKEN_TTL', 3600),
    refreshTokenTtl: envInt('MCP_REFRESH_TOKEN_TTL', 60 * 60 * 24 * 30),
    allowDynamicRegistration: envBool('MCP_ALLOW_DYNAMIC_REGISTRATION', true),
    allowClientIdMetadataDocuments: envBool('MCP_ALLOW_CLIENT_METADATA_DOCUMENTS', true),
    signingSecret: env('MCP_SIGNING_SECRET')
  };

  const dataDir = resolve(
    env('MCP_DATA_DIR') ?? join(process.env.XDG_DATA_HOME ?? join(homedir(), '.local', 'share'), 'protonmail-pro-mcp')
  );

  return { transport, mailOAuth: mailOAuthFromEnv(env), accounts, bridge, http, auth, dataDir };
}

export function isLoopbackHost(host: string): boolean {
  return isLoopback(host);
}
