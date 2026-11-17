/**
 * Bridge instances and their inspection.
 *
 * Mode A (default): one official Bridge holding several Proton accounts.
 * Mode B: several isolated Bridges on one host, each with its own service
 * user (or container), config/cache/keychain directories, socket and ports.
 * An instance is identified by where its settings live; nothing here assumes
 * a single instance.
 */

import { execFile } from 'node:child_process';
import { accessSync, constants, existsSync, readFileSync, statSync } from 'node:fs';
import { connect } from 'node:net';
import { homedir } from 'node:os';
import { delimiter, join } from 'node:path';

import { BridgeClient, BridgeSecurityError, readServerConfig, checkSocket, type MailServerSettings } from './client.js';
import { compatibility, type CompatLevel } from './compat.js';

export interface InstanceConfig {
  id: string;
  /** Bridge settings directory ($XDG_CONFIG_HOME/protonmail/bridge-v3 of the service user). */
  settingsDir: string;
  /** Unix user expected to own the files and socket (defaults to the Manager's user). */
  uid?: number;
  /** Official Bridge executable (the backend `bridge`, not the GUI launcher). */
  binary?: string;
  /** systemd unit running this instance, for diagnostics. */
  unit?: string;
}

export interface Problem {
  level: 'error' | 'warning';
  code: string;
  message: string;
}

export interface InstanceReport {
  id: string;
  settingsDir: string;
  installation: { binary?: string; version?: string };
  /** Bridge has created its vault (it has been started at least once). */
  initialized: boolean;
  running: boolean;
  version?: string;
  compat: { level: CompatLevel; detail: string };
  socket?: string;
  keychain?: { current: string; available: string[] };
  mailServer?: MailServerSettings & { imapListening: boolean; smtpListening: boolean };
  accounts?: { total: number; connected: number; signedOut: number; locked: number };
  problems: Problem[];
}

const DEFAULT_BINARIES = ['/usr/lib/protonmail/bridge/bridge', '/usr/lib/protonmail-bridge/bridge', '/opt/protonmail-bridge/bridge'];

export function defaultSettingsDir(): string {
  const base = process.env.XDG_CONFIG_HOME || join(homedir(), '.config');
  return join(base, 'protonmail', 'bridge-v3');
}

/** Instances from BRIDGE_MANAGER_INSTANCES (JSON array) or a single default one. */
export function loadInstances(env: NodeJS.ProcessEnv = process.env): InstanceConfig[] {
  const raw = env.BRIDGE_MANAGER_INSTANCES_FILE ? readFileSync(env.BRIDGE_MANAGER_INSTANCES_FILE, 'utf8') : env.BRIDGE_MANAGER_INSTANCES;
  if (!raw) {
    return [{ id: 'default', settingsDir: env.BRIDGE_SETTINGS_DIR || defaultSettingsDir(), binary: env.BRIDGE_BINARY, uid: env.BRIDGE_UID ? Number(env.BRIDGE_UID) : undefined }];
  }
  const list = JSON.parse(raw) as InstanceConfig[];
  if (!Array.isArray(list) || list.length === 0) throw new Error('BRIDGE_MANAGER_INSTANCES must be a non-empty JSON array');
  const ids = new Set<string>();
  for (const i of list) {
    if (!i.id || !/^[a-z0-9][a-z0-9_-]{0,31}$/.test(i.id)) throw new Error(`Invalid instance id "${i.id}"`);
    if (ids.has(i.id)) throw new Error(`Duplicate instance id "${i.id}"`);
    if (!i.settingsDir) throw new Error(`Instance "${i.id}" has no settingsDir`);
    ids.add(i.id);
  }
  return list;
}

function findBinary(preferred?: string): string | undefined {
  const candidates = [preferred, ...DEFAULT_BINARIES].filter((x): x is string => Boolean(x));
  for (const c of candidates) {
    try {
      accessSync(c, constants.X_OK);
      return c;
    } catch {
      /* next */
    }
  }
  for (const dir of (process.env.PATH ?? '').split(delimiter)) {
    const p = join(dir, 'protonmail-bridge');
    if (dir && existsSync(p)) return p;
  }
  return undefined;
}

function binaryVersion(binary: string): Promise<string | undefined> {
  return new Promise(resolve => {
    execFile(binary, ['--version'], { timeout: 15_000, env: { PATH: '/usr/bin:/bin' } }, (err, stdout) => {
      if (err) return resolve(undefined);
      resolve(/Bridge\s+(\d+\.\d+\.\d+\S*)/.exec(stdout)?.[1]);
    });
  });
}

function listening(port: number): Promise<boolean> {
  return new Promise(resolve => {
    const s = connect({ host: '127.0.0.1', port });
    const done = (ok: boolean) => {
      s.destroy();
      resolve(ok);
    };
    s.setTimeout(1500, () => done(false));
    s.once('connect', () => done(true));
    s.once('error', () => done(false));
  });
}

/** Read-only inspection: never changes Bridge's state or files. */
export async function inspectInstance(inst: InstanceConfig, opts: { checkBinary?: boolean } = {}): Promise<InstanceReport> {
  const problems: Problem[] = [];
  const report: InstanceReport = {
    id: inst.id,
    settingsDir: inst.settingsDir,
    installation: {},
    initialized: false,
    running: false,
    compat: { level: 'unsupported', detail: 'not reachable' },
    problems
  };

  if (opts.checkBinary !== false) {
    const binary = findBinary(inst.binary);
    report.installation.binary = binary;
    if (binary) report.installation.version = await binaryVersion(binary);
    else problems.push({ level: 'warning', code: 'binary-not-found', message: 'No Proton Mail Bridge executable found on this host (it may run in a container).' });
  }

  if (!existsSync(inst.settingsDir)) {
    problems.push({ level: 'error', code: 'not-initialized', message: `${inst.settingsDir} does not exist: Bridge has never been started by this user.` });
    return report;
  }
  const st = statSync(inst.settingsDir);
  if ((st.mode & 0o077) !== 0) problems.push({ level: 'warning', code: 'settings-permissions', message: `${inst.settingsDir} is accessible to other users (mode ${(st.mode & 0o777).toString(8)}); expected 700.` });
  report.initialized = existsSync(join(inst.settingsDir, 'vault.enc'));
  if (!report.initialized) problems.push({ level: 'warning', code: 'no-vault', message: 'Bridge has no vault yet: start it once to initialise.' });

  const configPath = join(inst.settingsDir, 'grpcServerConfig.json');
  if (!existsSync(configPath)) {
    problems.push({ level: 'error', code: 'grpc-not-enabled', message: 'No grpcServerConfig.json: run the Bridge backend with --grpc (the --cli mode has no control socket).' });
    return report;
  }

  let client: BridgeClient | undefined;
  try {
    const cfg = readServerConfig(configPath, { uid: inst.uid });
    report.socket = cfg.fileSocketPath;
    if (!existsSync(cfg.fileSocketPath)) {
      problems.push({ level: 'error', code: 'not-running', message: `Socket ${cfg.fileSocketPath} is missing: Bridge is not running (or was started with another TMPDIR).` });
      return report;
    }
    checkSocket(cfg.fileSocketPath, { uid: inst.uid });
    if (/^\/tmp\//.test(cfg.fileSocketPath) || /^\/var\/tmp\//.test(cfg.fileSocketPath)) {
      problems.push({ level: 'warning', code: 'socket-in-tmp', message: 'The control socket is in a shared temporary directory; run Bridge with TMPDIR pointing to a private directory (see deploy/systemd).' });
    }
    client = await BridgeClient.connect(inst.settingsDir, { uid: inst.uid, timeoutMs: 5000 });
    report.running = true;
    report.version = await client.version();
    report.compat = compatibility(report.version);
    if (report.compat.level !== 'tested') problems.push({ level: report.compat.level === 'unsupported' ? 'error' : 'warning', code: 'version', message: report.compat.detail });

    const [keychain, mail, users] = await Promise.all([client.keychains(), client.mailServerSettings(), client.users()]);
    report.keychain = keychain;
    if (!keychain.current) problems.push({ level: 'error', code: 'no-keychain', message: 'Bridge has no usable keychain (install pass or a Secret Service provider).' });
    const [imapListening, smtpListening] = await Promise.all([listening(mail.imapPort), listening(mail.smtpPort)]);
    report.mailServer = { ...mail, imapListening, smtpListening };
    if (users.some(u => u.state === 'CONNECTED') && (!imapListening || !smtpListening)) {
      problems.push({ level: 'warning', code: 'ports', message: `IMAP ${mail.imapPort} or SMTP ${mail.smtpPort} is not listening on 127.0.0.1.` });
    }
    report.accounts = {
      total: users.length,
      connected: users.filter(u => u.state === 'CONNECTED').length,
      signedOut: users.filter(u => u.state === 'SIGNED_OUT').length,
      locked: users.filter(u => u.state === 'LOCKED').length
    };
    if (users.length === 0) problems.push({ level: 'warning', code: 'no-account', message: 'Bridge is running but no Proton account is configured yet.' });
    if (report.accounts.signedOut > 0) problems.push({ level: 'warning', code: 'signed-out', message: `${report.accounts.signedOut} account(s) are signed out and need to sign in again.` });
  } catch (err) {
    problems.push({
      level: 'error',
      code: err instanceof BridgeSecurityError ? 'security' : 'unreachable',
      message: err instanceof Error ? err.message : String(err)
    });
  } finally {
    await client?.close();
  }
  return report;
}
