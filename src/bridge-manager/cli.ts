#!/usr/bin/env node
/**
 * bridge-manager — administer the official Proton Mail Bridge from the command line.
 *
 *   bridge-manager status | diagnose | instances list
 *   bridge-manager accounts list | show <account> [--credentials]
 *   bridge-manager accounts add [--username <name>]
 *   bridge-manager accounts logout <account>
 *   bridge-manager accounts remove <account>
 *   bridge-manager events
 *
 * Options: --instance <id> (default: the first configured), --json.
 * Runs as the Unix user that owns the Bridge instance: the control socket is
 * only reachable by that user. Secrets are read from the terminal without
 * echo (or from stdin when it is not a terminal), never from arguments.
 */

import { createInterface } from 'node:readline';

import { setLogLevel } from '../logger.js';
import { AuthError, type AuthSessionView } from './auth.js';
import { loadInstances, type InstanceReport } from './instance.js';
import { BridgeManager } from './manager.js';

interface Args {
  positional: string[];
  flags: Record<string, string | boolean>;
}

function parseArgs(argv: string[]): Args {
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith('--')) {
      const [k, v] = a.slice(2).split('=', 2) as [string, string | undefined];
      if (v !== undefined) flags[k] = v;
      else if (['instance', 'username', 'imap', 'smtp'].includes(k) && argv[i + 1] && !argv[i + 1]!.startsWith('--')) flags[k] = argv[++i]!;
      else flags[k] = true;
    } else positional.push(a);
  }
  return { positional, flags };
}

const out = (s = '') => process.stdout.write(`${s}\n`);
const err = (s: string) => process.stderr.write(`${s}\n`);

// ---------------------------------------------------------------------------- prompts

let stdinLines: AsyncIterableIterator<string> | undefined;

async function prompt(question: string, secret = false): Promise<string> {
  if (!process.stdin.isTTY) {
    // Non-interactive: one answer per line on stdin (e.g. from a secrets manager pipe).
    stdinLines ??= createInterface({ input: process.stdin, terminal: false })[Symbol.asyncIterator]();
    process.stderr.write(question);
    const next = await stdinLines.next();
    process.stderr.write('\n');
    if (next.done) throw new Error('No more input on stdin');
    return next.value;
  }
  if (!secret) {
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    return new Promise(resolve => rl.question(question, a => (rl.close(), resolve(a))));
  }
  process.stderr.write(question);
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    let value = '';
    stdin.setRawMode(true);
    stdin.resume();
    const onData = (buf: Buffer) => {
      for (const ch of buf.toString('utf8')) {
        if (ch === '\r' || ch === '\n') {
          cleanup();
          process.stderr.write('\n');
          return resolve(value);
        }
        if (ch === '\u0003') {
          cleanup();
          process.stderr.write('\n');
          return reject(new Error('Interrupted'));
        }
        if (ch === '\u007f' || ch === '\b') value = value.slice(0, -1);
        else value += ch;
      }
    };
    const cleanup = () => {
      stdin.off('data', onData);
      stdin.setRawMode(false);
      stdin.pause();
    };
    stdin.on('data', onData);
  });
}

// ---------------------------------------------------------------------------- output

function printReport(r: InstanceReport): void {
  out(`Instance ${r.id}`);
  out(`  settings     ${r.settingsDir}`);
  out(`  executable   ${r.installation.binary ?? 'not found'}${r.installation.version ? ` (${r.installation.version})` : ''}`);
  out(`  initialized  ${r.initialized ? 'yes' : 'no'}`);
  out(`  running      ${r.running ? `yes, Bridge ${r.version} — ${r.compat.detail}` : 'no'}`);
  if (r.socket) out(`  socket       ${r.socket}`);
  if (r.keychain) out(`  keychain     ${r.keychain.current || 'none'} (available: ${r.keychain.available.join(', ') || 'none'})`);
  if (r.mailServer) {
    const m = r.mailServer;
    out(`  IMAP         127.0.0.1:${m.imapPort} ${m.useSSLForImap ? 'SSL' : 'STARTTLS'} ${m.imapListening ? 'listening' : 'not listening'}`);
    out(`  SMTP         127.0.0.1:${m.smtpPort} ${m.useSSLForSmtp ? 'SSL' : 'STARTTLS'} ${m.smtpListening ? 'listening' : 'not listening'}`);
  }
  if (r.accounts) out(`  accounts     ${r.accounts.total} (${r.accounts.connected} connected, ${r.accounts.signedOut} signed out, ${r.accounts.locked} locked)`);
  for (const p of r.problems) out(`  ${p.level === 'error' ? 'ERROR' : 'warn '}        [${p.code}] ${p.message}`);
}

function describe(v: AuthSessionView): string {
  return v.error ? `${v.state}: ${v.error.message}` : v.state;
}

// ---------------------------------------------------------------------------- commands

async function addAccount(manager: BridgeManager, instance: string, username?: string): Promise<number> {
  const name = username ?? (await prompt('Proton username or address: '));
  const password = await prompt('Proton password: ', true);
  let view = await manager.startSignIn(instance, name, password, 'cli');
  const auth = await manager.signIn(instance);
  for (;;) {
    switch (view.state) {
      case 'TOTP_REQUIRED': {
        if (view.error) err(view.error.message);
        if (view.fidoAlsoAccepted) err('(This account also has a security key; only the TOTP code is supported here.)');
        view = await auth.submitTotp(view.id, await prompt('Two-factor code: '));
        break;
      }
      case 'MAILBOX_PASSWORD_REQUIRED': {
        if (view.error) err(view.error.message);
        view = await auth.submitMailboxPassword(view.id, await prompt('Mailbox password: ', true));
        break;
      }
      case 'HV_REQUIRED': {
        err('Proton asks for a human verification. Open this address in a browser and complete it:');
        err(`  ${view.hvUrl}`);
        view = await auth.retryAfterHumanVerification(view.id, await prompt('Then enter your Proton password again: ', true));
        break;
      }
      case 'CONNECTED': {
        const a = view.account!;
        out(`${a.alreadyConfigured ? 'Already configured' : 'Connected'}: ${a.username} (${a.id})`);
        for (const address of a.addresses) out(`  ${address}`);
        out('Run `bridge-manager accounts show <account> --credentials` to display its IMAP/SMTP settings.');
        return 0;
      }
      default:
        err(`Sign-in ${describe(view)}`);
        return 1;
    }
  }
}

async function main(argv: string[]): Promise<number> {
  const { positional, flags } = parseArgs(argv);
  const json = Boolean(flags.json);
  setLogLevel(flags.verbose ? 'debug' : 'warn');
  const [cmd, sub, target] = positional;
  if (!cmd || flags.help) {
    out('Usage: bridge-manager <status|diagnose|instances list|accounts list|accounts show <a> [--credentials]|accounts add|accounts logout <a>|accounts remove <a>|ports [set --imap N --smtp N]|events> [--instance id] [--json]');
    return cmd ? 0 : 2;
  }
  const instances = loadInstances();
  const instance = typeof flags.instance === 'string' ? flags.instance : instances[0]!.id;
  const manager = new BridgeManager(instances, { allowUntested: process.env.BRIDGE_MANAGER_ALLOW_UNTESTED === 'true' });
  // Bridge quits when its event-stream client disappears without StopEventStream:
  // always detach gracefully, even on Ctrl+C or a broken pipe.
  let closing = false;
  const detach = (code: number) => {
    if (closing) return;
    closing = true;
    void manager.close().finally(() => process.exit(code));
  };
  process.once('SIGTERM', () => detach(143));
  process.stdout.on('error', () => detach(141));
  if (cmd !== 'events') process.once('SIGINT', () => detach(130));

  try {
    if (cmd === 'instances') {
      if (json) out(JSON.stringify(instances, null, 2));
      else for (const i of instances) out(`${i.id}\t${i.settingsDir}${i.unit ? `\t${i.unit}` : ''}`);
      return 0;
    }
    if (cmd === 'status' || cmd === 'diagnose') {
      const ids = flags.instance ? [instance] : instances.map(i => i.id);
      const reports = await Promise.all(ids.map(id => manager.inspect(id)));
      if (json) out(JSON.stringify(reports, null, 2));
      else reports.forEach((r, i) => (i && out(), printReport(r)));
      return cmd === 'diagnose' && reports.some(r => r.problems.some(p => p.level === 'error')) ? 1 : 0;
    }
    if (cmd === 'accounts') {
      if (!sub || sub === 'list') {
        const accounts = await manager.accounts(instance);
        if (json) out(JSON.stringify(accounts, null, 2));
        else if (accounts.length === 0) out('No Proton account on this Bridge. Add one with `bridge-manager accounts add`.');
        else for (const a of accounts) out(`${a.id}\t${a.state}\t${a.username}\t${a.addresses.join(', ')}`);
        return 0;
      }
      if (sub === 'show') {
        if (!target) throw new Error('Usage: accounts show <account>');
        const account = await manager.account(instance, target);
        const credentials = flags.credentials ? await manager.credentials(instance, target, 'cli') : undefined;
        if (json) out(JSON.stringify({ ...account, credentials }, null, 2));
        else {
          out(`${account.username} (${account.id}) — ${account.state}${account.splitMode ? ', split mode' : ''}`);
          out(`  addresses: ${account.addresses.join(', ')}`);
          if (credentials) {
            out(`  IMAP ${credentials.imap.host}:${credentials.imap.port} (${credentials.imap.security}), SMTP ${credentials.smtp.host}:${credentials.smtp.port} (${credentials.smtp.security})`);
            out(`  username: ${credentials.username}`);
            out(`  password: ${credentials.password}`);
          }
        }
        return 0;
      }
      if (sub === 'add') return await addAccount(manager, instance, typeof flags.username === 'string' ? flags.username : undefined);
      if (sub === 'logout') {
        if (!target) throw new Error('Usage: accounts logout <account>');
        await manager.logout(instance, target, 'cli');
        out('Signed out.');
        return 0;
      }
      if (sub === 'remove') {
        if (!target) throw new Error('Usage: accounts remove <account>');
        const account = await manager.account(instance, target);
        err(`This removes ${account.username} and its local data from Bridge. Assistants using it will stop working.`);
        const confirm = await prompt(`Type "${account.username}" to confirm: `);
        await manager.remove(instance, account.id, confirm, 'cli');
        out('Removed.');
        return 0;
      }
    }
    if (cmd === 'ports') {
      if (sub === 'set') {
        const imap = Number(flags.imap);
        const smtp = Number(flags.smtp);
        const s = await manager.setPorts(instance, { imapPort: imap, smtpPort: smtp }, 'cli');
        out(`IMAP 127.0.0.1:${s.imapPort}, SMTP 127.0.0.1:${s.smtpPort}`);
        return 0;
      }
      const s = await manager.mailServer(instance);
      out(json ? JSON.stringify(s) : `IMAP 127.0.0.1:${s.imapPort} (${s.useSSLForImap ? 'SSL' : 'STARTTLS'}), SMTP 127.0.0.1:${s.smtpPort} (${s.useSSLForSmtp ? 'SSL' : 'STARTTLS'})`);
      return 0;
    }
    if (cmd === 'events') {
      await manager.onEvents(instance, e => out(JSON.stringify(e)));
      err('Streaming Bridge events (Ctrl+C to stop)…');
      await new Promise<void>(resolve => process.once('SIGINT', () => resolve()));
      return 0;
    }
    err(`Unknown command: ${positional.join(' ')}`);
    return 2;
  } catch (e) {
    err(e instanceof AuthError ? `${e.message} [${e.code}]` : e instanceof Error ? e.message : String(e));
    return 1;
  } finally {
    await manager.close();
  }
}

main(process.argv.slice(2)).then(
  code => process.exit(code),
  e => {
    err(e instanceof Error ? e.message : String(e));
    process.exit(1);
  }
);
