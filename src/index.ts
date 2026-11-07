#!/usr/bin/env node
/**
 * protonmail-pro-mcp — mail MCP server for Proton Mail (Bridge) and any IMAP mailbox (stdio + Streamable HTTP/HTTPS with OIDC).
 *
 *   protonmail-pro-mcp            # stdio (Claude Desktop, Claude Code, Cursor, ...)
 *   protonmail-pro-mcp --http     # Streamable HTTP(S) server, see README for OIDC
 */

import { serveStdio } from '@modelcontextprotocol/server/stdio';

import { AccessPolicy, LOCAL_PRINCIPAL } from './auth/principal.js';
import { loadConfig } from './config.js';
import { startHttp } from './http.js';
import { createLogger } from './logger.js';
import { AccountRegistry } from './mail/account.js';
import { AccountDirectory } from './mail/directory.js';
import { discover, settingsFromDiscovery } from './mail/discovery.js';
import { MailOAuth } from './mail/oauth.js';
import { buildServer } from './server.js';
import { VERSION } from './version.js';

const log = createLogger('main');

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    process.stderr.write(
      `protonmail-pro-mcp ${VERSION}\n\nUsage: protonmail-pro-mcp [--stdio | --http]\n\nConfiguration is read from environment variables and an optional JSON file; see README.md.\n`
    );
    return;
  }
  if (args.includes('--version')) {
    process.stderr.write(`${VERSION}\n`);
    return;
  }

  const config = loadConfig(args);

  // Accounts declared with discover=true: resolve their servers now.
  await Promise.all(
    config.accounts
      .filter(a => a.discover)
      .map(async account => {
        try {
          const settings = settingsFromDiscovery(await discover(account.email), config.bridge);
          if (!settings) throw new Error('no server found');
          Object.assign(account, settings);
          if (settings.imap.username || settings.smtp.username) account.username = account.email;
          log.info(`Account "${account.id}": ${settings.provider} (${settings.imap.host}:${settings.imap.port})`);
        } catch (err) {
          log.warn(`Autodiscovery failed for "${account.id}", using the Bridge settings: ${err instanceof Error ? err.message : err}`);
        }
      })
  );
  const directory = new AccountDirectory(config.accounts, config.dataDir, config.auth.encryptionKey);
  if (directory.list().length === 0) {
    log.warn(
      config.transport === 'http'
        ? 'No Proton account configured yet: add one in the web interface (/admin) or with environment variables (see README.md).'
        : 'No Proton account configured. Set PROTONMAIL_USERNAME and PROTONMAIL_PASSWORD (Bridge credentials), or add accounts with the web interface.'
    );
  }
  const oauth = new MailOAuth(config.mailOAuth);
  const registry = new AccountRegistry(directory, oauth);
  const policy = new AccessPolicy(directory, {
    allowedUsers: config.auth.allowedUsers,
    adminUsers: config.auth.adminUsers,
    selfService: config.auth.selfService
  });
  const deps = { registry, policy, directory, oauth };

  let shutdown: () => Promise<void>;
  if (config.transport === 'http') {
    const running = await startHttp(config, deps);
    shutdown = () => running.close();
  } else {
    const handle = serveStdio(() => buildServer(LOCAL_PRINCIPAL, deps));
    log.info(`protonmail-pro-mcp ${VERSION} ready on stdio (${directory.list().length} account(s))`);
    shutdown = () => handle.close();
    process.stdin.on('end', () => void stop('stdin closed'));
  }

  let stopping = false;
  const stop = async (reason: string) => {
    if (stopping) return;
    stopping = true;
    log.info(`Shutting down (${reason})`);
    const force = setTimeout(() => process.exit(0), 5000);
    force.unref();
    await shutdown().catch(err => log.error('shutdown error', err));
    await registry.closeAll();
    process.exit(0);
  };
  process.on('SIGINT', () => void stop('SIGINT'));
  process.on('SIGTERM', () => void stop('SIGTERM'));
}

process.on('unhandledRejection', reason => log.error('Unhandled rejection', reason));

main().catch(err => {
  log.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
