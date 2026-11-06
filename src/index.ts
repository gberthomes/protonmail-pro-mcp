#!/usr/bin/env node
/**
 * protonmail-pro-mcp — Proton Mail MCP server (stdio + Streamable HTTP/HTTPS with OIDC).
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
  if (config.accounts.length === 0) {
    log.warn('No Proton account configured. Set PROTONMAIL_USERNAME and PROTONMAIL_PASSWORD (Bridge credentials) or see README.md for multi-account setup.');
  }
  const registry = new AccountRegistry(config.accounts);
  const policy = new AccessPolicy(config.accounts, config.auth.allowedUsers);
  const deps = { registry, policy };

  let shutdown: () => Promise<void>;
  if (config.transport === 'http') {
    const running = await startHttp(config, deps);
    shutdown = () => running.close();
  } else {
    const handle = serveStdio(() => buildServer(LOCAL_PRINCIPAL, deps));
    log.info(`protonmail-pro-mcp ${VERSION} ready on stdio (${config.accounts.length} account(s))`);
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
