# Proton Bridge Manager

The Bridge Manager lets this project **deploy, initialise and administer the official Proton Mail Bridge** on Linux, including adding Proton accounts to a Bridge that has none, without the Bridge CLI. Proton accounts signed in to Bridge then become mailboxes for the MCP server automatically.

Proton Mail Bridge stays **the official, unmodified software**. The Manager is an external process that talks to Bridge through the gRPC control interface Bridge exposes for its own GUI.

> **The gRPC interface is internal to Proton Mail Bridge.** It is not a public API, carries no stability guarantee and can change in any release. The Manager isolates it in one adapter (`src/bridge-manager/client.ts`), checks the Bridge version and refuses state-changing operations on untested versions.

## Contents

- [Architecture](#architecture)
- [What was verified in Bridge's source](#what-was-verified-in-bridges-source)
- [Compatibility](#compatibility)
- [Installation (Debian/Ubuntu, systemd)](#installation-debianubuntu-systemd)
- [Command line](#command-line)
- [Web interface and API](#web-interface-and-api)
- [Several instances (mode B)](#several-instances-mode-b)
- [Security model](#security-model)
- [Validation with real accounts](#validation-with-real-accounts)
- [Limitations](#limitations)
- [Licences and sources](#licences-and-sources)

## Architecture

```text
Web interface (/admin) ─┐        CLI (bridge-manager)
MCP tools ──────────────┤                │
                        ▼                ▼
                 BridgeManager  (src/bridge-manager/manager.ts)
                 ├─ instances      (instance.ts: detection, diagnostics)
                 ├─ AuthController (auth.ts: sign-in state machine, one per instance)
                 └─ BridgeClient   (client.ts: the only module that knows the protocol)
                                   │  Unix socket, TLS pinned to Bridge's certificate,
                                   │  server token as gRPC metadata
                                   ▼
               Proton Mail Bridge (official, `bridge --grpc`)  ── IMAP/SMTP 127.0.0.1
                     ├─ account A
                     ├─ account B
                     └─ account C
```

- **Mode A** (default): one Bridge instance holding several Proton accounts. Each account keeps its own addresses, state and Bridge-generated IMAP/SMTP password; IMAP/SMTP ports belong to the instance.
- **Mode B**: several instances on one host, see [below](#several-instances-mode-b).
- `BridgeAccountSource` (`accounts-source.ts`) turns every connected Bridge account into an MCP mailbox. The IMAP/SMTP password is read from Bridge and kept in memory only; the Manager writes no secret to disk.

## What was verified in Bridge's source

Against Proton Mail Bridge **v3.27.2** (`internal/frontend/grpc`, `internal/service`, `internal/app`), then exercised against the signed Linux package:

| Topic | Behaviour | Consequence for the Manager |
| --- | --- | --- |
| Control interface | Started only with `--grpc`. **`--noninteractive` takes precedence over `--grpc` and disables it**; `--cli` has no socket. | systemd runs `bridge --grpc --parent-pid -1`. |
| Discovery | `$XDG_CONFIG_HOME/protonmail/bridge-v3/grpcServerConfig.json` (directory mode 0700): `cert`, `token`, `fileSocketPath`. | Read after checking owner and permissions. |
| Socket | Unix socket created in `$TMPDIR` (`/tmp/bridgeNNNN` by default). | systemd points `TMPDIR` to a private 0700 runtime directory; `status` warns when the socket is in a shared temp directory. |
| Transport security | TLS with a self-signed certificate published in the config file; every call needs the `server-token` metadata. | Certificate pinned by fingerprint; no "accept any certificate". |
| Events | **One** event stream (`RunEventStream`); a second one gets `ALREADY_EXISTS`. **If the stream is cut without `StopEventStream`, Bridge quits** (it assumes its GUI died). | The Manager is the only frontend of an instance, always detaches with `StopEventStream`, handles SIGINT/SIGTERM/broken pipes; systemd restarts Bridge if the Manager crashes. Read-only commands do not open the stream. |
| Sign-in | One sign-in in progress per Bridge (single `auth` slot). Events carry the username or the new user id, no session id. Secrets are sent base64-encoded in `bytes`. | Sign-ins are serialised per instance; events are matched to the active session by username; a person restarting their own abandoned sign-in replaces it. |
| Steps | TOTP, FIDO2, TOTP-or-FIDO, mailbox password ("two passwords", 3 attempts in Bridge), human verification (CAPTCHA URL, then `Login` again with `useHvDetails`), "already logged in". | All mapped to explicit states (below). FIDO needs a security key on the Bridge host and is reported, not simulated. |
| Accounts | `GetUserList`/`GetUser` return id, username, state (`SIGNED_OUT`, `LOCKED`, `CONNECTED`), addresses, split mode, quota and the per-account IMAP/SMTP password. `LogoutUser`, `RemoveUser`. | Account views never include the password; credentials are only returned on explicit request (audited). |
| Ports | `SetMailServerSettings` is asynchronous; errors arrive as events. **After a failed change the new port is saved even though it is not listening.** | `ports set` waits for the result; `status` checks that ports really listen. |
| Keychain | `pass-app`, `secret-service`, `secret-service-dbus` (+ oo7 since 3.27.2). | Headless servers use `pass` with a dedicated GPG key per instance. |

Sign-in states: `CREATED → LOGIN_PENDING → TOTP_REQUIRED | MAILBOX_PASSWORD_REQUIRED | HV_REQUIRED | FIDO_REQUIRED → AUTHENTICATING → CONNECTED`, or `FAILED`, `CANCELLED`, `EXPIRED`. Sessions expire after 10 minutes, each step after 60 s without an answer from Bridge, TOTP and mailbox password allow 3 attempts; a failed or cancelled session aborts the sign-in in Bridge (`LoginAbort`).

## Compatibility

| Bridge | Status |
| --- | --- |
| 3.27.2 | **tested** — protocol reviewed in the source; read-only calls, event stream, port changes and graceful detach run against the signed package. Sign-in flows tested against a scripted Bridge implementing the same protocol (no real account used). |
| other 3.x | read-only only; state-changing operations refused unless `BRIDGE_MANAGER_ALLOW_UNTESTED=true` |
| 2.x and older | unsupported |

Upgrading Bridge is a deliberate step: the installer pins the version and puts the package on hold. To support a new release: diff `internal/frontend/grpc/bridge.proto` with the tested tag, update `src/bridge-manager/proto/bridge-control.proto` if needed, run the integration test, then add the version to `compat.ts`.

## Installation (Debian/Ubuntu, systemd)

```bash
sudo deploy/install-debian.sh --version 3.27.2 --instance default
```

The script is idempotent and never overwrites an existing instance, keychain or unit:

1. downloads the `.deb`, its signature and Proton's key from `proton.me`; accepts the package only if the signature is valid **and** made by the pinned key `D51E 64D3 E63E DC3E EF78 64CE E2C7 5D68 E623 4B07`;
2. installs that version and holds the package (`apt-mark hold`);
3. creates the `protonmail-bridge` system user and `/var/lib/protonmail-bridge/<instance>/{config,data,cache,gnupg,password-store}` (0700);
4. creates a `pass` keychain with a dedicated GPG key (no passphrase — Bridge must start unattended; protected by the service user's 0700 directories);
5. installs and starts `protonmail-bridge@<instance>.service` (`deploy/systemd/`).

`--download-only DIR` only downloads and verifies.

Then run the MCP server with the Manager **as the same user** (`deploy/systemd/protonmail-mcp.service`): Bridge keeps its control configuration in a 0700 directory, so only its own user can drive it. Configure the instances in `/etc/protonmail-mcp/bridge-instances.json`:

```json
[{ "id": "default", "settingsDir": "/var/lib/protonmail-bridge/default/config/protonmail/bridge-v3", "unit": "protonmail-bridge@default.service" }]
```

| Variable | Meaning |
| --- | --- |
| `BRIDGE_MANAGER=true` | Enable the Manager with a single instance (`BRIDGE_SETTINGS_DIR` or the current user's Bridge) |
| `BRIDGE_MANAGER_INSTANCES` / `BRIDGE_MANAGER_INSTANCES_FILE` | Instances as JSON (`id`, `settingsDir`, optional `uid`, `binary`, `unit`) — enables the Manager |
| `BRIDGE_SETTINGS_DIR`, `BRIDGE_BINARY`, `BRIDGE_UID` | Single-instance shortcuts |
| `BRIDGE_MANAGER_ALLOW_UNTESTED=true` | Allow sign-in/sign-out/removal on untested Bridge versions |

## Command line

`bridge-manager` (installed with the package, `node dist/bridge-manager/cli.js` from a checkout), run as the Bridge user:

```bash
bridge-manager status                 # every instance: version, socket, keychain, ports, accounts, problems
bridge-manager diagnose --json        # same, exit code 1 on errors
bridge-manager instances list
bridge-manager accounts list
bridge-manager accounts show <account> [--credentials]   # credentials: Bridge's IMAP/SMTP login (audited)
bridge-manager accounts add [--username me@proton.me]    # password, TOTP, mailbox password, human verification
bridge-manager accounts logout <account>
bridge-manager accounts remove <account>                 # asks to type the username
bridge-manager ports [set --imap 1144 --smtp 1026]
bridge-manager events                                    # live events (debugging)
```

Secrets are typed without echo, or read line by line from stdin when it is not a terminal; they are never accepted as arguments (visible in `ps`). While the MCP server holds an instance's event stream, use the web interface to add accounts (read-only commands keep working).

## Web interface and API

In the web interface, adding an address at a Proton domain shows **Sign in to Proton**: Proton password → two-factor code → mailbox password → human verification when Proton asks, all in the dialog. The account then appears among the mailboxes with *Sign out* and *Remove*.

The JSON API lives under `/admin/api/bridge` and inherits the web interface's protection (OIDC session, Origin check, `X-PMCP` header against CSRF, `Cache-Control: no-store`). Secrets only travel in JSON request bodies — never in URLs or headers.

| Method | Path | |
| --- | --- | --- |
| GET | `/instances` | Status (full report for administrators) |
| GET | `/instances/{id}/accounts` | Accounts you may see (no passwords) |
| POST | `/auth-sessions` | `{instance, username, password}` → session |
| GET | `/auth-sessions/{sid}` | Session state (only its creator can read it) |
| POST | `/auth-sessions/{sid}/totp` | `{code}` |
| POST | `/auth-sessions/{sid}/mailbox-password` | `{password}` |
| POST | `/auth-sessions/{sid}/hv` | `{password}` after the human verification |
| POST | `/auth-sessions/{sid}/cancel` | |
| PUT | `/instances/{id}/accounts/{aid}/sharing` | `{users}` — who may use the mailbox |
| POST | `/instances/{id}/accounts/{aid}/logout` | |
| DELETE | `/instances/{id}/accounts/{aid}` | `{confirm: "<username or address>"}` |

Rights: administrators manage every account; users allowed to add mailboxes (`MCP_ALLOWED_USERS`, self-service) sign in their own accounts and manage only those. Ten sign-in attempts per user per 15 minutes.

## Several instances (mode B)

Each instance needs its own settings, data, cache, keychain, socket and ports; the systemd template provides all of them from `/var/lib/protonmail-bridge/<id>` and `/run/protonmail-bridge/<id>`. Change the ports of the second instance with `bridge-manager ports set --instance <id> --imap 1144 --smtp 1026` (the first instance keeps 1143/1025).

- **B1 — one service user, several instances**: the template as shipped. One Manager drives all instances (listed in `/etc/protonmail-mcp/bridge-instances.json`). Instances are isolated by directories, keychains, sockets and ports, not by Unix user.
- **B2 — one Unix user (or container) per instance**: copy the unit with a different `User=`. Because Bridge's control directory is 0700, each user needs its own Manager process (one MCP server, or one CLI session, per instance).

## Security model

- The control socket and `grpcServerConfig.json` must belong to the expected user and sit in directories nobody else can write; otherwise the Manager refuses to connect (a planted socket would receive the token). The TLS certificate is pinned to the one published by Bridge, so a socket that is not Bridge cannot complete the handshake.
- No administrative route is anonymous: the API requires the web interface session (or a loopback-only server without authentication, where the local user is the administrator).
- The Manager never stores Proton passwords, TOTP codes or mailbox passwords; they go to Bridge and are dropped. Bridge keeps its own session. Bridge-generated IMAP/SMTP passwords are read on demand and kept in memory.
- Logs never contain those secrets nor the gRPC token (checked by the tests after every scenario). Sensitive operations are logged in an `[audit]` line (who, which account, which instance) without secrets.
- Destructive operations need an explicit confirmation (typing the account) and are audited.
- IMAP/SMTP are only reached on 127.0.0.1.

## Validation with real accounts

Real Proton accounts are never used by the automated tests. To validate an installation by hand (each step only after you decide to use real accounts):

1. `bridge-manager status` on a fresh instance: running, tested version, keychain present, no account.
2. `bridge-manager accounts add` with account A (TOTP on), then account B (two-password mode if available).
3. `bridge-manager accounts list`: both `CONNECTED`; `accounts show A --credentials` and `accounts show B --credentials` give different passwords.
4. `sudo systemctl restart protonmail-bridge@default`: both accounts still `CONNECTED`.
5. `accounts logout A`: A `SIGNED_OUT`, B still `CONNECTED` and usable over IMAP.
6. `accounts remove A`.

The read-only integration test runs against a real Bridge with `BRIDGE_IT_SETTINGS_DIR=… npm test`.

## Limitations

- The interface is internal and may change; only tested versions accept state changes.
- **FIDO2-only accounts** cannot be signed in by the Manager (Bridge expects a key plugged into its host). Add a TOTP method to the account.
- **Human verification** needs a browser: the Manager shows Proton's URL and asks for the password again afterwards.
- One sign-in at a time per instance (Bridge's design).
- The Manager must be the only frontend of an instance: do not run `bridge-gui` on it.
- Account ownership recorded by the web interface lives in `MCP_DATA_DIR/bridge-accounts.json` (no secret); accounts added from the CLI or another tool follow the global access rules.
- The IMAP/SMTP connections to Bridge on 127.0.0.1 do not verify Bridge's self-signed certificate (pin it with `PROTONMAIL_BRIDGE_CERT` after exporting it from Bridge).
- `docker-compose.yml` still uses a community Bridge image for the plain IMAP/SMTP setup; the Manager's supported deployment is systemd. A container built from the signed official package is a follow-up.

## Licences and sources

- Proton Mail Bridge is GPL-3.0 (<https://github.com/ProtonMail/proton-bridge>). The Manager does not include or link Bridge's code: it runs the official binary as a separate process and talks to it over IPC. `src/bridge-manager/proto/bridge-control.proto` is a minimal description written for this project from Bridge's observable interface (service, method names, field numbers and types); it is not a copy of Proton's `bridge.proto`.
- `pgray/mayl` (GPL-2.0, <https://github.com/pgray/mayl>) was studied as a reference for the overall approach (gRPC mode, Unix socket, token metadata, sign-in events). **No code was taken from it.** Deliberately not reproduced: administrative routes without authentication, Proton passwords in HTTP headers, SMTP credentials stored in clear in SQLite, disabled TLS verification, "first connected user" for SMTP, removal of lock files without checking processes.
- Official documentation: <https://proton.me/support/bridge-cli-guide>, <https://proton.me/support/bridge-for-linux>, <https://proton.me/support/protonmail-bridge-clients>.
