#!/usr/bin/env bash
# Install the official Proton Mail Bridge on Debian/Ubuntu and prepare one
# instance for the Bridge Manager. Idempotent: re-running never overwrites an
# existing instance, keychain or unit file.
#
#   sudo deploy/install-debian.sh [--version 3.27.2] [--instance default]
#   deploy/install-debian.sh --download-only DIR     # fetch + verify, no install
#
# The package is downloaded from proton.me and accepted only if its detached
# signature verifies against Proton's Bridge signing key whose fingerprint is
# pinned below (the key file itself is fetched from the same origin, so the
# pinned fingerprint is what establishes trust).

set -euo pipefail

PROTON_BRIDGE_KEY_FPR="D51E64D3E63EDC3EEF7864CEE2C75D68E6234B07"   # Proton Technologies AG (ProtonMail Bridge developers)
VERSION="3.27.2"                                                    # tested with this Manager (src/bridge-manager/compat.ts)
INSTANCE="default"
DOWNLOAD_ONLY=""
BASE_URL="https://proton.me/download/bridge"
SERVICE_USER="protonmail-bridge"
STATE_ROOT="/var/lib/protonmail-bridge"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --instance) INSTANCE="$2"; shift 2 ;;
    --download-only) DOWNLOAD_ONLY="$2"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid version $VERSION" >&2; exit 2; }
[[ "$INSTANCE" =~ ^[a-z0-9][a-z0-9_-]{0,31}$ ]] || { echo "Invalid instance id $INSTANCE" >&2; exit 2; }
[ "$(dpkg --print-architecture 2>/dev/null || uname -m)" = "amd64" ] || [ "$(uname -m)" = "x86_64" ] || { echo "Proton publishes Bridge for amd64 only" >&2; exit 1; }

log() { printf '==> %s\n' "$*"; }

# ---------------------------------------------------------------- download and verify
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
DEB="protonmail-bridge_${VERSION}-1_amd64.deb"

fetch() { curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$WORK/$1" "$BASE_URL/$1"; }
log "Downloading Proton Mail Bridge $VERSION"
fetch "$DEB"
fetch "$DEB.sig"
fetch "bridge_pubkey.gpg"

export GNUPGHOME="$WORK/gnupg"
mkdir -m 700 "$GNUPGHOME"
gpg --batch --quiet --import "$WORK/bridge_pubkey.gpg" 2>/dev/null
if ! gpg --batch --with-colons --fingerprint 2>/dev/null | grep -q "^fpr:::::::::${PROTON_BRIDGE_KEY_FPR}:"; then
  echo "The downloaded key is not Proton's Bridge key ${PROTON_BRIDGE_KEY_FPR}: aborting" >&2
  exit 1
fi
# VALIDSIG's last field is the fingerprint of the primary key that made the signature.
STATUS="$(gpg --batch --status-fd 1 --verify "$WORK/$DEB.sig" "$WORK/$DEB" 2>/dev/null || true)"
if ! printf '%s\n' "$STATUS" | grep -Eq "^\[GNUPG:\] VALIDSIG .* ${PROTON_BRIDGE_KEY_FPR}\$"; then
  echo "Signature verification of $DEB FAILED: aborting" >&2
  exit 1
fi
log "Signature verified (key ${PROTON_BRIDGE_KEY_FPR})"
log "SHA-256 $(sha256sum "$WORK/$DEB" | cut -d' ' -f1)"

if [ -n "$DOWNLOAD_ONLY" ]; then
  mkdir -p "$DOWNLOAD_ONLY"
  cp "$WORK/$DEB" "$WORK/$DEB.sig" "$DOWNLOAD_ONLY/"
  log "Saved to $DOWNLOAD_ONLY"
  exit 0
fi

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo) to install" >&2; exit 1; }

# ---------------------------------------------------------------- package (pinned)
INSTALLED="$(dpkg-query -W -f='${Version}' protonmail-bridge 2>/dev/null || true)"
if [ "${INSTALLED%%-*}" = "$VERSION" ]; then
  log "protonmail-bridge $VERSION already installed"
else
  log "Installing protonmail-bridge $VERSION (was: ${INSTALLED:-none})"
  apt-get install -y "$WORK/$DEB"
fi
# Upgrades are a deliberate decision: the gRPC interface is internal to Bridge.
apt-mark hold protonmail-bridge >/dev/null
apt-get install -y --no-install-recommends pass gnupg >/dev/null

# ---------------------------------------------------------------- service user and instance
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  log "Creating system user $SERVICE_USER"
  useradd --system --home-dir "$STATE_ROOT" --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_ROOT"

INST="$STATE_ROOT/$INSTANCE"
for d in "$INST" "$INST/config" "$INST/data" "$INST/cache" "$INST/gnupg" "$INST/password-store"; do
  [ -d "$d" ] || install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$d"
done

as_bridge() {
  runuser -u "$SERVICE_USER" -- env HOME="$INST" GNUPGHOME="$INST/gnupg" PASSWORD_STORE_DIR="$INST/password-store" "$@"
}

# Keychain for a headless server: `pass` with a dedicated GPG key. The key has no
# passphrase (Bridge must start unattended): it is protected by the 0700 directory
# of the service user only. Use a Secret Service provider instead if you need more.
if ! as_bridge gpg --batch --list-secret-keys --with-colons 2>/dev/null | grep -q '^sec'; then
  log "Generating the keychain GPG key for instance $INSTANCE"
  as_bridge gpg --batch --quiet --passphrase '' --quick-gen-key "Proton Bridge $INSTANCE <bridge-$INSTANCE@localhost>" default default never
fi
if [ ! -f "$INST/password-store/.gpg-id" ]; then
  KEY="$(as_bridge gpg --batch --list-secret-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}')"
  as_bridge pass init "$KEY" >/dev/null
  log "pass keychain initialised"
fi

# ---------------------------------------------------------------- systemd
UNIT_SRC="$SCRIPT_DIR/systemd/protonmail-bridge@.service"
if [ ! -f /etc/systemd/system/protonmail-bridge@.service ]; then
  install -m 0644 "$UNIT_SRC" /etc/systemd/system/protonmail-bridge@.service
  log "Installed protonmail-bridge@.service"
elif ! cmp -s "$UNIT_SRC" /etc/systemd/system/protonmail-bridge@.service; then
  log "Keeping your modified /etc/systemd/system/protonmail-bridge@.service (compare with $UNIT_SRC)"
fi
systemctl daemon-reload
systemctl enable --now "protonmail-bridge@$INSTANCE.service"

log "Done. Check the instance with:"
echo "  sudo -u $SERVICE_USER BRIDGE_SETTINGS_DIR=$INST/config/protonmail/bridge-v3 bridge-manager status"
echo "Then add Proton accounts with \`bridge-manager accounts add\` or from the web interface."
