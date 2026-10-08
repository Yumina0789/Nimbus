#!/usr/bin/env bash
# =============================================================================
#  Nimbus installer - deploy the Nimbus web admin panel for a vlmcsd KMS server
#
#  Nimbus is a one-file Python 3 (stdlib only) web panel that manages an
#  existing vlmcsd KMS daemon: it edits /etc/vlmcsd.ini, sends SIGHUP to hot
#  reload it, drives systemctl, and turns journald output into SQLite stats.
#
#  "One command, panel + KMS server": by default this script also makes sure
#  the vlmcsd service is present, using the upstream deploy script of the
#  (separate, independent) vlmcsd deployment project.
#
#    sudo bash install.sh                       # panel + vlmcsd (default)
#    sudo bash install.sh --no-vlmcsd           # panel only
#    sudo bash install.sh --port 8099 --bind 0.0.0.0 --kms-port 1688
#    sudo bash install.sh --unit vlmcsd --ini /etc/vlmcsd.ini
#    sudo bash install.sh --uninstall           # remove Nimbus, keep statistics + token
#    sudo bash install.sh --purge               # remove Nimbus and every leftover
#
#  Idempotent by design: re-running only refreshes the panel. The token, the
#  statistics database and - above all - vlmcsd itself survive an upgrade
#  untouched, and an existing vlmcsd install is never reinstalled.
#
#  !! NOT VERIFIED ON A REAL LINUX HOST !!
#  This installer, the systemd unit it writes and the real-mode backend of the
#  panel were developed on a Windows box and checked with "bash -n" and
#  "shellcheck" only. Nobody has run them against a live vlmcsd server yet.
#  Test on a throwaway VM first, and read the notes inside nimbus.service
#  about the hardening switches and the more conservative alternative.
# =============================================================================
set -euo pipefail

PANEL_VERSION="0.1.0"
PANEL_DIR="/usr/local/lib/nimbus"
UNIT_PATH="/etc/systemd/system/nimbus.service"
TOKEN_FILE="/etc/nimbus.token"
DATA_DIR="/var/lib/nimbus"
PYTHON_BIN="/usr/bin/python3"

# The vlmcsd deployment project is a SEPARATE repository; Nimbus only calls its
# installer when the KMS service is missing. Override for forks or mirrors:
#   NIMBUS_KMS_INSTALLER_URL=/path/to/install.sh sudo -E bash install.sh
KMS_INSTALLER_URL="${NIMBUS_KMS_INSTALLER_URL:-https://raw.githubusercontent.com/Yumina0789/V1mc4d/main/deploy/install.sh}"

PORT=8099
BIND="127.0.0.1"
KMS_PORT=1688
WITH_VLMCSD=1
UNIT_NAME="vlmcsd"
INI_PATH="/etc/vlmcsd.ini"
ACTION="install"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

step() { printf '\n==> %s\n' "$*"; }
log()  { printf '    %s\n' "$*"; }
warn() { printf '  ! %s\n' "$*" >&2; }
die()  { printf '  x %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
Nimbus installer - web admin panel for the vlmcsd KMS service

Usage: sudo bash install.sh [options]

Panel options
  --port N          panel TCP port                       (default: 8099)
  --bind ADDR       panel bind address                    (default: 127.0.0.1)
  --unit NAME       systemd unit Nimbus manages           (default: vlmcsd)
  --ini PATH        vlmcsd config file Nimbus edits       (default: /etc/vlmcsd.ini)

KMS (vlmcsd) options
  --with-vlmcsd     install vlmcsd too when it is missing (default: ON)
  --no-vlmcsd       panel only, never touch the KMS service
  --kms-port N      KMS client port used for a fresh vlmcsd install (default: 1688)
                    this is NOT the panel --port; the two are separate knobs

Removal
  --uninstall       stop and remove Nimbus: the systemd unit and
                    /usr/local/lib/nimbus. /var/lib/nimbus (statistics database)
                    and /etc/nimbus.token are KEPT, so a later reinstall reuses
                    the same token and the same activation history.
                    vlmcsd itself is never touched.
  --purge           same as --uninstall, and additionally delete the data
                    directory /var/lib/nimbus, the token file and every
                    remaining Nimbus leftover (private state dir, runtime dir)

Other
  -h, --help        show this help and exit

A normal install writes
  /usr/local/lib/nimbus/nimbus.py, ui.html   the panel itself
  /etc/systemd/system/nimbus.service         systemd unit (see nimbus.service)
  /etc/nimbus.token                          access token, mode 600
  /var/lib/nimbus/nimbus.db                  SQLite statistics database

Re-running the installer is safe: it refreshes the panel and the unit, reuses an
existing token and the existing statistics database, and skips vlmcsd when it is
already installed. --uninstall keeps the token and the statistics on purpose, so
"uninstall then install again" comes back with the same history.
USAGE
}

# ---------------------------------------------------------------------------
# Argument parsing happens before any privilege or dependency check, so that
# "bash install.sh --help" works for unprivileged users and on machines that
# have neither vlmcsd nor systemd.
# ---------------------------------------------------------------------------
while [ "$#" -gt 0 ]; do
  case "$1" in
    --port)
      [ "$#" -ge 2 ] || die "--port needs a value"
      PORT="$2"; shift 2 ;;
    --bind)
      [ "$#" -ge 2 ] || die "--bind needs a value"
      BIND="$2"; shift 2 ;;
    --kms-port)
      [ "$#" -ge 2 ] || die "--kms-port needs a value"
      KMS_PORT="$2"; shift 2 ;;
    --unit)
      [ "$#" -ge 2 ] || die "--unit needs a value"
      UNIT_NAME="$2"; shift 2 ;;
    --ini)
      [ "$#" -ge 2 ] || die "--ini needs a value"
      INI_PATH="$2"; shift 2 ;;
    --with-vlmcsd) WITH_VLMCSD=1; shift ;;
    --no-vlmcsd)   WITH_VLMCSD=0; shift ;;
    --uninstall)   ACTION="uninstall"; shift ;;
    --purge)       ACTION="purge"; shift ;;
    -h|--help)     usage; exit 0 ;;
    *)             die "unknown option: $1 (try --help)" ;;
  esac
done

case "$PORT" in
  ''|*[!0-9]*) die "--port must be a number, got: $PORT" ;;
esac
case "$KMS_PORT" in
  ''|*[!0-9]*) die "--kms-port must be a number, got: $KMS_PORT" ;;
esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  die "--port out of range: $PORT"
fi
if [ "$KMS_PORT" -lt 1 ] || [ "$KMS_PORT" -gt 65535 ]; then
  die "--kms-port out of range: $KMS_PORT"
fi

if [ "$(id -u)" -ne 0 ]; then
  die "please run as root: sudo bash install.sh"
fi

# ---------------------------------------------------------------------------
# Environment checks
# ---------------------------------------------------------------------------
check_python() {
  if ! command -v python3 >/dev/null 2>&1; then
    die "python3 not found - install Python 3.8 or newer first"
  fi
  local ver major minor
  ver="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
  major="${ver%%.*}"
  minor="${ver##*.}"
  if [ "$major" -lt 3 ]; then
    die "Nimbus needs Python 3.8+, found $ver"
  fi
  if [ "$major" -eq 3 ] && [ "$minor" -lt 8 ]; then
    die "Nimbus needs Python 3.8+, found $ver"
  fi
  log "python3 $ver"
  if [ ! -x "$PYTHON_BIN" ]; then
    warn "$PYTHON_BIN does not exist, but the systemd unit calls it"
    warn "point it at your interpreter, e.g.: ln -s /usr/bin/python3.11 $PYTHON_BIN"
  fi
}

# Sets KMS_PRESENT to 1 when a vlmcsd unit or binary can be found.
detect_kms() {
  KMS_PRESENT=0
  if systemctl cat "$UNIT_NAME" >/dev/null 2>&1; then
    KMS_PRESENT=1
  fi
  if [ -x /usr/local/bin/vlmcsd ]; then
    KMS_PRESENT=1
  fi
}

ensure_vlmcsd() {
  KMS_PRESENT=0
  detect_kms
  if [ "$KMS_PRESENT" -eq 1 ]; then
    log "vlmcsd already present (unit: $UNIT_NAME) - not reinstalling it"
    return 0
  fi
  if [ "$WITH_VLMCSD" -ne 1 ]; then
    warn "no vlmcsd detected and --no-vlmcsd was given: panel only"
    warn "the panel will honestly report 'no KMS service detected' until one exists"
    return 0
  fi

  step "Installing the vlmcsd KMS service (port $KMS_PORT)"
  log "source: $KMS_INSTALLER_URL"
  # A failure here must never block the panel, so the exit code is inspected
  # instead of being propagated by "set -e".
  local rc=0
  set +e
  curl -fsSL "$KMS_INSTALLER_URL" | bash -s -- --port "$KMS_PORT"
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    log "vlmcsd installer finished (rc=0)"
  else
    warn "vlmcsd installation failed with rc=$rc (network, mirror or permission problem)"
    warn "the panel is still being installed; fix the KMS side and re-run this script"
  fi
}

# ---------------------------------------------------------------------------
# systemd unit
# ---------------------------------------------------------------------------
unit_body() {
  # Prefer the repository template next to this script; fall back to the copy
  # embedded below so that "curl | bash" style installs still work.
  if [ -f "$SCRIPT_DIR/nimbus.service" ]; then
    sed -e "s|@BIND@|$BIND|g" \
        -e "s|@PORT@|$PORT|g" \
        -e "s|@UNIT@|$UNIT_NAME|g" \
        -e "s|@INI@|$INI_PATH|g" \
        "$SCRIPT_DIR/nimbus.service"
    return 0
  fi
  cat <<EOF
[Unit]
Description=Nimbus - web admin panel for the vlmcsd KMS service
Documentation=https://github.com/Yumina0789/Nimbus
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=$PYTHON_BIN $PANEL_DIR/nimbus.py --mode real --bind $BIND --port $PORT --data-dir $DATA_DIR --token-file $TOKEN_FILE --unit $UNIT_NAME --ini $INI_PATH
Restart=on-failure
RestartSec=3
StateDirectory=nimbus
StateDirectoryMode=0700
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=${INI_PATH} ${INI_PATH}.bak ${INI_PATH}.tmp

[Install]
WantedBy=multi-user.target
EOF
}

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
install_panel() {
  if [ ! -f "$SCRIPT_DIR/nimbus.py" ]; then
    die "nimbus.py not found next to install.sh"
  fi
  if [ ! -f "$SCRIPT_DIR/ui.html" ]; then
    die "ui.html not found next to install.sh"
  fi

  step "Installing panel files into $PANEL_DIR"
  install -d -m 0755 "$PANEL_DIR"
  install -m 0644 "$SCRIPT_DIR/nimbus.py" "$PANEL_DIR/nimbus.py"
  install -m 0644 "$SCRIPT_DIR/ui.html" "$PANEL_DIR/ui.html"
  log "nimbus.py + ui.html installed"

  step "Preparing data directory $DATA_DIR"
  install -d -m 0700 "$DATA_DIR"
  log "the SQLite database (nimbus.db) lives here"

  step "Preparing token $TOKEN_FILE"
  if [ -s "$TOKEN_FILE" ]; then
    log "token already exists - keeping it (an upgrade never logs you out)"
  else
    python3 -c 'import secrets; print(secrets.token_urlsafe(24))' > "$TOKEN_FILE"
    log "generated a fresh random token"
  fi
  chmod 0600 "$TOKEN_FILE"

  step "Writing systemd unit $UNIT_PATH"
  unit_body > "$UNIT_PATH"
  chmod 0644 "$UNIT_PATH"
  log "unit written (bind $BIND, port $PORT, unit $UNIT_NAME, ini $INI_PATH)"

  step "Enabling and (re)starting the panel"
  systemctl daemon-reload
  systemctl enable nimbus >/dev/null 2>&1 || warn "systemctl enable nimbus failed"
  if systemctl restart nimbus; then
    log "nimbus restarted"
  else
    warn "nimbus failed to start - inspect: systemctl status nimbus; journalctl -u nimbus -n 50"
  fi
}

summary() {
  local token=""
  if [ -r "$TOKEN_FILE" ]; then
    token="$(head -n1 "$TOKEN_FILE")"
  fi

  step "Done"
  log "panel URL  : http://$BIND:$PORT/?token=$token"
  log "panel bind : $BIND:$PORT"
  log "KMS port   : $KMS_PORT (unit $UNIT_NAME, config $INI_PATH)"
  log "statistics : $DATA_DIR/nimbus.db"
  log "token file : $TOKEN_FILE (mode 600)"
  printf '\n    systemctl is-active %s nimbus ->\n' "$UNIT_NAME"
  systemctl is-active "$UNIT_NAME" nimbus || true

  case "$BIND" in
    127.0.0.1|::1|localhost)
      log "loopback only: reach the panel through an SSH tunnel or a Caddy reverse proxy" ;;
    *)
      warn "the panel is bound to $BIND - put HTTPS (Caddy) plus the token in front of it" ;;
  esac
  log "the panel and the KMS service are independent: stopping the panel does not stop activation"
}

# ---------------------------------------------------------------------------
# Uninstall / purge - Nimbus only, never vlmcsd
# ---------------------------------------------------------------------------
do_uninstall() {
  step "Removing Nimbus (vlmcsd is left completely alone)"
  systemctl stop nimbus >/dev/null 2>&1 || true
  systemctl disable nimbus >/dev/null 2>&1 || true
  rm -f "$UNIT_PATH"
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -rf "${PANEL_DIR:?}"
  log "removed: $UNIT_PATH, $PANEL_DIR"

  if [ "$ACTION" = "purge" ]; then
    rm -rf "${DATA_DIR:?}" "${PANEL_DIR:?}/nimbus.db" /var/lib/private/nimbus /run/nimbus
    rm -f "$TOKEN_FILE"
    log "purged: data directory, token file and every leftover"
  else
    log "kept: $DATA_DIR (statistics database) and $TOKEN_FILE"
    log "a later reinstall reuses the same token and the same history"
    log "use --purge instead if you want those deleted as well"
  fi

  log "vlmcsd, its unit, its config and its logs were not modified"
  log "to remove the KMS service too, use the installer of the vlmcsd project"
}

if [ "$ACTION" = "uninstall" ] || [ "$ACTION" = "purge" ]; then
  do_uninstall
  exit 0
fi

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
printf 'Nimbus %s installer\n' "$PANEL_VERSION"
check_python
ensure_vlmcsd
install_panel
summary
