#!/usr/bin/env sh
#
# install-antigravity-ide.sh — reusable installer for Google's Antigravity IDE
# (Google's agentic VS Code/Electron fork), linux-x64 builds.
#
# Idempotent: safe to re-run; skips work that is already done. Runs anywhere
# with curl + tar; installs system-wide as root, per-user otherwise.
#
# Usage:
#   sh scripts/install-antigravity-ide.sh [options]
#
# Options:
#   --version <v>       Release version tag           (default: 2.5.5-4923483625488384)
#   --arch <a>          Download arch                 (default: linux-x64)
#   --install-dir <dir> Where to place the app        (default: /opt/Antigravity IDE)
#   --bin-dir <dir>     Where to link the CLI         (default: /usr/local/bin)
#   --url <url>         Override the download URL
#   --force             Re-download / re-extract even if already installed
#   --no-checksum       Skip SHA-256 verification (not recommended)
#   --uninstall         Remove the app, CLI link and desktop entry
#   -h, --help          Show this help
#
# Environment overrides (same meaning as the flags):
#   ANTIGRAVITY_VERSION, ANTIGRAVITY_ARCH, ANTIGRAVITY_INSTALL_DIR,
#   ANTIGRAVITY_BIN_DIR, ANTIGRAVITY_URL, ANTIGRAVITY_SHA256, ANTIGRAVITY_DOWNLOAD_DIR
#
# Examples:
#   sh scripts/install-antigravity-ide.sh
#   sh scripts/install-antigravity-ide.sh --version 2.5.5-4923483625488384 --force
#   ANTIGRAVITY_INSTALL_DIR="$HOME/.local/share/Antigravity IDE" sh scripts/install-antigravity-ide.sh
#
set -eu

DEFAULT_VERSION='2.5.5-4923483625488384'
# SHA-256 of the pinned default release tarball (linux-x64).
DEFAULT_SHA256='0c5233b297d2b3aebb61af49f8944012c2953d361a5ebb16978490636917f831'

VERSION="${ANTIGRAVITY_VERSION:-$DEFAULT_VERSION}"
ARCH="${ANTIGRAVITY_ARCH:-linux-x64}"
INSTALL_DIR="${ANTIGRAVITY_INSTALL_DIR:-/opt/Antigravity IDE}"
BIN_DIR="${ANTIGRAVITY_BIN_DIR:-/usr/local/bin}"
URL="${ANTIGRAVITY_URL:-}"
DOWNLOAD_DIR="${ANTIGRAVITY_DOWNLOAD_DIR:-${TMPDIR:-/tmp}}"
SHA256="${ANTIGRAVITY_SHA256:-}"
FORCE=0
NO_CHECKSUM=0
UNINSTALL=0

die() { printf 'error: %s\n' "$1" >&2; exit 1; }
log() { printf '==> %s\n' "$1"; }

usage() { sed -n '2,40p' "$0" | grep -v '^#$' | sed 's/^# \{0,1\}//'; }

need_arg() { [ $# -ge 2 ] || die "$1 requires a value"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version)     need_arg "$@"; VERSION="$2"; shift 2 ;;
    --arch)        need_arg "$@"; ARCH="$2"; shift 2 ;;
    --install-dir) need_arg "$@"; INSTALL_DIR="$2"; shift 2 ;;
    --bin-dir)     need_arg "$@"; BIN_DIR="$2"; shift 2 ;;
    --url)         need_arg "$@"; URL="$2"; shift 2 ;;
    --force)       FORCE=1; shift ;;
    --no-checksum) NO_CHECKSUM=1; shift ;;
    --uninstall)   UNINSTALL=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

# Only the pinned default release has a known checksum; other versions must be
# pinned explicitly via ANTIGRAVITY_SHA256 (or skipped with --no-checksum).
if [ -z "$SHA256" ] && [ "$VERSION" = "$DEFAULT_VERSION" ] && [ "$ARCH" = "linux-x64" ]; then
  SHA256="$DEFAULT_SHA256"
fi

[ -n "$URL" ] || URL="https://edgedl.me.gvt1.com/edgedl/release2/j0qc3/antigravity/stable/${VERSION}/${ARCH}/Antigravity%20IDE.tar.gz"

command -v curl >/dev/null 2>&1      || die "curl is required"
command -v tar >/dev/null 2>&1       || die "tar is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"

case "$INSTALL_DIR" in
  ""|"/") die "refusing unsafe install dir: '$INSTALL_DIR'" ;;
esac

IS_ROOT=0
[ "$(id -u)" = "0" ] && IS_ROOT=1

# ----------------------------- uninstall path -------------------------------
if [ "$UNINSTALL" = "1" ]; then
  log "removing $INSTALL_DIR"
  rm -rf -- "$INSTALL_DIR"
  for f in \
    "$BIN_DIR/antigravity-ide" \
    /usr/share/applications/antigravity-ide.desktop \
    "${HOME:-/root}/.local/share/applications/antigravity-ide.desktop"
  do
    if [ -e "$f" ] || [ -L "$f" ]; then
      rm -f -- "$f"
      log "removed $f"
    fi
  done
  log "Antigravity IDE uninstalled"
  exit 0
fi

# ------------------------- per-user fallback paths --------------------------
if [ "$IS_ROOT" = "0" ] && [ ! -w "$(dirname "$INSTALL_DIR")" ]; then
  INSTALL_DIR="${HOME:-/root}/.local/share/Antigravity IDE"
  log "no write access to default location; installing to $INSTALL_DIR"
fi
if [ "$IS_ROOT" = "0" ] && [ ! -w "$BIN_DIR" ]; then
  BIN_DIR="${HOME:-/root}/.local/bin"
  mkdir -p "$BIN_DIR"
  log "no write access to default bin dir; linking CLI in $BIN_DIR"
  case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) log "note: add $BIN_DIR to your PATH to use 'antigravity-ide'" ;;
  esac
fi

# ------------------------------- download -----------------------------------
TARBALL="$DOWNLOAD_DIR/antigravity-ide-$VERSION-$ARCH.tar.gz"
mkdir -p "$DOWNLOAD_DIR"

if [ -f "$TARBALL" ]; then
  log "using cached download: $TARBALL"
else
  log "downloading Antigravity IDE $VERSION ($ARCH)"
  log "  from $URL"
  curl -fSL --retry 3 --connect-timeout 20 -o "$TARBALL.tmp" "$URL"
  mv "$TARBALL.tmp" "$TARBALL"
fi

# ------------------------------ verification --------------------------------
ACTUAL_SHA=$(sha256sum "$TARBALL" | cut -d' ' -f1)
if [ "$NO_CHECKSUM" = "1" ]; then
  log "skipping checksum verification (--no-checksum); actual sha256: $ACTUAL_SHA"
elif [ -z "$SHA256" ]; then
  log "no checksum pinned for version $VERSION; actual sha256: $ACTUAL_SHA"
  log "pin it with ANTIGRAVITY_SHA256=<digest> to enforce integrity"
else
  if [ "$ACTUAL_SHA" != "$SHA256" ]; then
    die "checksum mismatch for $TARBALL
  expected: $SHA256
  actual:   $ACTUAL_SHA
If this is a new official release, pin its digest with ANTIGRAVITY_SHA256."
  fi
  log "checksum OK ($ACTUAL_SHA)"
fi

# -------------------------------- install -----------------------------------
if [ -x "$INSTALL_DIR/antigravity-ide" ] && [ "$FORCE" = "0" ]; then
  log "already installed at $INSTALL_DIR (use --force to reinstall)"
else
  log "extracting into $INSTALL_DIR"
  STAGING="$DOWNLOAD_DIR/antigravity-extract.$$"
  trap 'rm -rf "$STAGING" "$TARBALL.tmp"' EXIT
  mkdir -p "$STAGING"
  tar -xzf "$TARBALL" -C "$STAGING"
  [ -d "$STAGING/Antigravity IDE" ] || die "unexpected archive layout (no 'Antigravity IDE/' root)"
  mkdir -p "$(dirname "$INSTALL_DIR")"
  rm -rf -- "$INSTALL_DIR"
  mv "$STAGING/Antigravity IDE" "$INSTALL_DIR"
  rm -rf "$STAGING"
  trap - EXIT
  log "extracted $(du -sh "$INSTALL_DIR" | cut -f1) (version $(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$INSTALL_DIR/resources/app/package.json" | head -1))"
fi

# ------------------------------- CLI symlink --------------------------------
mkdir -p "$BIN_DIR"
ln -sfn "$INSTALL_DIR/bin/antigravity-ide" "$BIN_DIR/antigravity-ide"
log "CLI linked: $BIN_DIR/antigravity-ide -> $INSTALL_DIR/bin/antigravity-ide"

# ----------------------------- desktop entry --------------------------------
DESKTOP_DIR="/usr/share/applications"
if [ "$IS_ROOT" = "0" ] && [ ! -w "$DESKTOP_DIR" ]; then
  DESKTOP_DIR="${HOME:-/root}/.local/share/applications"
fi
mkdir -p "$DESKTOP_DIR"
printf '%s\n' \
  '[Desktop Entry]' \
  'Name=Antigravity IDE' \
  "Comment=Google's agentic development environment" \
  "Exec=$INSTALL_DIR/antigravity-ide" \
  "Icon=$INSTALL_DIR/resources/app/resources/linux/code.png" \
  'Terminal=false' \
  'Type=Application' \
  'Categories=Development;IDE;' \
  'StartupWMClass=antigravity-ide' \
  > "$DESKTOP_DIR/antigravity-ide.desktop"
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
fi
log "desktop entry installed: $DESKTOP_DIR/antigravity-ide.desktop"

# ------------------------------- verification -------------------------------
log "verifying CLI (headless)"
VERIFY_OK=1
if [ "$IS_ROOT" = "1" ]; then
  "$INSTALL_DIR/bin/antigravity-ide" --no-sandbox \
    --user-data-dir="$DOWNLOAD_DIR/antigravity-verify" \
    --list-extensions >/dev/null 2>&1 || VERIFY_OK=0
else
  "$INSTALL_DIR/bin/antigravity-ide" --list-extensions >/dev/null 2>&1 || VERIFY_OK=0
fi
if [ "$VERIFY_OK" = "1" ]; then
  log "verification passed"
else
  log "verification inconclusive (headless display?); the binary is installed at:"
  log "  $INSTALL_DIR/antigravity-ide"
fi

log "done. launch with: antigravity-ide"
if [ "$IS_ROOT" = "1" ]; then
  log "running as root? use: antigravity-ide --no-sandbox --user-data-dir=<dir>"
fi
