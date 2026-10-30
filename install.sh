#!/usr/bin/env bash
#
# rdpshot installer
#
# Detects the Linux distribution, installs any missing build tooling,
# compiles the project and installs it under /usr/local/rdpshot with a
# symlink at /usr/local/bin/rdpshot.
#
# The installer is idempotent:
#   * already installed system packages are never downloaded again,
#   * an up-to-date Go toolchain is left untouched,
#   * the project is only rebuilt when the sources changed (or --force).
#
# Usage: sudo ./install.sh [options]
set -Eeuo pipefail

SCRIPT_VERSION="1.0.0"
MIN_GO_VERSION="1.22"
DEFAULT_GO_VERSION="1.27.2"

INSTALL_PREFIX="/usr/local/rdpshot"
BIN_LINK_DIR="/usr/local/bin"
SOURCE_DIR=""
FORCE_REBUILD=0
SKIP_CAPTURE=0
UNINSTALL=0
DRY_RUN=0
ASSUME_YES=0
LOG_FILE=""

# ---------------------------------------------------------------- output ---

# terminal_width returns the usable terminal width, clamped to a sane value.
terminal_width() {
  local width="${COLUMNS:-}"
  if [[ ! "$width" =~ ^[0-9]+$ ]] || ((width < 40)); then
    width="$(tput cols 2>/dev/null || true)"
  fi
  if [[ ! "$width" =~ ^[0-9]+$ ]] || ((width < 40)); then
    width=80
  fi
  printf '%s' "$width"
}

init_colors() {
  # In-place progress rendering needs a real terminal; otherwise every update
  # is written as its own line so logs stay readable.
  if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
    INTERACTIVE=1
  else
    INTERACTIVE=0
  fi
  TERM_WIDTH="$(terminal_width)"

  # Size the bar to the terminal so the surrounding text keeps its room.
  if ((TERM_WIDTH >= 100)); then
    BAR_WIDTH=30
  elif ((TERM_WIDTH >= 80)); then
    BAR_WIDTH=22
  elif ((TERM_WIDTH >= 60)); then
    BAR_WIDTH=16
  else
    BAR_WIDTH=10
  fi

  if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]]; then
    C_RESET=$'\033[0m' C_BOLD=$'\033[1m' C_DIM=$'\033[2m'
    C_RED=$'\033[31m' C_GREEN=$'\033[32m' C_YELLOW=$'\033[33m'
    C_BLUE=$'\033[34m' C_CYAN=$'\033[36m'
  else
    C_RESET='' C_BOLD='' C_DIM='' C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_CYAN=''
  fi
  # Unicode glyphs only when the locale can render them.
  case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
    *UTF-8*|*utf8*|*UTF8*|*utf-8*) BAR_FULL='█'; BAR_EMPTY='░'; GLYPH_OK='✓'; GLYPH_SKIP='·'; GLYPH_WARN='!'; GLYPH_ERR='✗'; SPIN=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏) ;;
    *) BAR_FULL='#'; BAR_EMPTY='-'; GLYPH_OK='OK'; GLYPH_SKIP='..'; GLYPH_WARN='!!'; GLYPH_ERR='ERR'; SPIN=(- \\ \| /) ;;
  esac
}

BAR_WIDTH=22
STEP=0
TOTAL_STEPS=7
STEP_STARTED=0
INTERACTIVE=0
TERM_WIDTH=80
# LINE_DIRTY tracks whether the progress line currently occupies the screen.
LINE_DIRTY=0

# progress_clear erases the in-place progress line so regular messages never
# collide with it.
progress_clear() {
  if ((LINE_DIRTY)); then
    printf '\r\033[K'
    LINE_DIRTY=0
  fi
}

# progress_finish keeps the last rendered line on screen and moves the cursor
# below it.
progress_finish() {
  if ((LINE_DIRTY)); then
    printf '\n'
    LINE_DIRTY=0
  fi
}

# draw_bar <percent> <state-glyph> <message>
# Updates the single progress line in place on a terminal, so the bar grows
# without scrolling the log.
draw_bar() {
  local pct=$1 glyph=$2 message=$3
  local filled=$(( pct * BAR_WIDTH / 100 ))
  (( filled > BAR_WIDTH )) && filled=$BAR_WIDTH
  local bar='' i
  for ((i = 0; i < filled; i++)); do bar+="$BAR_FULL"; done
  for ((i = filled; i < BAR_WIDTH; i++)); do bar+="$BAR_EMPTY"; done

  # Truncate long messages so the line never wraps; a wrapped line could not be
  # overwritten in place anymore.
  local text="$message"
  local max_text=$(( TERM_WIDTH - BAR_WIDTH - 15 ))
  if ((max_text > 3)) && ((${#text} > max_text)); then
    text="${text:0:max_text-3}..."
  fi

  if ((INTERACTIVE)); then
    printf '\r\033[K%s %s[%s%s%s]%s %3d%%  %s %s%s%s' \
      "$C_DIM" "$C_BOLD" "$C_CYAN" "$bar" "$C_BOLD" "$C_RESET" "$pct" \
      "$glyph" "$C_DIM" "$text" "$C_RESET"
    LINE_DIRTY=1
  else
    printf '%s %s[%s%s%s]%s %3d%%  %s %s%s%s\n' \
      "$C_DIM" "$C_BOLD" "$C_CYAN" "$bar" "$C_BOLD" "$C_RESET" "$pct" \
      "$glyph" "$C_DIM" "$text" "$C_RESET"
  fi
}

# step_line <state> <glyph> <message> — final state of a step, drawn in place
step_line() {
  local state=$1 glyph=$2 message=$3
  local color="$C_GREEN"
  case "$state" in
    skipped) color="$C_DIM" ;;
    warn) color="$C_YELLOW" ;;
    failed) color="$C_RED" ;;
  esac
  draw_bar "$((STEP * 100 / TOTAL_STEPS))" "$color$glyph$C_RESET" "$message"
}

info()  { progress_clear; printf '%s %s%s%s\n' "$C_DIM" "$C_BLUE" "$1" "$C_RESET"; }
warn()  { progress_clear; printf '%s %s[!]%s %s\n' "$C_DIM" "$C_YELLOW" "$C_RESET" "$1" >&2; }
error() { progress_clear; printf '%s %s[✗]%s %s\n' "$C_BOLD" "$C_RED" "$C_RESET" "$1" >&2; }
die()   { error "$1"; exit "${2:-1}"; }

print_header() {
  printf '\n%s %srdpshot%s %sinstaller v%s%s\n' "$C_BOLD" "$C_CYAN" "$C_RESET" "$C_DIM" "$SCRIPT_VERSION" "$C_RESET"
  printf '%s%s%s\n\n' "$C_DIM" "--------------------------------------------------------------" "$C_RESET"
}

# run_step <message> <command...> — executes quietly, animating progress
run_step() {
  local message=$1
  shift
  STEP=$((STEP + 1))
  STEP_STARTED=$SECONDS
  local spin=0
  : >"$LOG_FILE"
  "$@" >>"$LOG_FILE" 2>&1 &
  local pid=$!
  # Only animate on a terminal; redirected output would otherwise turn every
  # spinner frame into a separate log line.
  if ((INTERACTIVE)); then
    while kill -0 "$pid" 2>/dev/null; do
      draw_bar "$((STEP * 100 / TOTAL_STEPS))" "${SPIN[$((spin % ${#SPIN[@]}))]}" "$message ..."
      spin=$((spin + 1))
      sleep 0.1
    done
  fi
  local rc=0
  wait "$pid" || rc=$?
  if ((rc != 0)); then
    step_line failed "$GLYPH_ERR" "$message"
    progress_finish
    printf '%s%s last output %s\n' "$C_DIM" "$C_YELLOW" "$C_RESET" >&2
    tail -n 12 "$LOG_FILE" | sed 's/^/    /' >&2
    die "$message failed (see output above)"
  fi
  step_line done "$GLYPH_OK" "$message ($((SECONDS - STEP_STARTED))s)"
}

# skip_step <message> — advances the bar without doing work
skip_step() {
  STEP=$((STEP + 1))
  step_line skipped "$GLYPH_SKIP" "$1 (skipped)"
}

# ------------------------------------------------------------- helpers ---

have() { command -v "$1" >/dev/null 2>&1; }

# version_ge <current> <minimum>
version_ge() {
  [[ "$1" == "$2" ]] && return 0
  printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

go_version_of() {
  "$1" version 2>/dev/null | sed -n 's/.*go\([0-9][0-9.]*\).*/\1/p' | head -n1
}

require_root() {
  [[ "$DRY_RUN" -eq 1 ]] && return 0
  if [[ "$(id -u)" -ne 0 ]]; then
    if have sudo; then
      info "root privileges required; re-running with sudo"
      exec sudo -- "$0" "$@"
    fi
    die "root privileges are required (run with sudo)"
  fi
}

confirm() {
  [[ "$ASSUME_YES" -eq 1 || "$DRY_RUN" -eq 1 ]] && return 0
  if [[ ! -t 0 ]]; then
    return 0
  fi
  printf ' %sContinue? [Y/n]%s ' "$C_DIM" "$C_RESET"
  local answer
  read -r answer
  [[ -z "$answer" || "$answer" =~ ^[Yy] ]]
}

# --------------------------------------------------------- detection -----

detect_os() {
  OS_ID="unknown"
  OS_NAME="Unknown Linux"
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    OS_ID="$(. /etc/os-release && echo "${ID:-unknown}")"
    OS_NAME="$(. /etc/os-release && echo "${PRETTY_NAME:-$ID}")"
  fi
  have apt-get && PM=apt && return 0
  have dnf && PM=dnf && return 0
  have yum && PM=yum && return 0
  have pacman && PM=pacman && return 0
  have apk && PM=apk && return 0
  have zypper && PM=zypper && return 0
  die "no supported package manager found (apt/dnf/yum/pacman/apk/zypper)"
}

package_installed() {
  case "$PM" in
    apt) dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed' ;;
    dnf | yum | zypper) rpm -q "$1" >/dev/null 2>&1 ;;
    pacman) pacman -Q "$1" >/dev/null 2>&1 ;;
    apk) apk info -e "$1" >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}

# install_packages <pkg...> — installs only the packages that are missing
install_packages() {
  local missing=() pkg
  for pkg in "$@"; do
    package_installed "$pkg" || missing+=("$pkg")
  done
  if ((${#missing[@]} == 0)); then
    return 0
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "would install: ${missing[*]}"
    return 0
  fi
  case "$PM" in
    apt)
      apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${missing[@]}"
      ;;
    dnf) dnf install -y -q "${missing[@]}" ;;
    yum) yum install -y -q "${missing[@]}" ;;
    pacman) pacman -Sy --noconfirm --needed "${missing[@]}" ;;
    apk) apk add --no-cache "${missing[@]}" ;;
    zypper) zypper --non-interactive --quiet install "${missing[@]}" ;;
  esac
}

build_packages_for() {
  case "$PM" in
    apt) printf '%s\n' ca-certificates curl git make tar xz-utils build-essential ;;
    dnf | yum) printf '%s\n' ca-certificates curl git make tar xz gcc gcc-c++ ;;
    pacman) printf '%s\n' ca-certificates curl git make tar xz base-devel ;;
    apk) printf '%s\n' ca-certificates curl git make tar xz build-base ;;
    zypper) printf '%s\n' ca-certificates curl git make tar xz gcc gcc-c++ ;;
  esac
}

capture_packages_for() {
  case "$PM" in
    apt) printf '%s\n' freerdp2-x11 xvfb imagemagick tesseract-ocr ;;
    dnf | yum) printf '%s\n' freerdp xorg-x11-server-Xvfb ImageMagick tesseract ;;
    pacman) printf '%s\n' freerdp xorg-server-xvfb imagemagick tesseract ;;
    apk) printf '%s\n' freerdp xvfb imagemagick tesseract-ocr ;;
    zypper) printf '%s\n' freerdp xorg-x11-server-Xvfb ImageMagick tesseract-ocr ;;
  esac
}

# --------------------------------------------------------- go toolchain ---

# install_go_tarball downloads the pinned official Go release (cached) and
# verifies it against the published SHA-256 checksum.
install_go_tarball() {
  local arch
  case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    i386 | i686) arch=386 ;;
    armv6l | armv7l) arch=armv6l ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; return 1 ;;
  esac

  local cache="${RDSHOT_CACHE_DIR:-/var/cache/rdpshot}"
  mkdir -p "$cache"
  local tarball="go${GO_VERSION}.linux-${arch}.tar.gz"
  local url="https://go.dev/dl/${tarball}"

  if [[ -f "$cache/$tarball" ]]; then
    echo "using cached ${tarball}"
  else
    echo "downloading ${tarball}"
    curl -fsSL --retry 3 --connect-timeout 15 -o "$cache/$tarball.partial" "$url"
    mv "$cache/$tarball.partial" "$cache/$tarball"
  fi

  local want
  want="$(curl -fsSL --retry 3 --connect-timeout 15 "${url}.sha256" | tr -d '[:space:]' || true)"
  if [[ -n "$want" ]]; then
    echo "${want}  ${cache}/${tarball}" | sha256sum -c - >/dev/null
    echo "checksum verified"
  else
    echo "warning: checksum unavailable, continuing without verification" >&2
  fi

  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$cache/$tarball"
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
  ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
  echo "Go ${GO_VERSION} installed to /usr/local/go"
}

# step_go_toolchain installs Go only when no suitable toolchain is present.
step_go_toolchain() {
  local version=""
  if have go; then
    version="$(go_version_of go)"
    if [[ -n "$version" ]] && version_ge "$version" "$MIN_GO_VERSION"; then
      skip_step "Go ${version} already present"
      return 0
    fi
    warn "found go${version:-unknown}, ${MIN_GO_VERSION} or newer is required"
  elif [[ -x /usr/local/go/bin/go ]]; then
    version="$(go_version_of /usr/local/go/bin/go)"
    if [[ -n "$version" ]] && version_ge "$version" "$MIN_GO_VERSION"; then
      ln -sf /usr/local/go/bin/go /usr/local/bin/go
      ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
      skip_step "Go ${version} already installed"
      return 0
    fi
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    skip_step "Go toolchain ${GO_VERSION} (dry-run)"
    return 0
  fi
  run_step "Installing Go ${GO_VERSION} toolchain" install_go_tarball
}

# ------------------------------------------------------ source / build ---

# source_fingerprint hashes everything that ends up in the binary so an
# unchanged source tree is never rebuilt.
source_fingerprint() {
  (
    cd "$SOURCE_DIR" || exit 1
    find . \( -name '*.go' -o -name 'go.mod' -o -name 'go.sum' \) -type f -print0 2>/dev/null \
      | sort -z | xargs -0 sha256sum 2>/dev/null
    find ./web -type f -print0 2>/dev/null | sort -z | xargs -0 sha256sum 2>/dev/null
  ) | sha256sum | cut -d' ' -f1
}

build_version_tag() {
  if have git && git -C "$SOURCE_DIR" rev-parse --short HEAD >/dev/null 2>&1; then
    git -C "$SOURCE_DIR" describe --tags --always --dirty 2>/dev/null && return 0
  fi
  printf 'dev-%s' "$(date -u +%Y%m%d)"
}

do_build() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: would build bin/rdpshot (${VERSION_TAG})"
    return 0
  fi
  cd "$SOURCE_DIR"
  export CGO_ENABLED=0
  mkdir -p "$SOURCE_DIR/bin"
  go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION_TAG}" \
    -o "$SOURCE_DIR/bin/rdpshot" ./cmd/rdpshot
  echo "built bin/rdpshot (${VERSION_TAG})"
}

do_install() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: would install to $INSTALL_PREFIX and link $BIN_LINK_DIR/rdpshot"
    return 0
  fi
  install -d -m 0755 "$INSTALL_PREFIX/bin" "$INSTALL_PREFIX/wordlists" "$INSTALL_PREFIX/share"
  install -m 0755 "$SOURCE_DIR/bin/rdpshot" "$INSTALL_PREFIX/bin/rdpshot"

  local file
  for file in "$SOURCE_DIR"/wordlists/*.txt; do
    [[ -f "$file" ]] && install -m 0644 "$file" "$INSTALL_PREFIX/wordlists/"
  done
  for file in README.md plan.md LICENSE; do
    [[ -f "$SOURCE_DIR/$file" ]] && install -m 0644 "$SOURCE_DIR/$file" "$INSTALL_PREFIX/share/"
  done

  ln -sfn "$INSTALL_PREFIX/bin/rdpshot" "$BIN_LINK_DIR/rdpshot"
  printf '%s\n' "$NEW_HASH" >"$INSTALL_PREFIX/.source-hash"
  echo "installed to $INSTALL_PREFIX (symlink: $BIN_LINK_DIR/rdpshot)"
}

# install_capture_tools is best effort: missing optional tools must not fail
# the whole installation, they only disable screenshot capture.
install_capture_tools() {
  # shellcheck disable=SC2046
  install_packages $(capture_packages_for) || \
    echo "optional capture tools unavailable; screenshot capture will be disabled"
  return 0
}

preflight() {
  [[ -f "$SOURCE_DIR/cmd/rdpshot/main.go" ]] || {
    echo "cmd/rdpshot/main.go not found in $SOURCE_DIR" >&2
    return 1
  }
  [[ -f "$SOURCE_DIR/go.mod" ]] || { echo "go.mod not found in $SOURCE_DIR" >&2; return 1; }
  echo "source tree: $SOURCE_DIR"
  echo "target:      $INSTALL_PREFIX"
  echo "version:     ${VERSION_TAG}"
}

verify_install() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: would verify $INSTALL_PREFIX/bin/rdpshot"
    return 0
  fi
  [[ -x "$INSTALL_PREFIX/bin/rdpshot" ]] || { echo "binary missing after install" >&2; return 1; }
  [[ -L "$BIN_LINK_DIR/rdpshot" ]] || { echo "symlink missing after install" >&2; return 1; }
  "$BIN_LINK_DIR/rdpshot" version
}

do_uninstall() {
  printf '%s\n' "Removing $INSTALL_PREFIX and $BIN_LINK_DIR/rdpshot"
  confirm || die "uninstall aborted"
  [[ "$DRY_RUN" -eq 1 ]] && { info "dry-run: nothing removed"; return 0; }
  rm -f "$BIN_LINK_DIR/rdpshot"
  rm -rf "$INSTALL_PREFIX"
  printf '%s %sremoved%s\n' "$C_DIM" "$C_GREEN" "$C_RESET"
}

# --------------------------------------------------------------- usage ---

usage() {
  cat <<EOF
rdpshot installer v${SCRIPT_VERSION}

Usage: sudo ./install.sh [options]

Options:
  --prefix DIR            installation directory (default: /usr/local/rdpshot)
  --force                 rebuild even when the sources are unchanged
  --skip-capture-tools    do not install FreeRDP/Xvfb/ImageMagick
  --uninstall             remove the installation and the symlink
  --dry-run               show what would happen without changing anything
  --yes, -y               never ask for confirmation
  --no-color              disable colored output
  --version               print installer version
  --help, -h              show this help

Environment:
  GO_VERSION              Go toolchain to install (default: ${DEFAULT_GO_VERSION})
  RDSHOT_CACHE_DIR        download cache (default: /var/cache/rdpshot)
  NO_COLOR                disable colored output when set

The installer is idempotent: installed packages are never downloaded again,
an adequate Go toolchain is reused and the project is rebuilt only when the
sources changed. The binary is installed to <prefix>/bin/rdpshot and linked
from /usr/local/bin/rdpshot.
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --prefix) [[ $# -ge 2 ]] || die "--prefix requires a directory" 2; INSTALL_PREFIX="$2"; shift 2 ;;
      --prefix=*) INSTALL_PREFIX="${1#*=}"; shift ;;
      --force) FORCE_REBUILD=1; shift ;;
      --skip-capture-tools) SKIP_CAPTURE=1; shift ;;
      --uninstall) UNINSTALL=1; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      --yes | -y) ASSUME_YES=1; shift ;;
      --no-color) NO_COLOR=1; shift ;;
      --version) echo "install.sh ${SCRIPT_VERSION}"; exit 0 ;;
      --help | -h) usage; exit 0 ;;
      *) die "unknown option: $1 (see --help)" 2 ;;
    esac
  done
}

cleanup() {
  local rc=$?
  [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]] && rm -f "$LOG_FILE"
  return "$rc"
}

main() {
  ORIGINAL_ARGS=("$@")
  init_colors
  parse_args "$@"

  SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  GO_VERSION="${GO_VERSION:-$DEFAULT_GO_VERSION}"
  VERSION_TAG="$(build_version_tag)"
  LOG_FILE="$(mktemp /tmp/rdpshot-install.XXXXXX)"
  trap cleanup EXIT

  print_header

  if [[ "$UNINSTALL" -eq 1 ]]; then
    require_root "${ORIGINAL_ARGS[@]}"
    do_uninstall
    exit 0
  fi

  require_root "${ORIGINAL_ARGS[@]}"
  detect_os

  printf '%s %ssystem%s   %s\n' "$C_DIM" "$C_CYAN" "$C_RESET" "$OS_NAME"
  printf '%s %smanager%s  %s · %s\n' "$C_DIM" "$C_CYAN" "$C_RESET" "$PM" "$(uname -m)"
  printf '%s %starget%s   %s\n\n' "$C_DIM" "$C_CYAN" "$C_RESET" "$INSTALL_PREFIX"

  confirm || die "installation aborted"

  run_step "Preflight checks" preflight

  # shellcheck disable=SC2046
  run_step "Installing system build tools" install_packages $(build_packages_for)

  step_go_toolchain

  NEW_HASH="$(source_fingerprint)"
  BUILD_NEEDED=1
  if [[ "$FORCE_REBUILD" -eq 0 && -x "$INSTALL_PREFIX/bin/rdpshot" && -f "$INSTALL_PREFIX/.source-hash" ]] &&
    [[ "$(<"$INSTALL_PREFIX/.source-hash")" == "$NEW_HASH" ]]; then
    BUILD_NEEDED=0
  fi

  if [[ "$BUILD_NEEDED" -eq 0 ]]; then
    skip_step "Build (sources unchanged)"
    skip_step "Install up to date"
  else
    run_step "Building rdpshot (${VERSION_TAG})" do_build
    run_step "Installing to ${INSTALL_PREFIX}" do_install
  fi

  if [[ "$SKIP_CAPTURE" -eq 1 ]]; then
    skip_step "Capture tools not requested"
  else
    run_step "Installing optional capture tools" install_capture_tools
  fi

  run_step "Verifying installation" verify_install
  progress_finish

  printf '\n%s %srdpshot is ready%s\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
  printf '   %-14s %s\n' "binary" "$BIN_LINK_DIR/rdpshot"
  printf '   %-14s %s\n' "install dir" "$INSTALL_PREFIX"
  printf '   %-14s %s\n' "wordlists" "$INSTALL_PREFIX/wordlists"
  printf '   %-14s %s\n\n' "try" "rdpshot targets 10.0.0.0/24"
  printf '%s%s%s\n' "$C_DIM" \
    "Only scan systems you are authorized to test. Use rdpshot serve --help for the web UI." \
    "$C_RESET"
}

main "$@"