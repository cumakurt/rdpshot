#!/usr/bin/env bash
#
# rdpshot Docker installer
#
# Builds the project into a container image and runs it as a Docker service.
# The script is safe to re-run:
#   * an existing, working Docker installation is reused,
#   * the Compose plugin is installed only when it is missing,
#   * the image is rebuilt only when the sources changed (or --force),
#   * an unchanged, healthy container is left running.
#
# Usage: ./install_docker.sh [options]
#
# Run it as your own user (Docker access is granted through the docker group)
# or with sudo; root execution skips the group dance.
#
# Only scan systems you are authorized to test. Credential checks and
# screenshot capture stay opt-in (--enable-auth / --enable-screens plus the
# authorization acknowledgement) exactly as in the CLI.
set -Eeuo pipefail

SCRIPT_VERSION="1.0.0"
IMAGE_NAME="rdpshot"
CONTAINER_NAME="rdpshot"
VOLUME_NAME="rdpshot-data"
HOST_PORT="8722"
CONTAINER_PORT="8722"
BUILD_TARGET="slim"
FORCE_REBUILD=0
UNINSTALL=0
DRY_RUN=0
ASSUME_YES=0
PULL_BASE=0
BIND_LOCALHOST=0
TOKEN=""
LOG_FILE=""

# Build context and Compose file live next to this script so the installer
# works from any working directory.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------- output ---

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
  if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
    INTERACTIVE=1
  else
    INTERACTIVE=0
  fi
  TERM_WIDTH="$(terminal_width)"

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
  case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
    *UTF-8*|*utf8*|*UTF8*|*utf-8*) BAR_FULL='█'; BAR_EMPTY='░'; GLYPH_OK='✓'; GLYPH_SKIP='·'; GLYPH_ERR='✗'; SPIN=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏) ;;
    *) BAR_FULL='#'; BAR_EMPTY='-'; GLYPH_OK='OK'; GLYPH_SKIP='..'; GLYPH_ERR='ERR'; SPIN=(- \\ \| /) ;;
  esac
}

BAR_WIDTH=22
STEP=0
# preflight, docker engine, compose, docker group, configuration, .env, build,
# container start, verification
TOTAL_STEPS=9
STEP_STARTED=0
INTERACTIVE=0
TERM_WIDTH=80
LINE_DIRTY=0

progress_clear() {
  if ((LINE_DIRTY)); then
    printf '\r\033[K'
    LINE_DIRTY=0
  fi
}

progress_finish() {
  if ((LINE_DIRTY)); then
    printf '\n'
    LINE_DIRTY=0
  fi
}

draw_bar() {
  local pct=$1 glyph=$2 message=$3
  local filled=$(( pct * BAR_WIDTH / 100 ))
  (( filled > BAR_WIDTH )) && filled=$BAR_WIDTH
  local bar='' i
  for ((i = 0; i < filled; i++)); do bar+="$BAR_FULL"; done
  for ((i = filled; i < BAR_WIDTH; i++)); do bar+="$BAR_EMPTY"; done

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

step_line() {
  local state=$1 glyph=$2 message=$3
  local color="$C_GREEN"
  case "$state" in
    skipped) color="$C_DIM" ;;
    failed) color="$C_RED" ;;
  esac
  draw_bar "$((STEP * 100 / TOTAL_STEPS))" "$color$glyph$C_RESET" "$message"
}

info()  { progress_clear; printf '%s %s%s%s\n' "$C_DIM" "$C_BLUE" "$1" "$C_RESET"; }
warn()  { progress_clear; printf '%s %s[!]%s %s\n' "$C_DIM" "$C_YELLOW" "$C_RESET" "$1" >&2; }
error() { progress_clear; printf '%s %s[✗]%s %s\n' "$C_BOLD" "$C_RED" "$C_RESET" "$1" >&2; }
die()   { error "$1"; exit "${2:-1}"; }

print_header() {
  printf '\n%s %srdpshot%s %sDocker installer v%s%s\n' \
    "$C_BOLD" "$C_CYAN" "$C_RESET" "$C_DIM" "$SCRIPT_VERSION" "$C_RESET"
  printf '%s%s%s\n\n' "$C_DIM" "--------------------------------------------------------------" "$C_RESET"
}

# print_run_instructions ends the installer with copy-pasteable commands for
# running and operating the container, so the operator does not have to look
# up the Compose invocation or the port/volume mapping afterwards.
print_run_instructions() {
  local health_url="http://${HEALTH_HOST}:${HOST_PORT}/api/v1/about"
  local health_cmd="curl -s ${health_url}"
  local run_token_flag=""
  if [[ -n "$TOKEN" ]]; then
    # Never echo the secret itself: this output may be piped into logs. The
    # operator can read the value from .env when copy-pasting.
    health_cmd="curl -s -H \"Authorization: Bearer \$RDSHOT_TOKEN\" ${health_url}"
    run_token_flag='     -e RDSHOT_TOKEN="$RDSHOT_TOKEN" \'
  fi

  printf '\n%s %sHow to run it with Docker%s\n' "$C_BOLD" "$C_CYAN" "$C_RESET"
  printf '   %-12s %s\n' "start" "docker compose up -d"
  printf '   %-12s %s\n' "restart" "docker compose restart"
  printf '   %-12s %s\n' "stop" "docker compose down"
  printf '   %-12s %s\n' "logs" "docker logs -f ${CONTAINER_NAME}"
  printf '   %-12s %s\n' "health" "$health_cmd"
  printf '   %-12s %s\n' "cli" "docker exec -it ${CONTAINER_NAME} rdpshot targets 10.0.0.0/24"

  printf '\n%s %sWithout Compose (single docker run)%s\n' "$C_BOLD" "$C_CYAN" "$C_RESET"
  printf '   docker run -d --rm --name %s \\\n' "$CONTAINER_NAME"
  printf '     -p %s:%s \\\n' "${BIND_ADDR}:${HOST_PORT}" "$CONTAINER_PORT"
  printf '     -v %s:/data \\\n' "$VOLUME_NAME"
  printf '     --read-only --tmpfs /tmp --security-opt no-new-privileges:true \\\n'
  if [[ -n "$run_token_flag" ]]; then
    printf '%s\n' "$run_token_flag"
  fi
  printf '     %s \\\n' "${IMAGE_NAME}:latest"
  printf '     serve --addr 0.0.0.0:8722 --db /data/rdpshot.db --outputs /data\n'

  if [[ -n "$TOKEN" ]]; then
    printf '\n%s%s\n%s%s\n' "$C_DIM" \
      "The token is masked above; export it before pasting those commands:" \
      "  export RDSHOT_TOKEN=\$(sed -n 's/^RDSHOT_TOKEN=//p' ${SCRIPT_DIR}/.env)" \
      "$C_RESET"
  fi

  printf '\n%s %sMaintenance%s\n' "$C_BOLD" "$C_CYAN" "$C_RESET"
  printf '   %-12s %s\n' "rebuild" "./install_docker.sh"
  printf '   %-12s %s\n' "full image" "./install_docker.sh --target full"
  printf '   %-12s %s\n' "uninstall" "./install_docker.sh --uninstall"
  printf '%s%s%s\n' "$C_DIM" \
    "Run the compose commands from ${SCRIPT_DIR}." \
    "$C_RESET"
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
    tail -n 15 "$LOG_FILE" | sed 's/^/    /' >&2
    die "$message failed (see output above)"
  fi
  step_line done "$GLYPH_OK" "$message ($((SECONDS - STEP_STARTED))s)"
}

skip_step() {
  STEP=$((STEP + 1))
  step_line skipped "$GLYPH_SKIP" "$1 (skipped)"
}

# ------------------------------------------------------------- helpers ---

have() { command -v "$1" >/dev/null 2>&1; }

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

# docker_usable reports whether the current user can actually talk to the
# daemon — installation alone is not sufficient (group membership matters).
docker_usable() {
  have docker && docker info >/dev/null 2>&1
}

# compose_usable reports whether a Docker Compose implementation is present.
compose_usable() {
  docker compose version >/dev/null 2>&1
}

# as_root runs the given command as root, using sudo when available.
as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  elif have sudo; then
    sudo -- "$@"
  else
    die "root privileges are required to install Docker; re-run with sudo"
  fi
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
  if have apt-get; then
    PM=apt
  elif have dnf; then
    PM=dnf
  elif have yum; then
    PM=yum
  elif have pacman; then
    PM=pacman
  elif have zypper; then
    PM=zypper
  elif have apk; then
    PM=apk
  else
    PM=none
  fi
}

# --------------------------------------------------------- docker setup ---

# install_docker_tooling installs Docker Engine plus the Compose plugin using
# the distribution packages. It is only reached when Docker is missing.
install_docker_tooling() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: would install Docker Engine and the Compose plugin"
    return 0
  fi
  case "$PM" in
    apt)
      as_root apt-get update -qq
      DEBIAN_FRONTEND=noninteractive as_root apt-get install -y -qq --no-install-recommends \
        docker.io docker-compose-v2 ca-certificates curl
      ;;
    dnf)
      as_root dnf install -y -q docker docker-compose-plugin ca-certificates curl
      ;;
    yum)
      as_root yum install -y -q docker docker-compose-plugin ca-certificates curl
      ;;
    pacman)
      as_root pacman -Sy --noconfirm --needed docker docker-compose ca-certificates curl
      ;;
    zypper)
      as_root zypper --non-interactive --quiet install \
        docker docker-compose ca-certificates curl
      ;;
    apk)
      as_root apk add --no-cache docker docker-cli-compose ca-certificates curl
      ;;
    *)
      echo "no supported package manager found; install Docker manually" >&2
      return 1
      ;;
  esac
}

# install_compose_plugin adds just the Compose plugin for the case where Docker
# itself is already installed but `docker compose` is not available.
install_compose_plugin() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: would install the Docker Compose plugin"
    return 0
  fi
  case "$PM" in
    apt) DEBIAN_FRONTEND=noninteractive as_root apt-get install -y -qq --no-install-recommends docker-compose-v2 ;;
    dnf | yum) as_root "$PM" install -y -q docker-compose-plugin ;;
    pacman) as_root pacman -Sy --noconfirm --needed docker-compose ;;
    zypper) as_root zypper --non-interactive --quiet install docker-compose ;;
    apk) as_root apk add --no-cache docker-cli-compose ;;
    *) return 1 ;;
  esac
}

# start_docker_daemon enables and starts the service. Systemd is the common
# case; the fallbacks cover containers, WSL and OpenRC systems.
start_docker_daemon() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: would start the Docker daemon"
    return 0
  fi
  if docker_usable; then
    echo "docker daemon already reachable"
    return 0
  fi
  if have systemctl; then
    as_root systemctl enable --now docker && sleep 1
  elif have service; then
    as_root service docker start && sleep 1
  elif have rc-service; then
    as_root rc-service docker start && sleep 1
  elif have dockerd; then
    # Last resort: run the daemon in the background without supervision.
    as_root nohup dockerd >/var/log/dockerd.log 2>&1 &
    sleep 3
  fi
  if docker_usable; then
    return 0
  fi
  # The daemon may be up while this user is not in the docker group yet.
  if [[ "$(id -u)" -ne 0 ]] && have sudo; then
    sudo docker info >/dev/null 2>&1 && return 0
  fi
  return 1
}

# ensure_docker_group grants the invoking user access to the daemon socket.
# Membership only takes effect on the next login, so the rest of the script
# falls back to sudo when the current shell cannot reach the socket.
ensure_docker_group() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: would grant docker group access"
    return 0
  fi
  if [[ "$(id -u)" -eq 0 ]]; then
    echo "running as root; skipping docker group setup"
    return 0
  fi
  if docker info >/dev/null 2>&1; then
    echo "current user can already access the docker socket"
    return 0
  fi
  if getent group docker >/dev/null 2>&1; then
    as_root usermod -aG docker "$(id -un)"
    echo "added $(id -un) to the docker group (effective after re-login)"
  else
    echo "docker group missing; leaving permissions untouched"
  fi
  return 0
}

# ensure_docker_engine installs Docker when it is missing and makes sure the
# daemon is reachable. Kept as one step so the progress bar advances a fixed
# number of times regardless of the host's starting state.
ensure_docker_engine() {
  if docker_usable; then
    echo "docker engine already installed and reachable"
    return 0
  fi
  if ! have docker; then
    install_docker_tooling
  fi
  start_docker_daemon
}

# ----------------------------------------------------------- build/run ---

# DOCKER_CMD is resolved once in the parent shell: run_step executes its
# command in a subshell, so a function-local assignment would never reach the
# later verification steps.
DOCKER_CMD=()

# resolve_docker_cmd picks `docker` or `sudo docker` for the current session.
resolve_docker_cmd() {
  if docker info >/dev/null 2>&1; then
    DOCKER_CMD=(docker)
  elif have sudo && sudo docker info >/dev/null 2>&1; then
    DOCKER_CMD=(sudo docker)
  else
    DOCKER_CMD=(docker)
  fi
  echo "using: ${DOCKER_CMD[*]}"
}

# docker_cmd prints the resolved command, falling back to a fresh probe when it
# has not been resolved yet.
docker_cmd() {
  if ((${#DOCKER_CMD[@]} == 0)); then
    resolve_docker_cmd >/dev/null
  fi
  "${DOCKER_CMD[@]}" "$@"
}

# stack_command dispatches docker compose through the resolved command.
stack_command() {
  if ((${#DOCKER_CMD[@]} == 0)); then
    resolve_docker_cmd >/dev/null
  fi
  "${DOCKER_CMD[@]}" compose -f "$SCRIPT_DIR/docker-compose.yml" "$@"
}

source_fingerprint() {
  # The image flavour is part of the fingerprint: switching --target slim/full
  # must rebuild even when the source tree is untouched.
  {
    printf 'target=%s\n' "$BUILD_TARGET"
    (
      cd "$SCRIPT_DIR" || exit 1
      find . \( -name '*.go' -o -name 'go.mod' -o -name 'go.sum' \
        -o -name 'Dockerfile' -o -name 'docker-compose.yml' \) -type f -print0 2>/dev/null \
        | sort -z | xargs -0 sha256sum 2>/dev/null
      find ./web ./wordlists -type f -print0 2>/dev/null | sort -z | xargs -0 sha256sum 2>/dev/null
    )
  } | sha256sum | cut -d' ' -f1
}

build_version_tag() {
  local tag=""
  if have git && git -C "$SCRIPT_DIR" rev-parse --short HEAD >/dev/null 2>&1; then
    tag="$(git -C "$SCRIPT_DIR" describe --tags --always --dirty 2>/dev/null || true)"
  fi
  if [[ -z "$tag" ]]; then
    tag="dev-$(date -u +%Y%m%d)"
  fi
  printf '%s' "$tag"
}

# image_revision returns the source hash recorded in the image label so an
# unchanged tree never triggers a rebuild.
image_revision() {
  docker_cmd image inspect --format '{{ index .Config.Labels "org.rdpshot.source-hash" }}' \
    "${IMAGE_NAME}:latest" 2>/dev/null || true
}

preflight() {
  [[ -f "$SCRIPT_DIR/Dockerfile" ]] || { echo "Dockerfile missing in $SCRIPT_DIR" >&2; return 1; }
  [[ -f "$SCRIPT_DIR/docker-compose.yml" ]] || { echo "docker-compose.yml missing in $SCRIPT_DIR" >&2; return 1; }
  [[ -f "$SCRIPT_DIR/cmd/rdpshot/main.go" ]] || { echo "cmd/rdpshot/main.go missing" >&2; return 1; }
  [[ -f "$SCRIPT_DIR/go.mod" ]] || { echo "go.mod missing" >&2; return 1; }
  echo "source tree: $SCRIPT_DIR"
  echo "image:       ${IMAGE_NAME}:latest (target: ${BUILD_TARGET})"
  echo "version:     ${VERSION_TAG}"
}

# resolve_endpoints validates the requested ports before a build is started.
resolve_endpoints() {
  [[ "$HOST_PORT" =~ ^[0-9]+$ ]] || { echo "invalid host port: $HOST_PORT" >&2; return 1; }
  ((HOST_PORT >= 1 && HOST_PORT <= 65535)) || { echo "host port out of range: $HOST_PORT" >&2; return 1; }
  if command -v ss >/dev/null 2>&1; then
    if ss -ltn "sport = :${HOST_PORT}" 2>/dev/null | grep -q LISTEN; then
      echo "warning: port ${HOST_PORT} is already in use; the container may fail to bind" >&2
    fi
  fi
  echo "publishing ${BIND_ADDR}:${HOST_PORT} -> ${CONTAINER_PORT}"
}

# write_env_file persists the runtime settings Compose interpolates so later
# `docker compose up -d` runs in the project directory behave identically.
write_env_file() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: would write .env"
    return 0
  fi
  local env_file="$SCRIPT_DIR/.env"
  {
    printf '# Generated by install_docker.sh — safe to edit, then re-run the installer.\n'
    printf 'RDSHOT_IMAGE=%s\n' "${IMAGE_NAME}:latest"
    printf 'RDSHOT_BUILD_TARGET=%s\n' "$BUILD_TARGET"
    printf 'RDSHOT_VERSION=%s\n' "$VERSION_TAG"
    printf 'RDSHOT_BIND_ADDR=%s\n' "$BIND_ADDR"
    printf 'RDSHOT_HOST_PORT=%s\n' "$HOST_PORT"
    printf 'RDSHOT_VOLUME=%s\n' "$VOLUME_NAME"
    printf 'RDSHOT_SOURCE_HASH=%s\n' "$NEW_HASH"
    if [[ -n "$TOKEN" ]]; then
      # Compose reads the token from .env; the file is created with mode 0600
      # below so the secret is not world-readable.
      printf 'RDSHOT_TOKEN=%s\n' "$TOKEN"
    fi
  } >"$env_file.tmp"
  chmod 0600 "$env_file.tmp"
  mv "$env_file.tmp" "$env_file"
  echo "wrote $env_file"
}

do_build() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: would build the image"
    return 0
  fi
  # `docker build` (not `docker compose build`) because the installer tags the
  # image twice and selects the stage explicitly.
  local args=(build
    --target "$BUILD_TARGET"
    --build-arg "VERSION=${VERSION_TAG}"
    --build-arg "SOURCE_HASH=${NEW_HASH}"
    -t "${IMAGE_NAME}:latest"
    -t "${IMAGE_NAME}:${VERSION_TAG}")
  if [[ "$PULL_BASE" -eq 1 ]]; then
    args+=(--pull)
  fi

  if docker_cmd "${args[@]}" "$SCRIPT_DIR"; then
    return 0
  fi

  # Some hosts cannot resolve DNS from the default bridge network (restricted
  # CI, VPN-split DNS, offline mirrors). Rebuild once on the host network so a
  # name-resolution failure is not reported as a broken source tree.
  if grep -qiE 'dial tcp|i/o timeout|no such host|name resolution|proxy\.golang\.org' "$LOG_FILE"; then
    echo "module download failed on the default bridge network; retrying with --network host"
    docker_cmd "${args[@]}" --network host "$SCRIPT_DIR"
    return
  fi
  return 1
}

# export_runtime_env mirrors the CLI flags onto the Compose environment.
export_runtime_env() {
  export RDSHOT_IMAGE="${IMAGE_NAME}:latest"
  export RDSHOT_BUILD_TARGET="$BUILD_TARGET"
  export RDSHOT_VERSION="$VERSION_TAG"
  export RDSHOT_BIND_ADDR="$BIND_ADDR"
  export RDSHOT_HOST_PORT="$HOST_PORT"
  export RDSHOT_VOLUME="$VOLUME_NAME"
  # Uninstall runs before any fingerprint is computed; Compose only needs a
  # value here, not a meaningful one.
  export RDSHOT_SOURCE_HASH="${NEW_HASH:-unknown}"
  export RDSHOT_TOKEN="$TOKEN"
}

do_up() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: would start the container"
    return 0
  fi
  export_runtime_env
  stack_command up -d --remove-orphans
  echo "container ${CONTAINER_NAME} started"
}

do_recreate() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: would recreate the container"
    return 0
  fi
  export_runtime_env
  stack_command up -d --remove-orphans --force-recreate
  echo "container ${CONTAINER_NAME} recreated"
}

# probe_http polls the container endpoint until the web UI answers.
probe_http() {
  local url="http://${HEALTH_HOST}:${HOST_PORT}/api/v1/about"
  local attempt
  # The bearer token must be sent when one is configured, otherwise the
  # endpoint answers 401 and a healthy container looks broken.
  local -a auth=()
  if [[ -n "$TOKEN" ]]; then
    auth=(-H "Authorization: Bearer ${TOKEN}")
  fi
  for attempt in $(seq 1 30); do
    if have curl; then
      if curl -fsS --max-time 2 "${auth[@]}" "$url" >/dev/null 2>&1; then
        echo "UI reachable at ${url%/*}"
        return 0
      fi
    elif command -v wget >/dev/null 2>&1; then
      if [[ -n "$TOKEN" ]]; then
        if wget -q -T 2 -O /dev/null --header="Authorization: Bearer ${TOKEN}" "$url" 2>/dev/null; then
          echo "UI reachable at ${url%/*}"
          return 0
        fi
      elif wget -q -T 2 -O /dev/null "$url" 2>/dev/null; then
        echo "UI reachable at ${url%/*}"
        return 0
      fi
    fi
    sleep 1
  done
  echo "container did not answer on ${url} within 30s" >&2
  echo "--- container logs ---" >&2
  docker_cmd logs --tail 30 "$CONTAINER_NAME" >&2 2>&1 || true
  return 1
}

verify_install() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: would verify http://${HEALTH_HOST}:${HOST_PORT}/api/v1/about"
    return 0
  fi
  # `docker compose up -d` returns while the container is still starting, so
  # poll the state before treating a short delay as a failure.
  local attempt state
  for attempt in $(seq 1 20); do
    state="$(docker_cmd inspect --format '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || true)"
    if [[ "$state" == "running" ]]; then
      break
    fi
    if [[ "$state" == "exited" || "$state" == "dead" ]]; then
      break
    fi
    sleep 1
  done
  if [[ "$state" != "running" ]]; then
    echo "container ${CONTAINER_NAME} is ${state:-missing}, expected running" >&2
    echo "--- container logs ---" >&2
    docker_cmd logs --tail 30 "$CONTAINER_NAME" >&2 2>&1 || true
    return 1
  fi
  probe_http
}

do_uninstall() {
  printf '%s\n' "Removing container ${CONTAINER_NAME}, image ${IMAGE_NAME} and volume ${VOLUME_NAME}"
  confirm || die "uninstall aborted"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "dry-run: nothing removed"
    return 0
  fi
  resolve_docker_cmd >/dev/null
  export_runtime_env
  stack_command down --volumes --remove-orphans >/dev/null 2>&1 || true
  docker_cmd rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  # Remove every tag of this build (latest and the versioned one, which may
  # already be the only remaining reference).
  local image_id
  while read -r image_id; do
    [[ -n "$image_id" ]] || continue
    docker_cmd image rm -f "$image_id" >/dev/null 2>&1 || true
  done < <(docker_cmd image ls --format '{{.ID}}' "$IMAGE_NAME" 2>/dev/null || true)
  rm -f "$SCRIPT_DIR/.env"
  printf '%s %sremoved%s\n' "$C_DIM" "$C_GREEN" "$C_RESET"
}

# --------------------------------------------------------------- usage ---

usage() {
  cat <<EOF
rdpshot Docker installer v${SCRIPT_VERSION}

Usage: ./install_docker.sh [options]

Options:
  --port PORT             host port for the web UI (default: 8722)
  --target slim|full      image flavour (default: slim)
                            slim - distroless runtime, scanning and reports
                            full - adds FreeRDP, Xvfb and ImageMagick so
                                   session screenshots work in-container
  --token TOKEN           bearer token required by every API/UI request
  --localhost             publish the port on 127.0.0.1 only (recommended
                            with --token absent)
  --pull                  always pull the newest base images
  --force                 rebuild the image even when sources are unchanged
  --uninstall             remove the container, image, volume and .env
  --dry-run               show what would happen without changing anything
  --yes, -y               never ask for confirmation
  --no-color              disable colored output
  --version               print installer version
  --help, -h              show this help

Environment:
  NO_COLOR                disable colored output when set
  RDSHOT_TOKEN            same as --token
  DOCKER_BUILDKIT         honoured as usual by the docker CLI

The script compiles the project inside Docker (multi-stage build), so no Go
toolchain is needed on the host. Data lives in the "${VOLUME_NAME}" Docker
volume; the web UI is served on http://<host>:<port>/.

Only scan systems you are authorized to test. Credential checks and session
screenshots stay disabled unless a scan opts in with the authorization
acknowledgement.
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --port) [[ $# -ge 2 ]] || die "--port requires a value" 2; HOST_PORT="$2"; shift 2 ;;
      --port=*) HOST_PORT="${1#*=}"; shift ;;
      --target) [[ $# -ge 2 ]] || die "--target requires slim or full" 2; BUILD_TARGET="$2"; shift 2 ;;
      --target=*) BUILD_TARGET="${1#*=}"; shift ;;
      --token) [[ $# -ge 2 ]] || die "--token requires a value" 2; TOKEN="$2"; shift 2 ;;
      --token=*) TOKEN="${1#*=}"; shift ;;
      --localhost) BIND_LOCALHOST=1; shift ;;
      --pull) PULL_BASE=1; shift ;;
      --force) FORCE_REBUILD=1; shift ;;
      --uninstall) UNINSTALL=1; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      --yes | -y) ASSUME_YES=1; shift ;;
      --no-color) NO_COLOR=1; shift ;;
      --version) echo "install_docker.sh ${SCRIPT_VERSION}"; exit 0 ;;
      --help | -h) usage; exit 0 ;;
      *) die "unknown option: $1 (see --help)" 2 ;;
    esac
  done

  case "$BUILD_TARGET" in
    slim | full) ;;
    *) die "--target must be 'slim' or 'full'" 2 ;;
  esac
  if [[ -n "${RDSHOT_TOKEN:-}" ]]; then
    TOKEN="${RDSHOT_TOKEN}"
  fi
}

cleanup() {
  local rc=$?
  [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]] && rm -f "$LOG_FILE"
  return "$rc"
}

main() {
  init_colors
  parse_args "$@"

  VERSION_TAG="$(build_version_tag)"
  LOG_FILE="$(mktemp /tmp/rdpshot-docker.XXXXXX)"
  trap cleanup EXIT

  if [[ "$BIND_LOCALHOST" -eq 1 ]]; then
    BIND_ADDR="127.0.0.1"
    HEALTH_HOST="127.0.0.1"
  else
    BIND_ADDR="0.0.0.0"
    HEALTH_HOST="127.0.0.1"
  fi

  print_header

  if [[ "$UNINSTALL" -eq 1 ]]; then
    do_uninstall
    exit 0
  fi

  detect_os

  printf '%s %ssystem%s   %s\n' "$C_DIM" "$C_CYAN" "$C_RESET" "$OS_NAME"
  printf '%s %smanager%s  %s\n' "$C_DIM" "$C_CYAN" "$C_RESET" "$PM"
  printf '%s %simage%s    %s:latest (target: %s, version: %s)\n' \
    "$C_DIM" "$C_CYAN" "$C_RESET" "$IMAGE_NAME" "$BUILD_TARGET" "$VERSION_TAG"
  printf '%s %surl%s      http://%s:%s/\n\n' \
    "$C_DIM" "$C_CYAN" "$C_RESET" "$BIND_ADDR" "$HOST_PORT"

  if [[ -z "$TOKEN" && "$BIND_LOCALHOST" -eq 0 ]]; then
    warn "no --token set: anyone who can reach port ${HOST_PORT} gets full access."
    warn "Use --token <secret> (or --localhost) for anything but a trusted LAN."
  fi

  confirm || die "installation aborted"

  run_step "Preflight checks" preflight
  run_step "Ensuring Docker Engine is ready" ensure_docker_engine

  if compose_usable; then
    skip_step "Compose plugin already available"
  else
    run_step "Installing Docker Compose plugin" install_compose_plugin
  fi

  run_step "Granting docker group access" ensure_docker_group

  # Resolve the docker invocation in the parent shell: run_step runs its
  # command in a subshell, so a value set there would not reach later steps.
  resolve_docker_cmd

  # Persist the settings before the build so a failed build still leaves a
  # usable, editable .env behind.
  NEW_HASH="$(source_fingerprint)"
  run_step "Resolving runtime configuration" resolve_endpoints
  run_step "Writing .env" write_env_file

  local image_rev=""
  image_rev="$(image_revision)"

  if [[ "$FORCE_REBUILD" -eq 0 && -n "$image_rev" && "$image_rev" == "$NEW_HASH" ]]; then
    skip_step "Build (sources unchanged)"
  else
    run_step "Building image ${IMAGE_NAME}:latest" do_build
  fi

  if docker_cmd inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    run_step "Recreating container ${CONTAINER_NAME}" do_recreate
  else
    run_step "Starting container ${CONTAINER_NAME}" do_up
  fi

  run_step "Verifying the web UI" verify_install
  progress_finish

  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '\n%s %sdry-run complete%s %s(nothing was changed)%s\n' \
      "$C_BOLD" "$C_YELLOW" "$C_RESET" "$C_DIM" "$C_RESET"
  else
    printf '\n%s %srdpshot is running%s\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
  fi
  printf '   %-12s %s\n' "url" "http://${BIND_ADDR}:${HOST_PORT}/"
  printf '   %-12s %s\n' "container" "$CONTAINER_NAME"
  printf '   %-12s %s\n' "image" "${IMAGE_NAME}:${VERSION_TAG}"
  printf '   %-12s %s\n' "volume" "$VOLUME_NAME"

  print_run_instructions

  if [[ -z "$TOKEN" ]]; then
    printf '\n%s%s%s\n' "$C_DIM" \
      "Tip: re-run with --token <secret> before exposing this port beyond localhost." \
      "$C_RESET"
  fi
  printf '%s%s%s\n' "$C_DIM" \
    "Only scan systems you are authorized to test." \
    "$C_RESET"
}

main "$@"
