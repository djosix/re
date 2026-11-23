#!/usr/bin/env bash
# re: launcher for the isolated RE / pentest agent sandbox. Runs on the host.
# Compatible with macOS bash 3.2.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd -P)
STATE_DIR="$ROOT/.state"
SECRETS_DIR="$ROOT/secrets"
KNOWN_SECRETS="anthropic_api_key openai_api_key deepseek_api_key openrouter_api_key venice_api_key anthropic_oauth_token"

die()  { echo "re: $*" >&2; exit 1; }
warn() { echo "re: warning: $*" >&2; }

usage() {
  cat <<'EOF'
usage: ./re [-w DIR] [-p PROVIDER] [-m MODEL[,SMALL]] <command> [args...]

  -w DIR        workspace mounted at /work (default: ./workspace). Each workspace gets
                its own stack, home volume and settings.
  -p PROVIDER   claude: anthropic|deepseek|openrouter   codex: openai|deepseek|openrouter
                (opencode has every provider configured; pick with -m)
  -m MODEL      model id for the chosen harness/provider. claude: sets every model tier
                (SMALL, if given, for the haiku/background tier). Examples:
                  ./re -p openrouter -m deepseek/deepseek-v4-pro,deepseek/deepseek-v4.1-flash claude
                  ./re -m openrouter/deepseek/deepseek-v4-pro opencode
                  ./re -m venice/deepseek-v4-pro opencode

Agent / shell (starts the stack with the last `up` settings if needed):
  claude [args]        Claude Code            codex [args]     OpenAI Codex CLI
  opencode [args]      opencode               shell            bash in the sandbox
  exec CMD [args]      run any command        info             what the sandbox can reach
  selftest             verify isolation from inside the sandbox

Stack:
  up [options]         (re)create the stack for this workspace
      --forward LPORT=HOST:PORT   relay:LPORT inside -> HOST:PORT (e.g. 7000=host.docker.internal:7000)
      --allow CIDR[:PORT]         direct access to a target range/host (adds an egress route)
      --egress DOMAIN             allow HTTP(S) to DOMAIN via `withproxy` (e.g. pypi.org, .pythonhosted.org)
      --mem SIZE                  sandbox memory limit (default 6g)
      --reset-net                 back to isolated mode (no forwards/allow/egress)
                                  network flags given to `up` replace the saved ones
  down                 stop this workspace's stack (home volume kept)
  reset                stop and delete this workspace's home volume (agent history, configs)
  status               show settings and containers        logs [svc]   follow gateway/relay/netns logs
  build [--pull]       build images

Host side:
  secret set NAME      store a credential (read from stdin, never echoed)
  secret ls | rm NAME  NAME: anthropic | openai | deepseek | openrouter | venice | anthropic_oauth_token
  serial DEV [BAUD] [PORT]   bridge a local serial device to 127.0.0.1:PORT (default 115200, 7000)
EOF
}

# ---------------------------------------------------------------- workspace / state
WORKSPACE=""
PROVIDER=""
MODEL=""
while [ $# -gt 0 ]; do
  case "$1" in
    -m) [ $# -ge 2 ] || die "-m needs a model id"; MODEL=$2; shift 2 ;;
    -w) [ $# -ge 2 ] || die "-w needs a directory"; WORKSPACE=$2; shift 2 ;;
    -p) [ $# -ge 2 ] || die "-p needs a provider"; PROVIDER=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) break ;;
  esac
done
[ $# -gt 0 ] || { usage; exit 1; }
CMD=$1; shift

resolve_workspace() {
  local ws=${WORKSPACE:-$ROOT/workspace}
  [ -n "$WORKSPACE" ] || mkdir -p "$ws"
  [ -d "$ws" ] || die "workspace not found: $ws"
  ws=$(cd "$ws" && pwd -P)
  [ "$ws" != / ] && [ "$ws" != "$(cd ~ && pwd -P)" ] || die "refusing to mount $ws: pick a dedicated directory"
  case "$ROOT/" in "$ws"/*) die "workspace $ws contains this project (and its secrets/)";; esac
  case "$ws/" in "$ROOT"/*) case "$ws/" in "$ROOT/workspace/"*) ;; *) die "inside the project only ./workspace may be mounted";; esac;; esac
  case "$ws" in *[!A-Za-z0-9._/@+-]*) die "workspace path has unsupported characters: $ws";; esac
  WS=$ws
  local slug hash
  slug=$(basename "$ws" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9\n' '-' | sed 's/^-*//; s/-*$//' | cut -c1-24)
  hash=$(printf '%s' "$ws" | shasum -a 256 | cut -c1-8)
  PROJECT="re-${slug:-ws}-$hash"
  STATE="$STATE_DIR/$PROJECT.env"
}

valid() { printf '%s' "$2" | grep -Eq "$1"; }
RX_ALLOW='^[A-Za-z0-9.-]+(/[0-9]{1,2})?(:[0-9]{1,5})?$'
RX_FWD='^[0-9]{1,5}=[A-Za-z0-9.-]+:[0-9]{1,5}$'
RX_DOMAIN='^(\*\.|\.)?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$'
RX_MEM='^[0-9]+[kmgKMG]?$'

load_state() {
  RE_ALLOW_CIDRS=""; RE_FORWARDS=""; RE_EGRESS_DOMAINS=""; RE_MEM="6g"
  if [ -f "$STATE" ]; then
    # Written only by this script with validated values.
    # shellcheck disable=SC1090
    . "$STATE"
  fi
}

host_ips() {
  # Every IPv4 address of this machine, so --allow can never reach the host via its LAN IP.
  {
    if command -v ifconfig >/dev/null 2>&1; then ifconfig | awk '/inet /{print $2}'; fi
    if command -v ip >/dev/null 2>&1; then ip -4 -o addr show | awk '{split($4,a,"/"); print a[1]}'; fi
  } | { grep -Ev '^127\.' || true; } | sort -u | sed 's#$#/32#' | paste -sd, -
}

save_state() {
  mkdir -p "$STATE_DIR"
  cat > "$STATE" <<EOF
RE_ALLOW_CIDRS=$RE_ALLOW_CIDRS
RE_FORWARDS=$RE_FORWARDS
RE_EGRESS_DOMAINS=$RE_EGRESS_DOMAINS
RE_MEM=$RE_MEM
EOF
}

export_env() {
  export RE_PROJECT=$PROJECT RE_WORKSPACE=$WS RE_SECCOMP="$ROOT/sandbox/seccomp.json"
  export RE_ALLOW_CIDRS RE_FORWARDS RE_EGRESS_DOMAINS RE_MEM
  export RE_DENY_CIDRS; RE_DENY_CIDRS=$(host_ips)
  export RE_EXPECT_EGRESS=0
  FILES="-f $ROOT/compose.yaml"
  if [ -n "$RE_ALLOW_CIDRS" ]; then FILES="$FILES -f $ROOT/compose.egress.yaml"; RE_EXPECT_EGRESS=1; fi
}

dc() {
  # shellcheck disable=SC2086
  docker compose --project-directory "$ROOT" -p "$PROJECT" $FILES "$@"
}

sandbox_running() {
  [ "$(dc ps --status running --services 2>/dev/null | grep -cx sandbox || true)" = 1 ]
}

stack_up() {
  [ -f "$WS/.git/config" ] && warn "$WS is a git repo: anything the agent writes to .git/ (hooks, config) runs when YOU use git on the host. Review before running git there."
  echo "re: starting $PROJECT  (workspace $WS)"
  [ -n "$RE_FORWARDS" ] && echo "re:   forwards: $RE_FORWARDS"
  [ -n "$RE_ALLOW_CIDRS" ] && echo "re:   direct access: $RE_ALLOW_CIDRS (host IPs always denied)"
  [ -n "$RE_EGRESS_DOMAINS" ] && echo "re:   egress domains: $RE_EGRESS_DOMAINS"
  dc up -d --wait --remove-orphans "$@"
}

ensure_up() {
  sandbox_running || stack_up
}

run_in_sandbox() {
  local tty=""
  [ -t 0 ] && [ -t 1 ] || tty="-T"
  local envs=""
  if [ -n "$PROVIDER" ]; then
    valid '^[a-z]+$' "$PROVIDER" || die "bad provider: $PROVIDER"
    envs="-e RE_PROVIDER=$PROVIDER"
  fi
  if [ -n "$MODEL" ]; then
    valid '^[A-Za-z0-9._:/@~-]+(\[1m\])?(,[A-Za-z0-9._:/@~-]+(\[1m\])?)?$' "$MODEL" || die "bad model id: $MODEL"
    envs="$envs -e RE_MODEL=${MODEL%%,*}"
    case "$MODEL" in *,*) envs="$envs -e RE_SMALL_MODEL=${MODEL#*,}" ;; esac
  fi
  # shellcheck disable=SC2086
  dc exec $tty $envs -w /work sandbox "$@"
}

secret_name() {
  case "$1" in
    anthropic) echo anthropic_api_key ;;
    openai) echo openai_api_key ;;
    deepseek) echo deepseek_api_key ;;
    openrouter) echo openrouter_api_key ;;
    venice) echo venice_api_key ;;
    *) valid '^[a-z0-9][a-z0-9_-]*$' "$1" || die "bad secret name: $1"; echo "$1" ;;
  esac
}

# ---------------------------------------------------------------- commands
case "$CMD" in
  claude|codex|opencode)
    resolve_workspace; load_state; export_env; ensure_up
    run_in_sandbox "$CMD" "$@" ;;
  shell)
    resolve_workspace; load_state; export_env; ensure_up
    run_in_sandbox bash -l "$@" ;;
  exec)
    [ $# -gt 0 ] || die "exec needs a command"
    resolve_workspace; load_state; export_env; ensure_up
    run_in_sandbox "$@" ;;
  info|selftest)
    resolve_workspace; load_state; export_env; ensure_up
    run_in_sandbox "re-$CMD" ;;

  up)
    resolve_workspace; load_state
    # Network flags replace the saved network settings as a whole; `up` without them reuses them.
    case " $* " in *" --forward "*|*" --allow "*|*" --egress "*) RE_ALLOW_CIDRS=""; RE_FORWARDS=""; RE_EGRESS_DOMAINS="" ;; esac
    while [ $# -gt 0 ]; do
      case "$1" in
        --reset-net) RE_ALLOW_CIDRS=""; RE_FORWARDS=""; RE_EGRESS_DOMAINS=""; shift ;;
        --allow)   valid "$RX_ALLOW" "${2:-}" || die "bad --allow '${2:-}' (CIDR, IP or host, optional :PORT)"
                   RE_ALLOW_CIDRS=${RE_ALLOW_CIDRS:+$RE_ALLOW_CIDRS,}$2; shift 2 ;;
        --forward) valid "$RX_FWD" "${2:-}" || die "bad --forward '${2:-}' (LPORT=HOST:PORT)"
                   [ "${2%%=*}" != 3128 ] || die "relay port 3128 is reserved for the egress proxy"
                   RE_FORWARDS=${RE_FORWARDS:+$RE_FORWARDS,}$2; shift 2 ;;
        --egress)  valid "$RX_DOMAIN" "${2:-}" || die "bad --egress '${2:-}' (domain, or .suffix)"
                   RE_EGRESS_DOMAINS=${RE_EGRESS_DOMAINS:+$RE_EGRESS_DOMAINS,}$2; shift 2 ;;
        --mem)     valid "$RX_MEM" "${2:-}" || die "bad --mem '${2:-}'"; RE_MEM=$2; shift 2 ;;
        *) die "unknown up option: $1" ;;
      esac
    done
    dedup() { printf '%s' "$1" | tr ',' '\n' | awk 'NF && !seen[$0]++' | paste -sd, -; }
    RE_ALLOW_CIDRS=$(dedup "$RE_ALLOW_CIDRS"); RE_EGRESS_DOMAINS=$(dedup "$RE_EGRESS_DOMAINS"); RE_FORWARDS=$(dedup "$RE_FORWARDS")
    dupports=$(printf '%s' "$RE_FORWARDS" | tr ',' '\n' | cut -d= -f1 | sort | uniq -d | paste -sd, -)
    [ -z "$dupports" ] || die "--forward listen port used twice: $dupports"
    case ",$RE_ALLOW_CIDRS," in *,0.0.0.0/0,*|*,0.0.0.0/0:*) warn "--allow 0.0.0.0/0 gives the agent the whole internet (host and metadata stay blocked)";; esac
    save_state; export_env
    stack_up --force-recreate
    echo "re: ready. Try: ./re ${WORKSPACE:+-w $WORKSPACE }selftest   or   ./re ${WORKSPACE:+-w $WORKSPACE }claude" ;;
  down)
    resolve_workspace; load_state; export_env
    dc down --remove-orphans ;;
  reset)
    resolve_workspace; load_state; export_env
    dc down --remove-orphans --volumes
    echo "re: home volume for $PROJECT deleted (workspace files untouched)" ;;
  status)
    resolve_workspace; load_state; export_env
    echo "project:   $PROJECT"
    echo "workspace: $WS"
    echo "forwards:  ${RE_FORWARDS:-none}"
    echo "allow:     ${RE_ALLOW_CIDRS:-none (isolated)}"
    echo "egress:    ${RE_EGRESS_DOMAINS:-none}"
    echo "memory:    $RE_MEM"
    dc ps ;;
  logs)
    resolve_workspace; load_state; export_env
    if [ $# -gt 0 ]; then dc logs -f "$@"; else dc logs -f gateway relay netns; fi ;;
  build)
    WS=$ROOT/workspace PROJECT=re-build; export RE_WORKSPACE=$WS RE_PROJECT=$PROJECT; FILES="-f $ROOT/compose.yaml"
    dc build "$@" ;;

  secret)
    sub=${1:-ls}; shift || true
    mkdir -p "$SECRETS_DIR"; chmod 700 "$SECRETS_DIR"
    case "$sub" in
      set)
        name=$(secret_name "${1:?usage: ./re secret set NAME}")
        if [ -t 0 ]; then
          printf 'value for %s (input hidden): ' "$name" >&2
          stty -echo; IFS= read -r value || true; stty echo; echo >&2
        else
          IFS= read -r value || true
        fi
        [ -n "$value" ] || die "empty value, nothing stored"
        ( umask 077; printf '%s\n' "$value" > "$SECRETS_DIR/$name" )
        unset value
        echo "re: stored secrets/$name (read by the gateway on every request; no restart needed)" ;;
      rm)
        name=$(secret_name "${1:?usage: ./re secret rm NAME}")
        rm -f "$SECRETS_DIR/$name"; echo "re: removed secrets/$name" ;;
      ls)
        for n in $KNOWN_SECRETS; do
          if [ -s "$SECRETS_DIR/$n" ]; then s=configured; else s=-; fi
          printf '  %-24s %s\n' "$n" "$s"
        done ;;
      *) die "secret: set|ls|rm" ;;
    esac ;;

  serial)
    dev=${1:?usage: ./re serial DEVICE [BAUD] [PORT]}; baud=${2:-115200}; port=${3:-7000}
    echo "re: in another terminal: ./re up --forward $port=host.docker.internal:$port   then inside: serial-attach $port"
    exec /usr/bin/python3 -I "$ROOT/host/serial-bridge.py" "$dev" --baud "$baud" --port "$port" ;;

  -h|--help|help) usage ;;
  *) usage; exit 1 ;;
esac
