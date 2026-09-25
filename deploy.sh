#!/usr/bin/env bash
# UAI — bring the platform up or down as containers.
#
#   ./deploy.sh up        build what is missing, start everything, apply the schema
#   ./deploy.sh down      stop everything, keep the data
#   ./deploy.sh nuke      stop everything and delete the data
#   ./deploy.sh status    what is running, and on which ports
#   ./deploy.sh logs [s]  follow the logs of one service, or all of them
#   ./deploy.sh build     rebuild the images without starting anything
#
# After `up`, `podman ps` shows four containers. The one thing that is NOT a
# container is the SPIRE agent, and that is not an oversight: a workload
# attestor derives a process's identity from what the kernel reports about it,
# so it has to share a view with the workloads it attests. The agents this
# platform is for run on your machine, not in this stack. `make spire-up`
# starts it when you want attested runtimes.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

CONTAINER="${CONTAINER:-$(command -v podman >/dev/null 2>&1 && echo podman || echo docker)}"
COMPOSE_FILE="deploy/compose/compose.yaml"
GATEWAY_PORT="${GATEWAY_PORT:-8080}"
WEB_PORT="${WEB_PORT:-8081}"
PG_PORT="${POSTGRES_PORT:-5432}"
PG_DSN="${PG_DSN:-postgres://uai:uai@localhost:${PG_PORT}/uai?sslmode=disable}"
ISSUER_KEY="${ISSUER_KEY:-.keys/issuer.jwk}"
ISSUER_DID="${ISSUER_DID:-did:web:credentials.uai.world}"
GO="${GO:-$(command -v go 2>/dev/null || echo "$HOME/.local/go/bin/go")}"

if [ "$CONTAINER" != podman ]; then
    COMPOSE=(docker compose -f "$COMPOSE_FILE")
elif command -v podman-compose >/dev/null 2>&1; then
    COMPOSE=(podman-compose -f "$COMPOSE_FILE")
else
    COMPOSE=(podman compose -f "$COMPOSE_FILE")
fi

BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'; RESET=$'\033[0m'

say()  { printf '%s\n' "$*"; }
step() { printf '%s==>%s %s\n' "$BOLD" "$RESET" "$*"; }
warn() { printf '%s!%s   %s\n' "$RED" "$RESET" "$*"; }

need() {
    command -v "$1" >/dev/null 2>&1 || {
        warn "$1 is required and not on PATH."
        [ -n "${2:-}" ] && say "    $2"
        exit 1
    }
}

build() {
    step "building images"
    # Built here rather than pulled: there is no published image yet, and a
    # deploy script that pulled an unpinned one would be installing whatever
    # was pushed last (threat T-07).
    "$CONTAINER" build --file deploy/containers/Containerfile.gateway \
        --tag localhost/uai-gateway:dev . >/dev/null
    "$CONTAINER" build --file deploy/containers/Containerfile.web \
        --tag localhost/uai-web:dev . >/dev/null
    say "    uai-gateway:dev  uai-web:dev"
}

issuer_key() {
    [ -f "$ISSUER_KEY" ] && return 0
    step "creating the credential issuer key"
    # Created once, on purpose, and never at container boot. A key that changed
    # on every restart would issue credentials that stop verifying, and the
    # operator would learn about it from verification failures rather than from
    # a startup error.
    mkdir -p "$(dirname "$ISSUER_KEY")" && chmod 700 "$(dirname "$ISSUER_KEY")"
    "$GO" run ./tools/uai-keygen -out "$ISSUER_KEY" -did "$ISSUER_DID" >/dev/null
    say "    $ISSUER_KEY  ${DIM}(never commit this; .keys/ is gitignored)${RESET}"
}

# seed_issuer_key copies the credential issuer key into a volume the gateway
# can actually read.
#
# .keys/ is 0700 for the host user and the gateway runs as uid 65532, so a bind
# mount of it is unreadable inside the container. The two obvious "fixes" are
# both wrong: widening the permissions on a private key, or running the service
# as root. This does neither — a short-lived helper (which IS the host user
# under rootless Podman, and root under Docker, so it can read the file either
# way) copies the key into a volume and gives it to the service user.
seed_issuer_key() {
    step "handing the issuer key to the gateway"
    "$CONTAINER" volume create uai_keys >/dev/null 2>&1 || true
    "$CONTAINER" run --rm \
        -v uai_keys:/dst \
        -v "$PWD/.keys:/src:ro" \
        --entrypoint sh \
        "$(pg_image)" -c \
        'cp /src/issuer.jwk /dst/issuer.jwk && chown 65532:65532 /dst/issuer.jwk && chmod 400 /dst/issuer.jwk' \
        >/dev/null
    say "    uai_keys:/issuer.jwk  ${DIM}(0400, owned by the service user)${RESET}"
}

# pg_image is the postgres image the stack already pins, reused as the helper
# rather than pulling a second one nobody reviewed (threat T-07).
pg_image() {
    sed -n 's|.*image: \(docker.io/library/postgres.*\)|\1|p' "$COMPOSE_FILE"
}

wait_for() {
    local what="$1" probe="$2" tries="${3:-60}"
    for _ in $(seq 1 "$tries"); do
        if eval "$probe" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    warn "$what did not come up"
    return 1
}

up() {
    need "$CONTAINER"
    need psql "Install the PostgreSQL client: it applies the schema."
    [ -x "$GO" ] || need go "Install Go 1.27, or set GO=/path/to/go."

    issuer_key
    build
    seed_issuer_key

    # SPIRE, when it is already running. Passed as environment rather than
    # written into the compose file, so that a stack without attestation is a
    # configuration and not a different file.
    if [ -s .spire/bootstrap.pem ]; then
        export UAI_SPIRE_BUNDLE=/spire/bootstrap.pem
        export UAI_SPIRE_TRUST_DOMAIN="${SPIRE_TRUST_DOMAIN:-uai.test}"
    else
        export UAI_SPIRE_BUNDLE="" UAI_SPIRE_TRUST_DOMAIN=""
    fi
    mkdir -p .spire

    # Infrastructure first, schema second, services third. `depends_on` waits
    # for postgres to be HEALTHY, which is not the same as migrated: on a fresh
    # volume the gateway came up against an empty database, failed on a missing
    # table and exited, and the migrations that would have fixed it ran a second
    # later against a container that was already gone.
    step "starting infrastructure"
    "${COMPOSE[@]}" up -d postgres spire-server >/dev/null 2>&1 \
        || "${COMPOSE[@]}" up -d postgres spire-server

    # A real query, not pg_isready: postgres restarts itself during first-time
    # initialisation, so pg_isready can say yes to a server about to shut down.
    wait_for "postgres" "psql '$PG_DSN' -qtAc 'select 1'"

    step "applying the schema"
    "$GO" run ./tools/uai-migrate -dsn "$PG_DSN" -dir db/migrations up | sed 's/^/    /'
    "$GO" run ./tools/uai-migrate -dsn "$PG_DSN" -dir db/seed up | sed 's/^/    /'

    step "starting the platform"
    "${COMPOSE[@]}" up -d >/dev/null 2>&1 || "${COMPOSE[@]}" up -d

    wait_for "the gateway" "curl -sf http://127.0.0.1:$GATEWAY_PORT/v1/quarantines" 40
    wait_for "the web" "curl -sf http://127.0.0.1:$WEB_PORT/" 40

    say
    status
    say
    say "  ${BOLD}Open${RESET}  http://localhost:${WEB_PORT}"
    say "  ${DIM}The verify page checks proofs in your browser. Everything else is a view.${RESET}"
    if [ -z "${UAI_SPIRE_BUNDLE:-}" ]; then
        say
        say "  ${DIM}Runtime attestation is off: bindings will record runtimes agents"
        say "  describe about themselves. Turn it on with: make spire-up && ./deploy.sh up${RESET}"
    fi
}

down() {
    step "stopping containers"
    "${COMPOSE[@]}" down >/dev/null 2>&1 || "${COMPOSE[@]}" down
    say "    stopped; the data is kept (./deploy.sh nuke deletes it)"
}

nuke() {
    step "stopping containers and deleting the data"
    "${COMPOSE[@]}" down -v >/dev/null 2>&1 || "${COMPOSE[@]}" down -v
    # The SPIRE agent's state goes with the server's. An agent holding an SVID
    # from a CA that no longer exists reports failures that look like the
    # workload's fault.
    rm -rf .spire/data .spire/public .spire/svid .spire/bootstrap.pem .spire/agent.log
    say "    gone"
}

status() {
    say "  ${BOLD}containers${RESET}"
    if ! "$CONTAINER" ps --filter "label=io.podman.compose.project=uai" \
        --format '    {{.Names}}  {{.Status}}' 2>/dev/null | grep -q .; then
        "$CONTAINER" ps --format '    {{.Names}}  {{.Status}}' | grep -E 'uai' \
            || say "    ${DIM}nothing running${RESET}"
    else
        "$CONTAINER" ps --filter "label=io.podman.compose.project=uai" \
            --format '    {{.Names}}  {{.Status}}'
    fi
    say
    say "  ${BOLD}ports${RESET}"
    printf '    %-28s %s\n' "http://localhost:$WEB_PORT" "the five surfaces"
    printf '    %-28s %s\n' "http://localhost:$GATEWAY_PORT" "the API"
    printf '    %-28s %s\n' "localhost:$PG_PORT" "PostgreSQL"
    say
    say "  ${BOLD}runtime attestation${RESET}"
    if [ -f .spire/agent.pid ] && kill -0 "$(cat .spire/agent.pid)" 2>/dev/null; then
        printf '    %son%s   the SPIRE agent is attesting host workloads\n' "$GREEN" "$RESET"
    else
        printf '    %soff%s  bindings record self-declared runtimes  %s(make spire-up)%s\n' \
            "$DIM" "$RESET" "$DIM" "$RESET"
    fi
}

logs() {
    if [ $# -gt 0 ]; then
        "${COMPOSE[@]}" logs -f "$1"
    else
        "${COMPOSE[@]}" logs -f
    fi
}

case "${1:-}" in
    up)     up ;;
    down)   down ;;
    nuke)   nuke ;;
    status) status ;;
    build)  build ;;
    logs)   shift; logs "$@" ;;
    *)
        say "usage: ./deploy.sh {up|down|nuke|status|build|logs [service]}"
        say
        say "  up      build what is missing, start everything, apply the schema"
        say "  down    stop everything, keep the data"
        say "  nuke    stop everything and delete the data"
        say "  status  what is running, and on which ports"
        say "  build   rebuild the images without starting anything"
        say "  logs    follow the logs of one service, or all of them"
        exit 1
        ;;
esac
