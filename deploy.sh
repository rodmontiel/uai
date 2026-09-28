#!/usr/bin/env bash
# UAI — bring the platform up or down as containers.
#
#   ./deploy.sh up        build what is missing, start everything, apply the schema
#   ./deploy.sh down      stop everything, keep the data
#   ./deploy.sh nuke      stop everything and delete the data (--keys: the keys too)
#   ./deploy.sh status    what is running, and on which ports
#   ./deploy.sh env       the exports for the stack that is running, for eval
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
# Chosen by version, not by PATH order: a distribution package can put gccgo at
# /usr/bin/go, and gccgo fails with "package slices is not in GOROOT" rather
# than with a version error. See tools/find-go.sh.
GO="${GO:-$(./tools/find-go.sh 2>/dev/null || true)}"

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
seed_secrets() {
    step "handing the gateway its keys"
    "$CONTAINER" volume create uai_keys >/dev/null 2>&1 || true
    # Always present, possibly empty: the mount below is unconditional, and a
    # bind mount of a directory that does not exist fails the whole step on the
    # path where attestation is simply off.
    mkdir -p .spire/gateway
    local script='cp /src/issuer.jwk /dst/issuer.jwk'
    local what="issuer.jwk"
    if [ -f .spire/gateway/tls.key ]; then
        # The TLS key is a private key too, and leaving it 0644 on the host so a
        # container could read it would be the same mistake in a nicer costume.
        script="$script && cp /tls/tls.pem /dst/tls.pem && cp /tls/tls.key /dst/tls.key"
        what="$what tls.pem tls.key"
    fi
    # The volume is emptied first. Leaving a TLS pair from a previous run beside
    # a bundle that no longer matches it is the exact state that produced an
    # unexplainable handshake failure.
    "$CONTAINER" run --rm \
        -v uai_keys:/dst \
        -v "$PWD/.keys:/src:ro" \
        -v "$PWD/.spire/gateway:/tls:ro" \
        --entrypoint sh \
        "$(pg_image)" -c \
        "rm -f /dst/* && $script && chown 65532:65532 /dst/* && chmod 400 /dst/*" \
        >/dev/null
    say "    uai_keys: $what  ${DIM}(0400, owned by the service user)${RESET}"
}

# mint_gateway_cert asks SPIRE for the gateway's own server certificate.
#
# Minted rather than self-signed so that both directions of the connection hang
# off one trust root: the browser's proxy verifies the gateway against the same
# bundle the gateway verifies agents against.
mint_gateway_cert() {
    step "minting the gateway's TLS certificate"
    mkdir -p .spire/gateway
    "${COMPOSE[@]}" exec -T spire-server /opt/spire/bin/spire-server x509 mint \
        -spiffeID "spiffe://${SPIRE_TRUST_DOMAIN:-uai.test}/gateway" \
        -dns uai-gateway -dns localhost -ttl 24h -write /tmp >/dev/null
    "$CONTAINER" cp "${SPIRE_CONTAINER:-uai_spire-server_1}:/tmp/svid.pem" .spire/gateway/tls.pem
    "$CONTAINER" cp "${SPIRE_CONTAINER:-uai_spire-server_1}:/tmp/key.pem" .spire/gateway/tls.key
    chmod 600 .spire/gateway/tls.key
    say "    spiffe://${SPIRE_TRUST_DOMAIN:-uai.test}/gateway  ${DIM}(dns: uai-gateway, localhost)${RESET}"
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
    if [ -z "$GO" ] || [ ! -x "$GO" ]; then
        warn "No Go toolchain new enough to build this module."
        say "    on PATH: $(command -v go 2>/dev/null || echo none)"
        command -v go >/dev/null 2>&1 && say "             $(go version 2>&1 | head -1)"
        say "    Ubuntu's golang-go and gccgo-go install gccgo, which cannot build this."
        say "    Install an official toolchain from https://go.dev/dl/, or set GO=/path/to/go."
        exit 1
    fi

    issuer_key
    build

    # Infrastructure first: minting the gateway's certificate needs the SPIRE
    # server answering, and the schema needs postgres.
    step "starting infrastructure"
    "${COMPOSE[@]}" up -d postgres spire-server >/dev/null 2>&1 \
        || "${COMPOSE[@]}" up -d postgres spire-server

    # SPIRE, when it is already running. Passed as environment rather than
    # written into the compose file, so that a stack without attestation is a
    # configuration and not a different file.
    mkdir -p .spire
    # Attestation is on when the SPIRE AGENT is running, not when a bundle file
    # happens to exist. A leftover bootstrap.pem from a stack that was since
    # nuked describes a CA that no longer exists: the gateway then served TLS
    # with a certificate nobody could verify and every handshake failed with
    # "bad record MAC", which names neither the stale file nor the missing
    # server. And with no agent running, no workload can obtain an SVID anyway,
    # so attestation would be on in name only.
    if [ -f .spire/agent.pid ] && kill -0 "$(cat .spire/agent.pid)" 2>/dev/null; then
        # Refreshed from the server that is running now, never read off disk.
        "${COMPOSE[@]}" exec -T spire-server /opt/spire/bin/spire-server bundle show \
            > .spire/bootstrap.pem
        test -s .spire/bootstrap.pem || { warn "the SPIRE server returned no bundle"; exit 1; }
        export UAI_SPIRE_BUNDLE=/spire/bootstrap.pem
        export UAI_SPIRE_TRUST_DOMAIN="${SPIRE_TRUST_DOMAIN:-uai.test}"
        # An SVID is presented as a client certificate, so attestation needs TLS
        # to have somewhere to put one. The gateway's own certificate is minted
        # by the same SPIRE, which means one trust root in both directions: the
        # client verifies the server against the bundle the server verifies
        # clients against.
        export UAI_TLS_CERT=/keys/tls.pem UAI_TLS_KEY=/keys/tls.key
        # The scheme the gateway rebuilds signed request URIs with. It has to
        # match what callers actually used: a gateway serving https while
        # believing it is http rebuilds a different URI than the client signed,
        # and every proof of possession fails with "signature verification
        # failed" — which reads like a broken client.
        export UAI_SCHEME=https
        export UAI_API_URL="https://uai-gateway:8080" UAI_API_CA=/spire/bootstrap.pem
        mint_gateway_cert
    else
        export UAI_SPIRE_BUNDLE="" UAI_SPIRE_TRUST_DOMAIN=""
        export UAI_TLS_CERT="" UAI_TLS_KEY=""
        export UAI_API_URL="http://uai-gateway:8080" UAI_API_CA=""
        export UAI_SCHEME=http
        # Removed rather than left behind: a certificate from a previous run is
        # the thing that made the stale case hard to see.
        rm -f .spire/gateway/tls.pem .spire/gateway/tls.key .spire/bootstrap.pem
    fi
    seed_secrets

    # Schema before services. `depends_on` waits for postgres to be HEALTHY,
    # which is not the same as migrated: on a fresh volume the gateway came up
    # against an empty database, failed on a missing table and exited, and the
    # migrations that would have fixed it ran a second later against a container
    # that was already gone.
    #
    # A real query, not pg_isready: postgres restarts itself during first-time
    # initialisation, so pg_isready can say yes to a server about to shut down.
    wait_for "postgres" "psql '$PG_DSN' -qtAc 'select 1'"

    step "applying the schema"
    "$GO" run ./tools/uai-migrate -dsn "$PG_DSN" -dir db/migrations up | sed 's/^/    /'
    "$GO" run ./tools/uai-migrate -dsn "$PG_DSN" -dir db/seed up | sed 's/^/    /'

    step "starting the platform"
    "${COMPOSE[@]}" up -d >/dev/null 2>&1 || "${COMPOSE[@]}" up -d

    local scheme=http probe=""
    [ -n "${UAI_TLS_CERT:-}" ] && scheme=https
    # --cacert, not -k: a readiness probe that skips verification would report a
    # gateway serving the wrong certificate as healthy.
    [ "$scheme" = https ] && probe="--cacert .spire/bootstrap.pem"
    wait_for "the gateway" \
        "curl -sf $probe $scheme://localhost:$GATEWAY_PORT/v1/quarantines" 40
    wait_for "the web" "curl -sf http://127.0.0.1:$WEB_PORT/" 40

    say
    status
    say
    say "  ${BOLD}Open${RESET}  http://localhost:${WEB_PORT}"
    say "  ${DIM}The verify page checks proofs in your browser. Everything else is a view.${RESET}"
    # Printed rather than left to be remembered, because the right answer changes
    # with the mode this run started in: the address and the CA are wrong half
    # the time otherwise, and the symptom is a TLS error that names neither.
    say
    say "  ${BOLD}To register from this shell${RESET}"
    say "    export PG_DSN=\"$PG_DSN\""
    say "    export UAI_ENDPOINT=\"$scheme://localhost:$GATEWAY_PORT\""
    if [ "$scheme" = https ]; then
        say "    export UAI_API_CA=\".spire/bootstrap.pem\""
    else
        # Cleared, not omitted: a CA exported during an attested run would stay
        # in the shell and be handed to a gateway that is no longer serving TLS.
        say "    unset UAI_API_CA"
    fi
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
    # --keys is opt-in and always will be. A private key deleted is gone: there
    # is no second copy, and the same file may still name an owner in a database
    # this script knows nothing about. But refusing to ever delete them left the
    # only fresh-start path as "work out which files to remove yourself", which
    # is a worse thing to teach.
    local wipe_keys=no
    case "${1:-}" in
        --keys) wipe_keys=yes ;;
        "")     ;;
        *)      warn "unknown option for nuke: $1"; say "    the only option is --keys"; exit 1 ;;
    esac

    step "stopping containers and deleting the data"
    "${COMPOSE[@]}" down -v >/dev/null 2>&1 || "${COMPOSE[@]}" down -v
    # The SPIRE agent's state goes with the server's. An agent holding an SVID
    # from a CA that no longer exists reports failures that look like the
    # workload's fault.
    rm -rf .spire/data .spire/public .spire/svid .spire/bootstrap.pem .spire/agent.log
    say "    gone"
    # The keys are deliberately NOT deleted: a private key is not something to
    # remove on a subcommand's say-so, and the same file may still name an owner
    # in another database. But they now outlive every record of them, and
    # `uai-register owner` refuses to overwrite one -- which is where this stops
    # being obvious and starts being a dead end.
    local keys=0
    for k in .keys/*.jwk; do [ -e "$k" ] && keys=$((keys + 1)); done
    [ "$keys" -gt 0 ] || return 0

    if [ "$wipe_keys" = yes ]; then
        step "deleting $keys key file(s)"
        # Named one by one on the way out. "Deleted 18 files" is not something a
        # person can check afterwards, and these are the files whose loss cannot
        # be undone by re-running anything.
        for k in .keys/*.jwk; do [ -e "$k" ] && say "    $k" && rm -f "$k"; done
        rm -rf .keys/demo .keys/pentest
        say "    gone. The next ./deploy.sh up creates a new issuer key."
        return 0
    fi

    say
    say "    ${BOLD}$keys key file(s) under .keys/ survived this.${RESET} They now name identities"
    say "    no database has. The keys are still yours, so there are two ways on:"
    say
    say "      ${BOLD}keep them${RESET}   register the same keys again"
    say "        uai-register owner -reuse-key -name 'ACME Robotics' -org-did did:web:acme.example"
    say "        uai-register agent -owner-did did:uai:owner:... -name 'MiAgente' -reuse-key"
    say
    say "      ${BOLD}start over${RESET}  ./deploy.sh nuke --keys   ${DIM}(deletes them, and says which)${RESET}"
}

# gateway_env prints one environment variable of the gateway container that is
# running now, and fails when none is.
#
# The reading lives in tools/gateway-env.sh because the Makefile needs the same
# answer, and two implementations of "what is the gateway running with" would
# drift into two different answers to one question.
gateway_env() { CONTAINER="$CONTAINER" ./tools/gateway-env.sh "$1"; }

# env prints the environment the tools read, for `eval "$(./deploy.sh env)"`.
#
# The same three lines `up` prints at the end, except that `up` prints them once
# and a terminal loses them the moment it closes. Everyone who came back the next
# day hit "no database: pass -dsn or set PG_DSN" and had to go find them again.
#
# Values come from the gateway that is running, so they are right for the mode it
# is in rather than for the mode it was in when someone wrote them down.
env_exports() {
    local scheme bundle
    if ! scheme="$(gateway_env UAI_SCHEME)"; then
        warn "no gateway is running; start one with ./deploy.sh up" >&2
        return 1
    fi
    bundle="$(gateway_env UAI_SPIRE_BUNDLE)"
    printf 'export PG_DSN=%s\n' "\"$PG_DSN\""
    printf 'export UAI_ENDPOINT=%s\n' "\"${scheme:-http}://localhost:$GATEWAY_PORT\""
    if [ -n "$bundle" ] && [ -s .spire/bootstrap.pem ]; then
        printf 'export UAI_API_CA=%s\n' "\"$PWD/.spire/bootstrap.pem\""
    else
        printf 'unset UAI_API_CA\n'
    fi
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
    local tls bundle running=yes
    tls="$(gateway_env UAI_TLS_CERT)" || running=no
    bundle="$(gateway_env UAI_SPIRE_BUNDLE)" || true

    say
    say "  ${BOLD}ports${RESET}"
    printf '    %-28s %s\n' "http://localhost:$WEB_PORT" "the five surfaces"
    local api=http
    [ -n "$tls" ] && api=https
    if [ "$running" = yes ]; then
        printf '    %-28s %s\n' "$api://localhost:$GATEWAY_PORT" "the API"
    else
        printf '    %-28s %s\n' "$api://localhost:$GATEWAY_PORT" "the API ${DIM}(not running)${RESET}"
    fi
    printf '    %-28s %s\n' "localhost:$PG_PORT" "PostgreSQL"
    say
    say "  ${BOLD}runtime attestation${RESET}"
    local agent=down
    [ -f .spire/agent.pid ] && kill -0 "$(cat .spire/agent.pid)" 2>/dev/null && agent=up
    if [ "$running" = no ]; then
        printf '    %s?%s    no gateway is running, so nothing is being attested\n' "$DIM" "$RESET"
    elif [ -n "$bundle" ]; then
        printf '    %son%s   the gateway binds runtimes to SPIFFE identities\n' "$GREEN" "$RESET"
        [ "$agent" = up ] || printf '    %s     but no SPIRE agent is running, so no workload can get an SVID  %s(make spire-up)%s\n' \
            "$RED" "$DIM" "$RESET"
    elif [ "$agent" = up ]; then
        # The state that reads as "on" from the filesystem and is off in fact.
        printf '    %soff%s  a SPIRE agent is running, but this gateway started before it\n' \
            "$RED" "$RESET"
        printf '         and takes its mode at startup  %s(./deploy.sh up)%s\n' "$DIM" "$RESET"
    else
        printf '    %soff%s  bindings record self-declared runtimes  %s(make spire-up && ./deploy.sh up)%s\n' \
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
    nuke)   nuke "${2:-}" ;;
    env)    env_exports ;;
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
