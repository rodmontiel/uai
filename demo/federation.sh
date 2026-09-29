#!/usr/bin/env bash
# Two independently administered UAI installations, peering and exchanging one
# signed statement about an identity.
#
#   demo/federation.sh          run it and tear it down
#   demo/federation.sh --keep   leave both stacks up, to look at the pages
#   demo/federation.sh --down   tear down a --keep run
#
# Two databases and two gateways, because that is the claim being demonstrated:
# not that one process can talk to itself, but that two registries with separate
# state can recognise each other without either becoming the other's database.
set -euo pipefail
cd "$(dirname "$0")/.."

A_ASN=1001;  A_PG=55471; A_PORT=8091; A_NAME="OMniLeads-UAI"
B_ASN=2001;  B_PG=55472; B_PORT=8092; B_NAME="Partner-UAI"
KEYS=.keys/federation
CONTAINER="${CONTAINER:-$(command -v podman >/dev/null 2>&1 && echo podman || echo docker)}"
PG_IMAGE="${PG_IMAGE:-docker.io/library/postgres:16-alpine}"
GO="$(./tools/find-go.sh 2>/dev/null || echo go)"

BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'; RED=$'\033[31m'; RESET=$'\033[0m'
say()  { printf '%s\n' "$*"; }
step() { printf '\n%s==>%s %s\n' "$BOLD" "$RESET" "$*"; }
ok()   { printf '    %s✓%s %s\n' "$GREEN" "$RESET" "$*"; }
die()  { printf '    %s✗%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }

dsn() { echo "postgres://uai:uai@localhost:$1/uai?sslmode=disable"; }

down() {
    for pid in "$KEYS"/*.pid; do
        [ -e "$pid" ] || continue
        kill "$(cat "$pid")" 2>/dev/null || true
        rm -f "$pid"
    done
    # Anything still holding the demo ports is a process an earlier run leaked.
    # Left alone, the next run talks to it and reports whatever it says.
    for port in $A_PORT $B_PORT; do
        # `|| true` on the assignment, not only on the kill: a plain assignment
        # takes the exit status of its command substitution, and grep finding
        # nothing is a failure -- which under `set -e` ends the script in the
        # ordinary case where no stale process exists.
        local stale=""
        stale=$(ss -ltnp 2>/dev/null | grep ":$port " | grep -oP 'pid=\K[0-9]+' | head -1) || true
        [ -n "$stale" ] && kill "$stale" 2>/dev/null || true
    done
    $CONTAINER rm -f uai-fed-a uai-fed-b >/dev/null 2>&1 || true
}

case "${1:-}" in
    --down) step "stopping both registries"; down; ok "gone"; exit 0 ;;
esac
KEEP=no
[ "${1:-}" = "--keep" ] && KEEP=yes

trap 'if [ "$KEEP" = no ]; then down; fi' EXIT

# ── infrastructure ──────────────────────────────────────────────────────────

start_pg() { # name port
    $CONTAINER rm -f "$1" >/dev/null 2>&1 || true
    $CONTAINER run -d --name "$1" -e POSTGRES_USER=uai -e POSTGRES_PASSWORD=uai \
        -e POSTGRES_DB=uai -p "127.0.0.1:$2:5432" "$PG_IMAGE" >/dev/null
    for _ in $(seq 1 60); do
        $CONTAINER exec "$1" psql -U uai -d uai -qtAc 'select 1' >/dev/null 2>&1 && return 0
        sleep 1
    done
    die "postgres $1 did not come up"
}

migrate() { # dsn
    for f in $(ls db/migrations/*.up.sql db/seed/*.up.sql | sort); do
        psql "$1" -v ON_ERROR_STOP=1 -q -f "$f" >/dev/null || die "migration $f failed"
    done
}

# The binary, not `go run`. `go run` compiles to a temporary path and execs it as
# a CHILD: the pid it reports is the wrapper's, so killing it leaves the gateway
# listening. The next run then found the port answering, skipped its own start,
# and talked to the previous build -- which looked exactly like a code change
# that had no effect.
start_gateway() { # label asn name port pg_port
    local label=$1 asn=$2 name=$3 port=$4 pgport=$5
    PG_DSN="$(dsn "$pgport")" \
    UAI_ASN="$asn" UAI_REGISTRY_NAME="$name" \
    UAI_REGISTRY_KEY="$KEYS/registry-$asn.jwk" \
    UAI_FEDERATION_ENDPOINT="http://127.0.0.1:$port" \
        "$KEYS/gateway" -addr "127.0.0.1:$port" -scheme http \
            -issuer-key "$KEYS/issuer-$asn.jwk" \
            -log-origin "uai.test/log/$asn" \
            > "$KEYS/gateway-$asn.log" 2>&1 &
    echo $! > "$KEYS/gateway-$asn.pid"
    for _ in $(seq 1 60); do
        curl -sf "http://127.0.0.1:$port/v1/federation/registry" >/dev/null 2>&1 && return 0
        sleep 1
    done
    say "    the $label gateway did not come up:"
    tail -6 "$KEYS/gateway-$asn.log" | sed 's/^/      /'
    die "gateway $asn"
}

fed() { # asn args...
    local asn=$1; shift
    local port=$A_PORT
    [ "$asn" = "$B_ASN" ] && port=$B_PORT
    UAI_ENDPOINT="http://127.0.0.1:$port" UAI_REGISTRY_KEY="$KEYS/registry-$asn.jwk" \
        "$GO" run ./tools/uai-federate "$@"
}

step "building two independent registries"
mkdir -p "$KEYS" && chmod 700 "$KEYS"
down
"$GO" build -o "$KEYS/gateway" ./services/gateway || die "could not build the gateway"
# The scenario's keys go with the scenario's databases, which are rebuilt on
# every run. Keeping them would leave an owner key naming an owner no database
# has -- the exact state `uai-register owner -reuse-key` exists for, and not
# something a demo should make the reader work through.
#
# The REGISTRY keys are not scenario keys and are kept: a registry's number and
# the key it signs with are its identity, and an identity that changed on every
# run would make every peering it had ever established stop verifying.
rm -f "$KEYS"/owner-*.jwk "$KEYS"/alpha.jwk
for asn in $A_ASN $B_ASN; do
    [ -f "$KEYS/issuer-$asn.jwk" ] || \
        "$GO" run ./tools/uai-keygen -out "$KEYS/issuer-$asn.jwk" \
            -did "did:web:credentials-$asn.uai.test" >/dev/null
    # The registry key is NOT the issuer key. One signs credentials about agents,
    # the other signs what this installation says about itself to its peers.
    [ -f "$KEYS/registry-$asn.jwk" ] || \
        "$GO" run ./tools/uai-keygen -out "$KEYS/registry-$asn.jwk" \
            -did "did:uai-registry:$asn" >/dev/null
done
start_pg uai-fed-a "$A_PG"; migrate "$(dsn "$A_PG")"
start_pg uai-fed-b "$B_PG"; migrate "$(dsn "$B_PG")"
start_gateway "A" "$A_ASN" "$A_NAME" "$A_PORT" "$A_PG"
start_gateway "B" "$B_ASN" "$B_NAME" "$B_PORT" "$B_PG"
ok "AS$A_ASN on :$A_PORT and AS$B_ASN on :$B_PORT, with separate databases"

# ── step 1: each shows who it is ────────────────────────────────────────────

step "step 1 — each registry says who it is"
fed $A_ASN show | sed 's/^/  A /'
fed $B_ASN show | sed 's/^/  B /'

# ── step 2: configure the peering, both ways ────────────────────────────────

step "step 2 — configure AS$A_ASN ↔ AS$B_ASN"
fed $A_ASN peer add -asn $B_ASN -endpoint-remote "http://127.0.0.1:$B_PORT" \
    -trust-on-first-use 2>&1 | sed 's/^/  A /'
fed $B_ASN peer add -asn $A_ASN -endpoint-remote "http://127.0.0.1:$A_PORT" \
    -trust-on-first-use 2>&1 | sed 's/^/  B /'

# ── step 3: handshake ───────────────────────────────────────────────────────

step "step 3 — handshake"
fed $A_ASN handshake -asn $B_ASN | sed 's/^/  A /'
fed $B_ASN handshake -asn $A_ASN | sed 's/^/  B /'
fed $B_ASN peers | sed 's/^/  B /'
UAI_ENDPOINT="http://127.0.0.1:$B_PORT" "$GO" run ./tools/uai-federate peers \
    | grep -q "ACTIVE" || die "the peering did not reach ACTIVE at B"
ok "PEER ACTIVE in both directions"

# ── step 4: AS1001 has an identity ──────────────────────────────────────────

step "step 4 — AS$A_ASN registers an identity of its own"
export PG_DSN="$(dsn "$A_PG")" UAI_ENDPOINT="http://127.0.0.1:$A_PORT"
unset UAI_API_CA
OWNER_OUT=$("$GO" run ./tools/uai-register owner -name "ACME Robotics" \
    -org-did did:web:acme-fed.example -key "$KEYS/owner-$A_ASN.jwk" 2>&1) || {
        say "$OWNER_OUT"; die "could not create the owner"; }
OWNER_DID=$(printf '%s\n' "$OWNER_OUT" | awk '/owner  /{print $2}')
AGENT_OUT=$("$GO" run ./tools/uai-register agent -owner-did "$OWNER_DID" -name "ALPHA" \
    -owner-key "$KEYS/owner-$A_ASN.jwk" -key "$KEYS/alpha.jwk" 2>&1) || {
        say "$AGENT_OUT"; die "could not register the agent"; }
UAI_ID=$(printf '%s\n' "$AGENT_OUT" | awk '/uai-id/{print $2}')
ok "AS$A_ASN issued $UAI_ID"

# ── step 5 and 6: announce, and let B judge it ──────────────────────────────

step "step 5 — AS$A_ASN announces it to AS$B_ASN"
fed $A_ASN announce -uai-id "$UAI_ID" -to $B_ASN -sequence 1042 | sed 's/^/  A /'

step "step 6 — AS$B_ASN checked peer, signature and sequence"
ok "accepted, and recorded as a claim rather than as an identity"

step "step 7 — what AS$B_ASN now holds"
fed $B_ASN identities | sed 's/^/  B /'

# ── what it refuses ─────────────────────────────────────────────────────────

step "and what AS$B_ASN refuses"
ULID=${UAI_ID##*:}
replay=$(fed $A_ASN announce -uai-id "$UAI_ID" -to $B_ASN -sequence 1042 2>&1 || true)
printf '%s\n' "$replay" | grep -q "STALE_SEQUENCE" \
    && ok "a replayed announcement: STALE_SEQUENCE" \
    || die "a replay was not refused: $replay"

# A registry with a perfectly valid key, announcing an identity it did not issue.
# Its signature verifies. Being able to sign is not authority, and this is the
# case that shows the difference.
forged=$(fed $B_ASN announce -uai-id "$UAI_ID" -to $A_ASN \
    -forge-did "did:uai:$A_ASN:agent:$ULID" 2>&1 || true)
printf '%s\n' "$forged" | grep -q "WRONG_AUTHORITY" \
    && ok "AS$B_ASN trying to revoke AS$A_ASN's identity: WRONG_AUTHORITY" \
    || die "a registry revoked another registry's identity: $forged"

# FED-002, checked where it matters: B's own agent table.
local_rows=$(psql "$(dsn "$B_PG")" -qtAc "SELECT count(*) FROM agents")
[ "$local_rows" = "0" ] && ok "AS$B_ASN has 0 local agents: a federated identity is not one (FED-002)" \
    || die "AS$B_ASN has $local_rows local agents; a federated identity became one"

step "done"
say "  Two registries, separately administered, recognised each other and shared one"
say "  cryptographically verifiable statement about an identity — without either"
say "  becoming the other's database."
if [ "$KEEP" = yes ]; then
    say
    say "  ${BOLD}Left running.${RESET}"
    say "    A  http://127.0.0.1:$A_PORT/v1/federation/registry   ${DIM}(AS$A_ASN)${RESET}"
    say "    B  http://127.0.0.1:$B_PORT/v1/federation/identities ${DIM}(AS$B_ASN)${RESET}"
    say "    stop with: demo/federation.sh --down"
fi
