#!/bin/sh
# Report the configuration of the gateway container that is RUNNING.
#
# A process takes its mode when it starts, so a TLS certificate on disk or a
# SPIRE agent started afterwards says what the NEXT `deploy.sh up` will do, not
# what the gateway now serving requests does. Asking the container is the only
# answer that is about the present.
#
#   tools/gateway-env.sh            every UAI_* setting, as NAME=value
#   tools/gateway-env.sh UAI_SCHEME just that value
#
# Exits 1 when no gateway is running, so a caller can tell "off" from "absent".
set -eu

CONTAINER="${CONTAINER:-$(command -v podman >/dev/null 2>&1 && echo podman || echo docker)}"

name="$("$CONTAINER" ps --format '{{.Names}}' 2>/dev/null \
    | grep -E 'uai[-_]gateway' | head -1)" || true
[ -n "${name:-}" ] || exit 1

env_lines="$("$CONTAINER" inspect "$name" \
    --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
    | grep -E '^UAI_' || true)"

if [ $# -gt 0 ]; then
    printf '%s\n' "$env_lines" | sed -n "s/^$1=//p" | head -1
    exit 0
fi
printf '%s\n' "$env_lines"
