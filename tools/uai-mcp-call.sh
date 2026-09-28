#!/bin/sh
# Call one tool on the UAI MCP server and print the result.
#
# An MCP server speaks JSON-RPC over stdin/stdout and wants an `initialize`
# handshake before anything else, which makes trying a single tool by hand more
# ceremony than the tool is worth. This does the handshake, sends one call, and
# prints what came back.
#
#   tools/uai-mcp-call.sh --list
#   tools/uai-mcp-call.sh uai_get_status
#   tools/uai-mcp-call.sh uai_check_policy '{"capability":"docs.read","purpose":"…"}'
#
# Identity comes from UAI_AGENT_ID and UAI_AGENT_KEY, or from -uai-id and -key.
# The gateway's address is asked of the gateway that is RUNNING, because the
# answer changes with whether attestation is on and a default of http against a
# TLS gateway fails with an error that names neither.
#
# Every call it makes is signed by the agent key exactly as any other client
# would sign it. This is a convenience for reading the output, not a second way
# to be an agent.
set -eu

cd "$(dirname "$0")/.."

usage() {
    cat >&2 <<'USAGE'
usage: tools/uai-mcp-call.sh [options] <tool-name> ['<json arguments>']
       tools/uai-mcp-call.sh [options] --list

options (or the matching UAI_* environment variable):
  -endpoint URL    gateway URL          (UAI_ENDPOINT)
  -ca PATH         PEM CA bundle        (UAI_API_CA)
  -uai-id ID       the identity to sign as (UAI_AGENT_ID)
  -key PATH        that identity's key  (UAI_AGENT_KEY)
  -owner-did DID   owner recorded in attestations (UAI_OWNER_DID)
USAGE
    exit 2
}

endpoint="${UAI_ENDPOINT:-}"
ca="${UAI_API_CA:-}"
uai_id="${UAI_AGENT_ID:-}"
key="${UAI_AGENT_KEY:-}"
owner="${UAI_OWNER_DID:-}"
tool=""
args="{}"

# Flags anywhere, before or after the tool name. The first version accepted them
# nowhere and ignored them in silence, so `... -endpoint https://…` appended to
# a failing command changed nothing and looked like the flag had no effect.
while [ $# -gt 0 ]; do
    case "$1" in
        -endpoint)  endpoint="${2:?-endpoint needs a URL}"; shift 2 ;;
        -ca)        ca="${2:?-ca needs a path}"; shift 2 ;;
        -uai-id)    uai_id="${2:?-uai-id needs an identifier}"; shift 2 ;;
        -key)       key="${2:?-key needs a path}"; shift 2 ;;
        -owner-did) owner="${2:?-owner-did needs a DID}"; shift 2 ;;
        --list)     tool="--list"; shift ;;
        -h|--help)  usage ;;
        -*)         echo "unknown option: $1" >&2; usage ;;
        *)
            if [ -z "$tool" ]; then tool="$1"
            elif [ "$args" = "{}" ]; then args="$1"
            else echo "unexpected argument: $1" >&2; usage
            fi
            shift ;;
    esac
done

[ -n "$tool" ] || usage

# The address of the gateway that is running, not a default that is right half
# the time. Only consulted when the caller said nothing.
if [ -z "$endpoint" ]; then
    scheme="$(CONTAINER="${CONTAINER:-}" ./tools/gateway-env.sh UAI_SCHEME 2>/dev/null || true)"
    endpoint="${scheme:-http}://localhost:8080"
fi
if [ -z "$ca" ] && [ "${endpoint#https://}" != "$endpoint" ] && [ -s .spire/bootstrap.pem ]; then
    ca=.spire/bootstrap.pem
fi

if [ -z "$uai_id" ] || [ -z "$key" ]; then
    echo "this call has to be signed by a registered identity." >&2
    echo "  set UAI_AGENT_ID and UAI_AGENT_KEY, or pass -uai-id and -key." >&2
    echo "  \`go run ./tools/uai-register show\` lists what this database holds." >&2
    exit 2
fi
[ -f "$key" ] || { echo "no key at $key" >&2; exit 2; }

SERVER="./uai-mcp"
if [ ! -x "$SERVER" ]; then
    GO="$(./tools/find-go.sh 2>/dev/null || echo go)"
    "$GO" build -o ./uai-mcp ./mcp || { echo "could not build ./uai-mcp" >&2; exit 2; }
fi

if [ "$tool" = "--list" ]; then
    request='{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
else
    request=$(printf '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"%s","arguments":%s}}' \
        "$tool" "$args")
fi

# stderr kept, not discarded. The first version sent it to /dev/null, so a server
# that failed to start produced an empty stdout, an empty parse, and exit 0 --
# a command that says nothing and claims success.
err=$(mktemp)
trap 'rm -f "$err"' EXIT
out=$(printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"uai-mcp-call","version":"0.1"}}}' \
  "$request" \
| "$SERVER" -endpoint "$endpoint" ${ca:+-ca "$ca"} \
    -uai-id "$uai_id" -key "$key" ${owner:+-owner-did "$owner"} 2>"$err") || {
    echo "the MCP server exited without answering:" >&2
    sed 's/^/  /' "$err" >&2
    exit 1
}

printf '%s' "$out" | tail -1 | UAI_ENDPOINT="$endpoint" python3 -c '
import json, os, sys

raw = sys.stdin.read().strip()
if not raw:
    sys.exit("the MCP server answered nothing. Is the gateway at "
             + os.environ.get("UAI_ENDPOINT", "?") + " running?")
try:
    doc = json.loads(raw)
except json.JSONDecodeError:
    sys.exit("the MCP server did not answer JSON:\n  " + raw[:400])
if "error" in doc:
    sys.exit("error: " + json.dumps(doc["error"], indent=2, ensure_ascii=False))
result = doc.get("result", {})
if "tools" in result:
    for t in result["tools"]:
        print("  %-24s %s" % (t.get("name", ""), t.get("title", "")))
    sys.exit(0)
if not result.get("content"):
    sys.exit("the server returned no content:\n  " + json.dumps(doc)[:400])
for part in result["content"]:
    text = part.get("text", "")
    try:
        print(json.dumps(json.loads(text), indent=2, ensure_ascii=False))
    except json.JSONDecodeError:
        print(text)
# A tool refusal is a failure of the call, and a shell that reads $? has to see
# it. The first version printed the refusal and exited 0.
if result.get("isError"):
    sys.exit(1)
'
