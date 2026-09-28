#!/bin/sh
# Call one tool on the UAI MCP server and print the result.
#
# An MCP server speaks JSON-RPC over stdin/stdout and expects an `initialize`
# handshake before anything else, which makes trying a single tool by hand more
# ceremony than the tool is worth. This does the handshake, sends one call, and
# prints what came back.
#
#   tools/uai-mcp-call.sh uai_get_status
#   tools/uai-mcp-call.sh uai_check_policy '{"capability":"docs.read","purpose":"…"}'
#
# It reads the same environment an agent would: UAI_ENDPOINT, UAI_API_CA,
# UAI_AGENT_ID, UAI_AGENT_KEY, UAI_OWNER_DID. This is a convenience for reading
# the output, not a second way to be an agent -- every call it makes is signed
# by UAI_AGENT_KEY exactly as the server would sign it for any other client.
set -eu

cd "$(dirname "$0")/.."

if [ $# -lt 1 ]; then
    echo "usage: tools/uai-mcp-call.sh <tool-name> ['<json arguments>']" >&2
    echo "       tools/uai-mcp-call.sh --list" >&2
    exit 2
fi

: "${UAI_ENDPOINT:=http://127.0.0.1:8080}"
: "${UAI_API_CA:=}"
: "${UAI_AGENT_ID:?set UAI_AGENT_ID to the UAI-ID this call signs as}"
: "${UAI_AGENT_KEY:?set UAI_AGENT_KEY to that identity's private key}"
: "${UAI_OWNER_DID:=}"

SERVER="./uai-mcp"
if [ ! -x "$SERVER" ]; then
    GO="$(./tools/find-go.sh 2>/dev/null || echo go)"
    "$GO" build -o ./uai-mcp ./mcp
fi

if [ "$1" = "--list" ]; then
    request='{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
else
    name="$1"
    args="${2:-{\}}"
    request=$(printf '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"%s","arguments":%s}}' \
        "$name" "$args")
fi

printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"uai-mcp-call","version":"0.1"}}}' \
  "$request" \
| "$SERVER" -endpoint "$UAI_ENDPOINT" ${UAI_API_CA:+-ca "$UAI_API_CA"} \
    -uai-id "$UAI_AGENT_ID" -key "$UAI_AGENT_KEY" \
    ${UAI_OWNER_DID:+-owner-did "$UAI_OWNER_DID"} 2>/dev/null \
| tail -1 \
| python3 -c '
import json, sys
try:
    doc = json.loads(sys.stdin.read() or "{}")
except json.JSONDecodeError:
    sys.exit("the server returned something that is not JSON")
if "error" in doc:
    sys.exit("error: " + json.dumps(doc["error"], indent=2, ensure_ascii=False))
result = doc.get("result", {})
if "tools" in result:
    for t in result["tools"]:
        print("  %-24s %s" % (t.get("name", ""), t.get("title", "")))
    sys.exit(0)
for part in result.get("content", []):
    text = part.get("text", "")
    try:
        print(json.dumps(json.loads(text), indent=2, ensure_ascii=False))
    except json.JSONDecodeError:
        print(text)
if result.get("isError"):
    sys.exit(1)
'
