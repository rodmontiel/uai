#!/usr/bin/env bash
# Regenerate the screenshots the README embeds, from a running stack.
#
# They are committed because a README needs them, and they are generated rather
# than pasted because a screenshot taken by hand goes stale silently: the page
# changes, the image does not, and the README keeps showing a product that no
# longer exists. Re-running this is the only way to notice.
#
#   ./deploy.sh up && ./tools/screenshots.sh uai:agent:01M3QA6…
set -euo pipefail

WEB="${UAI_WEB:-http://localhost:8081}"
OUT="${UAI_SCREENSHOT_DIR:-docs/img}"
AGENT="${1:-}"

browser=""
for candidate in chromium chromium-browser google-chrome; do
    if command -v "$candidate" >/dev/null 2>&1; then browser="$candidate"; break; fi
done
[ -n "$browser" ] || { echo "screenshots: no chromium on PATH" >&2; exit 1; }

if [ -z "$AGENT" ]; then
    echo "usage: $0 <uai-id>" >&2
    echo "  e.g. $0 \"\$(go run ./tools/uai-register show | awk '/^  uai:agent:/{print \$1}' | head -1)\"" >&2
    exit 2
fi

# A page that answered 404 still screenshots, as an error card. Check first, so a
# broken capture fails here rather than being committed as the product's face.
code=$(curl -s -o /dev/null -w '%{http_code}' "$WEB/agent.html") || true
[ "$code" = "200" ] || { echo "screenshots: $WEB/agent.html answered $code" >&2; exit 1; }

mkdir -p "$OUT"
shoot() { # shoot <file> <url> <height>
    "$browser" --headless --disable-gpu --no-sandbox --hide-scrollbars \
        --window-size="1280,$3" --virtual-time-budget=6000 \
        --screenshot="$OUT/$1" "$2" >/dev/null 2>&1
    printf '  %s\n' "$OUT/$1"
}

shoot agent-passport.png "$WEB/agent.html?id=$AGENT" 880
