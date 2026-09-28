#!/usr/bin/env bash
# Print the path of a Go toolchain new enough to build this module, or nothing.
#
# `command -v go` is not enough, which is the entire reason this file exists.
# Ubuntu's golang-go and gccgo-go packages install gccgo at /usr/bin/go, and
# gccgo 1.18 does not refuse with a version error. It gets as far as compiling
# and then says
#
#     package slices is not in GOROOT (/usr/src/slices)
#
# which reads like a broken checkout, and sends whoever hit it looking in the
# wrong place. Choosing by version instead of by PATH order makes that failure
# impossible to reach.
#
# Candidates are tried in order, so a correct `go` on PATH still wins.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

required=$(sed -n 's/^go \([0-9][0-9.]*\).*/\1/p' go.mod)
[ -n "$required" ] || { echo "go.mod names no Go version" >&2; exit 1; }

for candidate in "$(command -v go 2>/dev/null || true)" \
                 "$HOME/.local/go/bin/go" \
                 /usr/local/go/bin/go \
                 /snap/bin/go; do
    [ -n "$candidate" ] && [ -x "$candidate" ] || continue
    version=$("$candidate" version 2>/dev/null) || continue

    # gccgo reports "go version go1.18 gccgo (...)". It is a different compiler
    # with a different standard library, and its GOROOT is not a Go GOROOT.
    [ "${version#*gccgo}" != "$version" ] && continue

    number=${version#go version go}
    number=${number%% *}
    [ -n "$number" ] || continue

    # sort -V puts the smaller first; if that is the requirement, the candidate
    # is at least as new.
    if [ "$(printf '%s\n%s\n' "$required" "$number" | sort -V | head -1)" = "$required" ]; then
        echo "$candidate"
        exit 0
    fi
done
exit 1
