#!/usr/bin/env bash
# Run the invariant suite and FAIL when it does.
#
# This exists because `psql ... | grep PASS` is not a gate. A pipeline's exit
# status is the last command's, so the shape this replaced --
#
#     psql -f invariants.sql 2>&1 | grep -E 'PASS|FAIL' | sed ...
#
# -- printed "FAIL  INV-003  the forbidden operation SUCCEEDED" in red and then
# exited 0. Every invariant could have been broken and `make integration` would
# still have been green. The suite was written, run, and read by a human; it was
# never enforced.
#
# Usage:  run.sh psql "$PG_DSN"
#         run.sh podman exec -i uai-pg-test psql -U uai -d uai
#
# Everything after the script name is the psql invocation; the SQL arrives on
# its stdin, which is the one form that works both locally and through a
# container exec.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sql="$here/invariants.sql"
out="$(mktemp)"
trap 'rm -f "$out"' EXIT

if [ $# -eq 0 ]; then
    echo "usage: run.sh <psql invocation...>" >&2
    exit 2
fi

# The suite must not be able to shrink or stop early unnoticed. A run that
# exits after ten assertions because the eleventh hit a syntax error would
# otherwise report ten passes and nothing else -- technically true, and the
# most misleading thing a security gate can say.
#
# Expected = the assertions the file contains. Derived rather than committed as
# a number, so adding an invariant needs no second edit; what it catches is a
# run that did not reach the end of the file it was given.
expected=$(( $(grep -c '^SELECT assert_fails(' "$sql") \
           + $(grep -c "RAISE NOTICE 'PASS  [A-Z]" "$sql") ))

status=0
"$@" -v ON_ERROR_STOP=1 -q -f - < "$sql" > "$out" 2>&1 || status=$?

# A passing assertion arrives as a NOTICE and a failing one as an ERROR, both
# behind a psql prefix. Strip the prefix from BOTH: a report that renders the
# passes and hides the failures behind log noise is the wrong way round.
report="$(sed -E 's/^psql:[^:]*:[0-9]+: (NOTICE|ERROR):  //' "$out" | grep -E '^(PASS|FAIL)' || true)"
echo "$report"

failed=$(printf '%s\n' "$report" | grep -c '^FAIL' || true)
passed=$(printf '%s\n' "$report" | grep -c '^PASS' || true)

if [ "$failed" -ne 0 ]; then
    echo
    echo "invariants: $failed FORBIDDEN OPERATION(S) SUCCEEDED."
    echo "A negative test that passes means the threat model's control is not there."
    exit 1
fi
if [ "$status" -ne 0 ]; then
    echo
    echo "invariants: psql exited $status -- the suite did not complete."
    # Not a failed assertion, then: a broken fixture, a missing table, a schema
    # the suite was not written against. Show what psql actually said.
    grep -E '^psql:[^:]*:[0-9]+: ERROR:' "$out" | tail -3 | sed -E 's/^psql:[^:]*:[0-9]+: //'
    exit 1
fi
if [ "$passed" -ne "$expected" ]; then
    echo
    echo "invariants: $passed assertions ran, $expected are in $sql."
    echo "The suite did not run to the end. Its silence is not evidence."
    exit 1
fi

echo "invariants: $passed/$expected assertions -- every forbidden operation was refused"
