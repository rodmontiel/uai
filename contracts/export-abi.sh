#!/usr/bin/env bash
# Export the compiled ABIs to spec/contracts/ as specification artifacts.
#
# The ABI is what a third party integrates against, so it belongs with the
# schemas and the test vectors rather than in a build directory. Committing it
# also means the INV-007/008 check runs on a machine with no Solidity toolchain,
# and that a change to a contract's surface shows up as a reviewable diff
# instead of appearing silently at deploy time.
set -euo pipefail
cd "$(dirname "$0")"
out="../spec/contracts"
mkdir -p "$out"
for name in Roles UAIIdentityRegistry UAIPolicyRegistry UAITransparencyAnchor \
            UAIQuarantineRegistry UAIGovernance UAIVoting UAIRevocationRegistry; do
    # ABI only. Bytecode is a build output that differs with compiler settings;
    # the ABI is the contract's promise, and that is what must not drift.
    python3 -c "
import json, sys
src = json.load(open('out/$name.sol/$name.json'))
json.dump({'contract': '$name', 'abi': src['abi']}, open('$out/$name.abi.json', 'w'),
          indent=2, sort_keys=True)
open('$out/$name.abi.json', 'a').write('\n')
"
done
echo "exported $(ls "$out" | wc -l) ABIs to spec/contracts/"
