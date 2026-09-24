// Package uai is the Go client for the UAI API: the one used by UAI's own
// services and by uai-mcp.
//
// # What an SDK in this system can and cannot do
//
// Every other component of UAI is built assuming the agent may be adversarial.
// This package runs inside the agent's process, so it inherits none of that
// protection: an agent that does not want to be accountable simply does not
// call it. That is not a gap to be closed — it is the reason the protocol puts
// verification in the relying party rather than in the agent's toolchain.
//
// What the SDK can do is make the accountable path the easy one, and make the
// unaccountable path require someone to deliberately take it. Three design
// choices follow from that, and they are the whole point of this package:
//
//   - Act attests on the way out, always. Not only on success: if the work
//     panics, returns an error, or is refused by policy, an attestation is still
//     submitted with the matching outcome. An accountability record that
//     contains only successes is an advertisement.
//
//   - A denial stops the work. Evaluate runs before the closure, and a DENY
//     means the closure never executes. The refusal is then attested as
//     ABORTED_BY_POLICY, so the agent's own chain shows the request that was
//     refused — a refusal nobody wrote down is indistinguishable from a request
//     nobody made.
//
//   - Content never leaves the process. Inputs and outputs are committed
//     locally with a fresh random salt and only the commitment is sent. The salt
//     comes back to the caller, because a commitment whose salt nobody kept can
//     never be opened by anyone, which is the same as having recorded nothing.
//
// # What it deliberately does not do
//
// It does not hold or generate private keys. A Signer is supplied by the caller
// and may be backed by a file, an HSM or a remote KMS; this package never sees
// key material and never writes any.
//
// It does not retry a denied decision, soften a refusal into a warning, or
// carry a "force" option. There is no argument to Act that turns a DENY into
// execution.
package uai
