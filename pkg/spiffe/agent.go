package spiffe

import (
	"fmt"
	"strings"

	"github.com/rodmontiel/uai/pkg/uaiid"
)

// AgentPrefix is the path segment under which UAI workloads live.
//
// §9.1 shows spiffe://uai.world/agents/01JY…/i/7f6a92 -- the trust domain says
// who runs the infrastructure, and the path says which UAI identity the process
// is allowed to be.
const AgentPrefix = "/agents/"

// AgentULID returns the agent ULID a SPIFFE ID names, canonically spelled.
//
// This is the mapping §9.1 step 6 calls "verify SVID subject matches uai_id".
// Without it, a valid SVID for ANY workload in the trust domain would attest
// ANY agent identity: the certificate would be genuine, the binding would
// verify, and the runtime it named would be somebody else's. The registration
// entry that issues the SVID is what decides which process may hold which path,
// so this is where SPIRE's decision is read back.
//
// Parsed rather than compared as a string, and returned canonically, because
// the identifier is the value and not its spelling -- pkg/uaiid decodes
// Crockford's ambiguous characters and encodes one canonical form. Comparing
// raw path text would reject a transcribed registration entry that names
// exactly the right agent.
//
// Everything after the ULID is free: an instance discriminator, a replica
// index, whatever the operator's registration entries use. Only the identity
// is load-bearing.
func (id ID) AgentULID() (string, error) {
	if !strings.HasPrefix(id.Path, AgentPrefix) {
		return "", fmt.Errorf("%w: %s does not name a UAI agent (no %q prefix)",
			ErrInvalidID, id, AgentPrefix)
	}
	raw, _, _ := strings.Cut(strings.TrimPrefix(id.Path, AgentPrefix), "/")
	u, err := uaiid.ParseULID(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %q is not a ULID, so %s names no identity: %v",
			ErrInvalidID, raw, id, err)
	}
	return u.String(), nil
}

// Attests reports whether this SVID may speak for a UAI-ID, and says why not.
//
// uaiID is the full identifier ("uai:agent:01JY…"); only the ULID is compared,
// because that is what a SPIFFE path carries.
func (s *SVID) Attests(uaiID string) error {
	named, err := s.ID.AgentULID()
	if err != nil {
		return err
	}
	want := uaiID
	if i := strings.LastIndex(uaiID, ":"); i >= 0 {
		want = uaiID[i+1:]
	}
	parsed, err := uaiid.ParseULID(want)
	if err != nil {
		return fmt.Errorf("%w: %q is not a UAI agent identifier: %v", ErrInvalidID, uaiID, err)
	}
	if named != parsed.String() {
		// Not ErrUntrusted: the certificate is genuine and the trust domain is
		// right. What is wrong is which identity it is being used to attest,
		// and that distinction is the whole of §9.1 step 6.
		return fmt.Errorf("%w: the SVID attests agent %s and the binding claims %s",
			ErrWrongSubject, named, parsed)
	}
	return nil
}
