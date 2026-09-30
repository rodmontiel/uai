// Package assurance derives an identity's assurance level from evidence.
//
// §6.8 gives a table with three columns -- key protection, owner verification,
// runtime attestation -- and the columns are conjunctive: an identity is at the
// highest level whose EVERY requirement it meets. So the level is the minimum
// across the three, and computing it is the only honest way to produce it.
//
// Before this package, agents.assurance_level was written once at registration
// as "UAI-AL0" and never again by anything. Every identity was AL0 for life,
// the AL2 rules in the policy bundle could not fire, and the column looked like
// a setting somebody had forgotten to change rather than a fact about evidence.
//
// The other half of the job is saying WHY. A bare AL0 is indistinguishable from
// a misconfiguration; "AL0, limited by owner verification" tells a relying party
// what would have to change. No dependencies, no I/O.
package assurance

import "fmt"

// Level is an assurance level of §6.8.
type Level int

// The levels, ordered.
const (
	AL0 Level = iota
	AL1
	AL2
	AL3
)

// String renders the level as it appears on the wire.
func (l Level) String() string {
	switch l {
	case AL1:
		return "UAI-AL1"
	case AL2:
		return "UAI-AL2"
	case AL3:
		return "UAI-AL3"
	default:
		return "UAI-AL0"
	}
}

// Parse reads a level from its wire form.
func Parse(s string) (Level, error) {
	switch s {
	case "UAI-AL0":
		return AL0, nil
	case "UAI-AL1":
		return AL1, nil
	case "UAI-AL2":
		return AL2, nil
	case "UAI-AL3":
		return AL3, nil
	}
	return AL0, fmt.Errorf("assurance: %q is not an assurance level", s)
}

// KeyProtection is how the agent's signing key is held (§6.8 column 1).
type KeyProtection string

// The key_protection values the registry stores.
const (
	Software      KeyProtection = "SOFTWARE"
	TPM2          KeyProtection = "TPM2"
	SecureEnclave KeyProtection = "SECURE_ENCLAVE"
	HSM           KeyProtection = "HSM"
	CloudKMS      KeyProtection = "CLOUD_KMS"
	WebAuthn      KeyProtection = "WEBAUTHN"
)

// OwnerVerification is how the owner was established (§6.8 column 2).
type OwnerVerification string

// The owner verification states.
const (
	// SelfAsserted is where every owner is today: the DID is claimed, and
	// nothing has demonstrated control of it. §20.5 records the missing control.
	SelfAsserted     OwnerVerification = "SELF_ASSERTED"
	DomainControl    OwnerVerification = "DOMAIN_CONTROL"
	OrgCredential    OwnerVerification = "ORG_CREDENTIAL_VERIFIED"
	LegalEntityProof OwnerVerification = "LEGAL_ENTITY_VERIFIED"
)

// RuntimeAttestation is what is known about where the agent runs (§6.8 col 3).
type RuntimeAttestation string

// The runtime states.
const (
	// NoRuntime covers both "never bound" and "bound with a runtime the agent
	// described itself", because those are worth the same: nothing.
	NoRuntime RuntimeAttestation = "NONE"
	// SVIDOnly is an attested SPIFFE identity with no image digest: the
	// process is who it says, and what code it is running is unestablished.
	SVIDOnly RuntimeAttestation = "SVID"
	// SVIDWithImage adds the image digest the attestor observed.
	SVIDWithImage RuntimeAttestation = "SVID_IMAGE"
	// RemoteAttestation is TEE evidence about the execution environment.
	RemoteAttestation RuntimeAttestation = "REMOTE_ATTESTATION"
)

// Evidence is what the registry knows about one identity.
type Evidence struct {
	Key     KeyProtection
	Owner   OwnerVerification
	Runtime RuntimeAttestation
}

// Dimension names one of §6.8's three columns.
type Dimension string

// The dimensions, spelled as they are reported.
const (
	DimKey     Dimension = "key protection"
	DimOwner   Dimension = "owner verification"
	DimRuntime Dimension = "runtime attestation"
)

// Result is a level with the reason it is not higher.
type Result struct {
	Level Level
	// LimitedBy is the dimension holding the level down, and is empty only at
	// AL3 where nothing does.
	LimitedBy Dimension
	// Detail is one sentence a relying party or an owner can act on.
	Detail string
	// Reached is what each dimension supports on its own, so a caller can show
	// the whole picture rather than only the binding constraint.
	Reached map[Dimension]Level
}

// keyLevel is the highest level this key protection supports.
func keyLevel(k KeyProtection) Level {
	switch k {
	case TPM2, SecureEnclave, CloudKMS, WebAuthn:
		return AL2
	case HSM:
		return AL3
	default:
		// Unknown protections read as software. A protection nobody recognises
		// is not evidence of anything, and guessing upward is the one direction
		// this must never guess in.
		return AL1
	}
}

func ownerLevel(o OwnerVerification) Level {
	switch o {
	case DomainControl:
		return AL1
	case OrgCredential:
		return AL2
	case LegalEntityProof:
		return AL3
	default:
		return AL0
	}
}

func runtimeLevel(r RuntimeAttestation) Level {
	switch r {
	case SVIDOnly:
		return AL1
	case SVIDWithImage:
		return AL2
	case RemoteAttestation:
		return AL3
	default:
		return AL0
	}
}

// details explains, per dimension, what is missing at the level below.
var details = map[Dimension]map[Level]string{
	DimKey: {
		AL0: "the agent's signing key is software-held",
		AL1: "the agent's signing key is software-held; AL2 needs a TPM, secure enclave or KMS",
		AL2: "the agent's signing key is not in an HSM",
	},
	DimOwner: {
		AL0: "the owner is self-asserted; nothing has demonstrated control of its DID",
		AL1: "the owner proved domain control; AL2 needs a verified organization credential",
		AL2: "the organization credential is verified; AL3 needs legal-entity verification",
	},
	DimRuntime: {
		AL0: "no attested runtime; a binding the agent described itself is not attestation",
		AL1: "the runtime holds an attested SVID with no image digest, so what code it runs is unestablished",
		AL2: "the runtime is attested with an image digest; AL3 needs remote attestation of the execution environment",
	},
}

// Derive computes the level and the dimension that limits it.
//
// Ties are broken toward the dimension a reader can act on soonest: key
// protection, then runtime, then owner. All three are reported in Reached, so
// nothing is hidden by the choice -- it only decides which sentence leads.
func Derive(e Evidence) Result {
	reached := map[Dimension]Level{
		DimKey: keyLevel(e.Key), DimOwner: ownerLevel(e.Owner), DimRuntime: runtimeLevel(e.Runtime),
	}
	level := reached[DimKey]
	for _, l := range reached {
		if l < level {
			level = l
		}
	}
	if level >= AL3 {
		return Result{Level: AL3, Detail: "every dimension is at its maximum", Reached: reached}
	}
	for _, d := range []Dimension{DimKey, DimRuntime, DimOwner} {
		if reached[d] == level {
			return Result{Level: level, LimitedBy: d, Detail: details[d][level], Reached: reached}
		}
	}
	// Unreachable: level is the minimum of the map, so some dimension equals it.
	return Result{Level: level, Reached: reached}
}

// FromEvidence derives a level from the raw values a registry records about one
// identity: every currently-valid key protection, how the owner was
// established, the attestor that vouched for the live runtime (empty when
// nothing is bound), and the image digest recorded with it.
//
// It exists so there is exactly one translation from stored strings to a level.
// Before it, the API turned an attestor into a RuntimeAttestation privately,
// which meant any other reader -- an operator CLI, a report, a migration
// check -- had to reimplement the rule that "self-declared" is worth nothing,
// and a second implementation of that rule is a second answer to the only
// question this package exists to answer.
func FromEvidence(keyProtections []string, ownerVerification, attestor, imageDigest string) Result {
	return Derive(Evidence{
		Key:     Strongest(keyProtections),
		Owner:   OwnerVerification(ownerVerification),
		Runtime: RuntimeOf(attestor, imageDigest),
	})
}

// RuntimeOf reads §6.8's third column off what a binding recorded.
//
// "self-declared" maps to NONE deliberately. A runtime the agent described
// itself is worth the same as no runtime at all -- it is the agent's word about
// where it is running, signed by the agent.
//
// An image digest counts only because an attestor supplied it as a selector. A
// digest the agent typed into a request body is its own claim about its own
// code, and the caller must not pass one here.
func RuntimeOf(attestor, imageDigest string) RuntimeAttestation {
	switch {
	case attestor == "" || attestor == "self-declared":
		return NoRuntime
	case imageDigest != "":
		return SVIDWithImage
	default:
		return SVIDOnly
	}
}

// Strongest picks the best key protection an identity holds.
//
// Neither the database enum's declaration order nor its alphabet is a strength
// order: sorted as text, TPM2 comes after HSM; declared, WEBAUTHN comes last.
// Ranking is a policy question and it lives here, once, beside the table that
// gives it meaning.
//
// An empty list is Software rather than an error. An identity with no valid key
// is in trouble for reasons assurance is not the right place to report, and the
// answer to "how well is its key protected" is still "not at all".
func Strongest(protections []string) KeyProtection {
	best, bestLevel := Software, keyLevel(Software)
	for _, p := range protections {
		k := KeyProtection(p)
		if l := keyLevel(k); l > bestLevel {
			best, bestLevel = k, l
		}
	}
	return best
}
