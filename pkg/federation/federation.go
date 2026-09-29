// Package federation implements the UAI Autonomous Registry System wire format:
// the peer handshake and the identity announcement.
//
// A UAI-AS is one installation of this registry, identified by a number of its
// own and speaking for the identities it registered. Two of them can recognise
// each other and exchange signed statements without either one becoming the
// other's database.
//
// The distinction this package exists to keep is between two kinds of trust:
//
//	PEER TRUST   this registry is allowed to send me federated statements
//	AGENT TRUST  I believe what it says about a particular identity
//
// They are not the same, and nothing here converts the first into the second.
// An accepted announcement is recorded as what it is -- another registry's
// claim -- and never as a local identity.
//
// Like every package under pkg/, this takes no external dependencies: it is on
// the verification path, and a relying party checking a peer's statement should
// not have to trust a dependency tree to do it.
package federation

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// ProtocolVersion is the federation wire version this package produces.
const ProtocolVersion = "0.1"

// Message types.
const (
	TypeHello        = "REGISTRY_HELLO"
	TypeAnnouncement = "IDENTITY_ANNOUNCEMENT"
)

// MaxClockSkew is how far a peer's clock may be from ours before its message is
// refused. Generous, because a handshake refused over a minute of drift reads
// as a broken peer; bounded, because a message with no freshness at all is one
// an attacker can keep replaying after the nonce cache has forgotten it.
const MaxClockSkew = 5 * time.Minute

// Validation failures, as the reasons a peer is told.
var (
	ErrUnsigned         = errors.New("federation: message is not signed")
	ErrWrongDomain      = errors.New("federation: signature was not made in the federation domain")
	ErrInvalidPayload   = errors.New("federation: payload is incomplete or malformed")
	ErrInvalidSignature = errors.New("federation: signature does not verify")
	ErrUnknownPeer      = errors.New("federation: the origin registry is not a configured peer")
	ErrPeerNotActive    = errors.New("federation: the peering with that registry is not ACTIVE")
	ErrStaleSequence    = errors.New("federation: sequence is not newer than the last one accepted")
	ErrClockSkew        = errors.New("federation: timestamp is outside the accepted window")
	ErrWrongAuthority   = errors.New("federation: the identity is not under the authority of the registry announcing it")
)

// Reason renders a validation failure as the short code a peer receives.
//
// The codes are part of the wire contract: a peer that is refused has to be
// able to act on the refusal, and "invalid" tells it nothing about whether to
// fix its clock, its key, or its configuration.
func Reason(err error) string {
	switch {
	case err == nil:
		return "ACCEPTED"
	case errors.Is(err, ErrUnknownPeer):
		return "UNKNOWN_PEER"
	case errors.Is(err, ErrPeerNotActive):
		return "PEER_NOT_ACTIVE"
	case errors.Is(err, ErrStaleSequence):
		return "STALE_SEQUENCE"
	case errors.Is(err, ErrInvalidSignature), errors.Is(err, ErrUnsigned),
		errors.Is(err, ErrWrongDomain):
		return "INVALID_SIGNATURE"
	case errors.Is(err, ErrClockSkew):
		return "STALE_TIMESTAMP"
	case errors.Is(err, ErrWrongAuthority):
		return "WRONG_AUTHORITY"
	default:
		return "INVALID_PAYLOAD"
	}
}

// ── registry identifiers ────────────────────────────────────────────────────

// ASN is a UAI Autonomous Registry System number.
//
// Deliberately its own number space and not the Internet's: a UAI-AS is not an
// IP routing domain, and borrowing real ASNs would imply an authority to assign
// them that nobody here has.
type ASN uint32

var registryDIDRE = regexp.MustCompile(`^did:uai-registry:([1-9][0-9]{0,9})$`)

// String renders the ASN as a decimal number, for messages that name it.
func (a ASN) String() string { return strconv.FormatUint(uint64(a), 10) }

// RegistryDID renders the DID of a registry.
func RegistryDID(asn ASN) string { return "did:uai-registry:" + strconv.FormatUint(uint64(asn), 10) }

// ParseRegistryDID reads the ASN out of a registry DID.
func ParseRegistryDID(did string) (ASN, error) {
	m := registryDIDRE.FindStringSubmatch(did)
	if m == nil {
		return 0, fmt.Errorf("%w: %q is not a registry DID", ErrInvalidPayload, did)
	}
	n, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: %q: %v", ErrInvalidPayload, did, err)
	}
	return ASN(n), nil
}

// agentDIDRE matches the federated spelling of an agent DID, which names the
// registry that issued it. A bare did:uai:agent:… says who but not under whose
// authority, and authority is the only thing an announcement is about.
var agentDIDRE = regexp.MustCompile(`^did:uai:([1-9][0-9]{0,9}):agent:([0-7][0-9A-HJKMNP-TV-Z]{25})$`)

// AgentDID renders the federated DID of an agent under a registry.
func AgentDID(asn ASN, ulid string) string {
	return "did:uai:" + strconv.FormatUint(uint64(asn), 10) + ":agent:" + ulid
}

// AuthorityOf returns the ASN a federated agent DID names as its registry.
func AuthorityOf(agentDID string) (ASN, error) {
	m := agentDIDRE.FindStringSubmatch(agentDID)
	if m == nil {
		return 0, fmt.Errorf("%w: %q is not a federated agent DID", ErrInvalidPayload, agentDID)
	}
	n, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: %q: %v", ErrInvalidPayload, agentDID, err)
	}
	return ASN(n), nil
}

// ── REGISTRY_HELLO ──────────────────────────────────────────────────────────

// Hello is one registry introducing itself to another.
type Hello struct {
	Type            string              `json:"type"`
	ProtocolVersion string              `json:"protocol_version"`
	UAIASN          ASN                 `json:"uai_asn"`
	RegistryDID     string              `json:"registry_did"`
	RegistryName    string              `json:"registry_name"`
	Endpoint        string              `json:"federation_endpoint"`
	PublicJWK       uaicrypto.JWK       `json:"public_jwk"`
	Timestamp       uaicrypto.Timestamp `json:"timestamp"`
	Nonce           string              `json:"nonce"`
	Signature       uaicrypto.Signature `json:"signature"`
}

// SigningBytes returns the canonical bytes covered by the signature: the
// document minus its signature, exactly as §10.4 does for an attestation.
func (h Hello) SigningBytes() ([]byte, error) {
	return uaicrypto.CanonicalizeWithout(h, "signature")
}

// Sign returns a signed copy.
func Sign(signer uaicrypto.Signer, h Hello) (Hello, error) {
	h.Type, h.ProtocolVersion = TypeHello, ProtocolVersion
	payload, err := h.SigningBytes()
	if err != nil {
		return Hello{}, err
	}
	sig, err := signer.Sign(uaicrypto.DomainFederationHello, payload)
	if err != nil {
		return Hello{}, err
	}
	h.Signature = sig
	return h, nil
}

// Validate checks everything about a hello that does not need the database:
// its shape, its freshness, and that it is internally consistent.
//
// The signature is NOT checked here, because checking it needs the key, and
// which key is the question a hello exists to answer. The caller resolves the
// key -- from a configured peer, or from the hello's own public_jwk on a first
// contact it has explicitly chosen to accept -- and calls Verify.
func (h Hello) Validate(now time.Time) error {
	switch {
	case h.Type != TypeHello:
		return fmt.Errorf("%w: type is %q, want %s", ErrInvalidPayload, h.Type, TypeHello)
	case h.ProtocolVersion != ProtocolVersion:
		return fmt.Errorf("%w: protocol version %q, this registry speaks %s",
			ErrInvalidPayload, h.ProtocolVersion, ProtocolVersion)
	case h.UAIASN == 0:
		return fmt.Errorf("%w: uai_asn is required", ErrInvalidPayload)
	case strings.TrimSpace(h.Nonce) == "":
		return fmt.Errorf("%w: nonce is required", ErrInvalidPayload)
	}
	asn, err := ParseRegistryDID(h.RegistryDID)
	if err != nil {
		return err
	}
	if asn != h.UAIASN {
		// A hello whose DID and ASN disagree names two registries. Accepting it
		// would let a peer be recorded under one number while its statements
		// verify under another.
		return fmt.Errorf("%w: registry_did names AS%d and uai_asn says %d",
			ErrInvalidPayload, asn, h.UAIASN)
	}
	return checkSkew(h.Timestamp.Time, now)
}

// Verify checks the signature against a key the caller has decided to trust.
func (h Hello) Verify(pub crypto.PublicKey) error {
	if h.Signature.Value == "" {
		return ErrUnsigned
	}
	if h.Signature.Domain != uaicrypto.DomainFederationHello {
		return fmt.Errorf("%w: %q", ErrWrongDomain, h.Signature.Domain)
	}
	payload, err := h.SigningBytes()
	if err != nil {
		return err
	}
	if err := uaicrypto.Verify(pub, uaicrypto.DomainFederationHello, payload, h.Signature); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	return nil
}

// ── IDENTITY_ANNOUNCEMENT ───────────────────────────────────────────────────

// Announcement is a registry's signed statement about an identity it registered.
//
// Every member is a fact about authority or status. There is deliberately no
// free-form member, and decoding refuses unknown ones (see Decode): a field a
// sender could fill with anything is a field that will eventually carry a
// prompt, a conversation or a customer's name into another operator's database.
type Announcement struct {
	Type            string              `json:"type"`
	ProtocolVersion string              `json:"protocol_version"`
	OriginUAIASN    ASN                 `json:"origin_uai_asn"`
	AgentDID        string              `json:"agent_did"`
	AgentStatus     string              `json:"agent_status"`
	Timestamp       uaicrypto.Timestamp `json:"timestamp"`
	Sequence        int64               `json:"sequence"`
	CredentialHash  string              `json:"credential_hash"`
	Signature       uaicrypto.Signature `json:"signature"`
}

// Statuses an announcement may carry. They mirror the local lifecycle, and the
// list is closed: an unknown status from a peer is a payload this registry does
// not understand, not a status to store and hope somebody interprets later.
var announceableStatus = map[string]bool{
	"REGISTERED": true, "ACTIVE": true, "SUSPENDED": true,
	"QUARANTINED": true, "REVOKED": true, "RETIRED": true,
}

// SigningBytes returns the canonical bytes covered by the signature.
func (a Announcement) SigningBytes() ([]byte, error) {
	return uaicrypto.CanonicalizeWithout(a, "signature")
}

// SignAnnouncement returns a signed copy.
func SignAnnouncement(signer uaicrypto.Signer, a Announcement) (Announcement, error) {
	a.Type, a.ProtocolVersion = TypeAnnouncement, ProtocolVersion
	payload, err := a.SigningBytes()
	if err != nil {
		return Announcement{}, err
	}
	sig, err := signer.Sign(uaicrypto.DomainFederationAnnouncement, payload)
	if err != nil {
		return Announcement{}, err
	}
	a.Signature = sig
	return a, nil
}

// Validate checks the announcement's shape, freshness, and -- the part that
// matters most -- that the registry signing it is the one the identity's DID
// names as its authority.
//
// That last check is what stops a peer announcing somebody else's agents. A
// registry may say anything about the identities it issued and nothing about
// the identities it did not.
func (a Announcement) Validate(now time.Time) error {
	switch {
	case a.Type != TypeAnnouncement:
		return fmt.Errorf("%w: type is %q, want %s", ErrInvalidPayload, a.Type, TypeAnnouncement)
	case a.ProtocolVersion != ProtocolVersion:
		return fmt.Errorf("%w: protocol version %q, this registry speaks %s",
			ErrInvalidPayload, a.ProtocolVersion, ProtocolVersion)
	case a.OriginUAIASN == 0:
		return fmt.Errorf("%w: origin_uai_asn is required", ErrInvalidPayload)
	case !announceableStatus[a.AgentStatus]:
		return fmt.Errorf("%w: agent_status %q is not one this registry understands",
			ErrInvalidPayload, a.AgentStatus)
	case a.Sequence <= 0:
		return fmt.Errorf("%w: sequence must be positive", ErrInvalidPayload)
	}
	if _, err := uaicrypto.ParseDigest(a.CredentialHash); err != nil {
		return fmt.Errorf("%w: credential_hash: %v", ErrInvalidPayload, err)
	}
	authority, err := AuthorityOf(a.AgentDID)
	if err != nil {
		return err
	}
	if authority != a.OriginUAIASN {
		return fmt.Errorf("%w: %s belongs to AS%d, announced by AS%d",
			ErrWrongAuthority, a.AgentDID, authority, a.OriginUAIASN)
	}
	return checkSkew(a.Timestamp.Time, now)
}

// Verify checks the signature against the peer's registered key.
func (a Announcement) Verify(pub crypto.PublicKey) error {
	if a.Signature.Value == "" {
		return ErrUnsigned
	}
	if a.Signature.Domain != uaicrypto.DomainFederationAnnouncement {
		return fmt.Errorf("%w: %q", ErrWrongDomain, a.Signature.Domain)
	}
	payload, err := a.SigningBytes()
	if err != nil {
		return err
	}
	if err := uaicrypto.Verify(pub, uaicrypto.DomainFederationAnnouncement, payload, a.Signature); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	return nil
}

// CheckSequence refuses an announcement that does not advance.
//
// Without it, a captured announcement can be replayed to move an identity back
// to a status it has left -- turning a revoked identity into an active one by
// resending yesterday's message.
func CheckSequence(last, incoming int64) error {
	if incoming <= last {
		return fmt.Errorf("%w: last accepted %d, this one %d", ErrStaleSequence, last, incoming)
	}
	return nil
}

// ── shared ──────────────────────────────────────────────────────────────────

func checkSkew(t, now time.Time) error {
	if t.IsZero() {
		return fmt.Errorf("%w: timestamp is required", ErrInvalidPayload)
	}
	d := now.Sub(t)
	if d < 0 {
		d = -d
	}
	if d > MaxClockSkew {
		return fmt.Errorf("%w: %s is %s from now", ErrClockSkew,
			t.UTC().Format(time.RFC3339), d.Round(time.Second))
	}
	return nil
}

// Decode reads a federated message and refuses members it does not know.
//
// This is where "the announcement must not carry prompts, conversations, PII or
// secrets" stops being a rule in a document and becomes something the code
// enforces. A decoder that ignored unknown members would accept them, store
// nothing, and leave the sender believing they had been delivered -- or, worse,
// leave a future version of this struct picking them up.
func Decode[T Hello | Announcement](raw []byte) (T, error) {
	var out T
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}
	return out, nil
}
