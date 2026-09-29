package api

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/federation"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
	"github.com/rodmontiel/uai/pkg/uaiid"
)

// Federation is this installation's identity as a UAI Autonomous Registry
// System, and the key it speaks to other registries with.
//
// Separate from the issuer key on purpose. The issuer signs credentials ABOUT
// agents; the registry key signs statements this installation makes about
// ITSELF to its peers. One key for both would mean that a peer who learned to
// verify our federation messages could also be handed a credential we never
// issued, and that compromising the federation path would compromise every
// credential ever issued here.
type Federation struct {
	Registry store.Registry
	Signer   uaicrypto.Signer
}

// WithFederation turns this registry into a peerable UAI-AS.
//
// Absent, every federation route answers 404 the way an unconfigured feature
// should: a registry that has not been given a number is not a silent member of
// a federation, it is not a member at all.
func WithFederation(f *Federation) Option { return func(srv *Server) { srv.federation = f } }

// federationEnabled writes the refusal for a registry with no federation
// identity, and reports whether the caller should stop.
func (s *Server) federationOff(w http.ResponseWriter, r *http.Request) bool {
	if s.federation != nil {
		return false
	}
	WriteProblem(w, r, http.StatusNotFound, "UAI_FEDERATION_NOT_CONFIGURED",
		"This registry has no UAI-AS identity, so it is not part of any federation.",
		WithRemediation("An operator configures one with UAI_ASN and UAI_REGISTRY_NAME, "+
			"and a registry signing key. See docs/Ejemplo_Practico_federation_es.md."))
	return true
}

// ── GET /v1/federation/registry ─────────────────────────────────────────────

// RegistryView is what this registry publishes about itself.
type RegistryView struct {
	UAIASN          federation.ASN `json:"uai_asn"`
	Name            string         `json:"name"`
	RegistryDID     string         `json:"registry_did"`
	Status          string         `json:"status"`
	Endpoint        string         `json:"federation_endpoint"`
	PublicJWK       uaicrypto.JWK  `json:"public_key"`
	ProtocolVersion string         `json:"protocol_version"`
}

func (s *Server) federationRegistry(w http.ResponseWriter, r *http.Request) {
	if s.federationOff(w, r) {
		return
	}
	reg := s.federation.Registry
	WriteJSON(w, http.StatusOK, RegistryView{
		UAIASN: reg.ASN, Name: reg.Name, RegistryDID: reg.DID, Status: reg.Status,
		Endpoint: reg.Endpoint, PublicJWK: reg.PublicJWK,
		ProtocolVersion: reg.ProtocolVersion,
	})
}

// ── GET /v1/federation/peers ────────────────────────────────────────────────

// PeerView is a peering as an operator sees it.
type PeerView struct {
	RemoteASN  federation.ASN `json:"remote_uai_asn"`
	RemoteDID  string         `json:"remote_registry_did"`
	Endpoint   string         `json:"remote_endpoint"`
	Status     string         `json:"status"`
	LastError  string         `json:"last_error,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	LastSeenAt *time.Time     `json:"last_seen_at,omitempty"`
}

func (s *Server) federationPeers(w http.ResponseWriter, r *http.Request) {
	if s.federationOff(w, r) {
		return
	}
	peers, err := s.db.Peers(r.Context())
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	out := make([]PeerView, 0, len(peers))
	for _, p := range peers {
		out = append(out, PeerView{
			RemoteASN: p.RemoteASN, RemoteDID: p.RemoteDID, Endpoint: p.Endpoint,
			Status: p.Status, LastError: p.LastError,
			CreatedAt: p.CreatedAt, LastSeenAt: p.LastSeenAt,
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"peers": out})
}

// ── POST /v1/federation/peers ───────────────────────────────────────────────

// PeerRequest configures a peering. It is signed by the LOCAL registry key.
//
// Not unauthenticated, and this is the decision that matters most in this file.
// Adding a peer says "this registry may send me federated statements". A route
// anybody could call would let whoever reached it add themselves, and every
// later check -- signature, sequence, authority -- would then pass, because they
// would all be checking a key the attacker had just registered.
//
// The key that may do it is the one that speaks for this installation. Peering
// is the registry acting for itself, so the registry's own key is the authority,
// exactly as an owner's key is the authority for a capability grant.
type PeerRequest struct {
	RemoteASN       federation.ASN      `json:"remote_uai_asn"`
	RemoteDID       string              `json:"remote_registry_did"`
	Endpoint        string              `json:"remote_endpoint"`
	RemotePublicJWK uaicrypto.JWK       `json:"remote_public_key"`
	Nonce           string              `json:"nonce"`
	Signature       uaicrypto.Signature `json:"signature"`
}

func (s *Server) federationAddPeer(w http.ResponseWriter, r *http.Request) {
	if s.federationOff(w, r) {
		return
	}
	req, ok := decode[PeerRequest](w, r)
	if !ok {
		return
	}
	local := s.federation.Registry

	// The signature first. Everything below it is the attacker's input until
	// this passes.
	//
	// The member is REMOVED, not blanked -- §10.4 again, and it caught this file
	// on its first run. A zeroed Signature struct marshals as four empty strings
	// that no signer ever produced, so the verifier hashed a document the sender
	// had not sent and every genuine request was refused.
	payload, err := uaicrypto.CanonicalizeWithout(req, "signature")
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST",
			"The peering request could not be canonicalized.")
		return
	}
	localKey, err := local.PublicJWK.Public()
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL",
			"This registry's own public key could not be read.")
		return
	}
	if err := uaicrypto.Verify(localKey, uaicrypto.DomainFederationPeering,
		payload, req.Signature); err != nil {
		WriteProblem(w, r, http.StatusUnauthorized, "UAI_FEDERATION_NOT_AUTHORIZED",
			"Configuring a peering requires a signature by this registry's own key.",
			WithRemediation("Use `uai-federate peer add`, which holds that key. "+
				"A peering an unauthenticated caller could create would make every "+
				"later signature check meaningless."))
		return
	}
	if req.Nonce == "" || s.db.Nonces().Seen(local.DID, req.Nonce, s.now().Add(federation.MaxClockSkew)) {
		WriteProblem(w, r, http.StatusConflict, "UAI_REPLAY",
			"This peering request has already been seen.",
			WithRemediation("Send a fresh nonce."))
		return
	}

	// Shape next, so a malformed peering is refused before it is stored.
	asn, err := federation.ParseRegistryDID(req.RemoteDID)
	switch {
	case err != nil:
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST", err.Error())
		return
	case asn != req.RemoteASN:
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST",
			"remote_registry_did names AS"+asn.String()+" and remote_uai_asn says "+
				req.RemoteASN.String()+".")
		return
	case req.RemoteASN == local.ASN:
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST",
			"A registry cannot peer with itself.",
			WithRemediation("Every identity would then appear twice, once as local and "+
				"once as federated."))
		return
	case req.Endpoint == "":
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST", "remote_endpoint is required.")
		return
	}
	if _, err := req.RemotePublicJWK.Public(); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "UAI_BAD_REQUEST",
			"remote_public_key is not a usable key: "+err.Error(),
			WithRemediation("The peer's key is recorded here and never taken from the "+
				"messages it is used to check."))
		return
	}

	id, err := uaiid.NewULID()
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL", "Could not mint an id.")
		return
	}
	peer := store.Peer{
		ID: "peer-" + id.String(), LocalASN: local.ASN, RemoteASN: req.RemoteASN,
		RemoteDID: req.RemoteDID, Endpoint: req.Endpoint, PublicJWK: req.RemotePublicJWK,
	}
	if err := s.db.CreatePeer(r.Context(), peer); err != nil {
		WriteStoreError(w, r, err)
		return
	}
	s.auditFederation(r, "PEER_CREATED", "federation_peer", req.RemoteDID, "SUCCESS", map[string]any{
		"remote_uai_asn": req.RemoteASN, "remote_endpoint": req.Endpoint,
	})
	WriteJSON(w, http.StatusCreated, map[string]any{
		"remote_uai_asn": req.RemoteASN,
		"status":         "PENDING",
		"note": "A configured peer may send federated statements. It does not mean this " +
			"registry trusts its agents: peer trust and agent trust are separate, and " +
			"nothing here converts one into the other.",
	})
}

// ── POST /v1/federation/handshake ───────────────────────────────────────────

// handshake receives a peer's REGISTRY_HELLO and answers with our own.
//
// The order of checks is the whole security of the exchange:
//
//  1. Shape and freshness, which need nothing but the message.
//  2. The sender must already be a configured peer. An unknown registry is
//     refused here, before any key is read.
//  3. The signature, against the key recorded when the peering was configured
//     -- never against the key inside the message, which is the sender's claim
//     about itself.
//  4. The nonce, so a captured hello cannot be replayed into an ACTIVE peering.
//
// Only then does PENDING become ACTIVE.
func (s *Server) federationHandshake(w http.ResponseWriter, r *http.Request) {
	if s.federationOff(w, r) {
		return
	}
	hello, err := federation.Decode[federation.Hello](Body(r))
	if err != nil {
		s.refuseFederation(w, r, "PEER_HANDSHAKE_FAILED", "federation_peer", "unknown", err)
		return
	}
	now := s.now()
	if err := hello.Validate(now); err != nil {
		s.refuseFederation(w, r, "PEER_HANDSHAKE_FAILED", "federation_peer", hello.RegistryDID, err)
		return
	}

	peer, err := s.db.PeerByASN(r.Context(), hello.UAIASN)
	if errors.Is(err, store.ErrNotFound) {
		s.refuseFederation(w, r, "PEER_HANDSHAKE_FAILED", "federation_peer", hello.RegistryDID,
			federation.ErrUnknownPeer)
		return
	}
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	if peer.Status == "DISABLED" {
		s.refuseFederation(w, r, "PEER_HANDSHAKE_FAILED", "federation_peer", hello.RegistryDID,
			federation.ErrPeerNotActive)
		return
	}

	pub, err := peer.PublicJWK.Public()
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL",
			"The key recorded for this peer could not be read.")
		return
	}
	if err := hello.Verify(pub); err != nil {
		_ = s.db.MarkPeer(r.Context(), hello.UAIASN, "ERROR", federation.Reason(err), now)
		s.refuseFederation(w, r, "PEER_HANDSHAKE_FAILED", "federation_peer", hello.RegistryDID, err)
		return
	}
	if s.db.Nonces().Seen(hello.RegistryDID, hello.Nonce, now.Add(federation.MaxClockSkew)) {
		s.refuseFederation(w, r, "PEER_HANDSHAKE_FAILED", "federation_peer", hello.RegistryDID,
			errors.New("federation: this hello has already been seen"))
		return
	}

	if err := s.db.MarkPeer(r.Context(), hello.UAIASN, "ACTIVE", "", now); err != nil {
		WriteStoreError(w, r, err)
		return
	}
	s.auditFederation(r, "PEER_HANDSHAKE_SUCCEEDED", "federation_peer", hello.RegistryDID,
		"SUCCESS", map[string]any{"remote_uai_asn": hello.UAIASN})

	reply, err := s.registryHello(now)
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL",
			"This registry could not sign its own hello.")
		return
	}
	WriteJSON(w, http.StatusOK, reply)
}

// registryHello builds and signs this registry's own introduction.
func (s *Server) registryHello(now time.Time) (federation.Hello, error) {
	nonce, err := randomHex()
	if err != nil {
		return federation.Hello{}, err
	}
	reg := s.federation.Registry
	return federation.Sign(s.federation.Signer, federation.Hello{
		UAIASN: reg.ASN, RegistryDID: reg.DID, RegistryName: reg.Name,
		Endpoint: reg.Endpoint, PublicJWK: reg.PublicJWK,
		Timestamp: uaicrypto.NewTimestamp(now), Nonce: nonce,
	})
}

// ── POST /v1/federation/announcements ───────────────────────────────────────

func (s *Server) federationAnnouncement(w http.ResponseWriter, r *http.Request) {
	if s.federationOff(w, r) {
		return
	}
	ann, err := federation.Decode[federation.Announcement](Body(r))
	if err != nil {
		s.rejectAnnouncement(w, r, "unknown", err)
		return
	}
	now := s.now()
	if err := ann.Validate(now); err != nil {
		s.rejectAnnouncement(w, r, ann.AgentDID, err)
		return
	}

	peer, err := s.db.PeerByASN(r.Context(), ann.OriginUAIASN)
	if errors.Is(err, store.ErrNotFound) {
		s.rejectAnnouncement(w, r, ann.AgentDID, federation.ErrUnknownPeer)
		return
	}
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	if peer.Status != "ACTIVE" {
		s.rejectAnnouncement(w, r, ann.AgentDID, federation.ErrPeerNotActive)
		return
	}

	pub, err := peer.PublicJWK.Public()
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "UAI_INTERNAL",
			"The key recorded for this peer could not be read.")
		return
	}
	if err := ann.Verify(pub); err != nil {
		s.rejectAnnouncement(w, r, ann.AgentDID, err)
		return
	}

	// Sequence. Read before write, and the store's conditional update settles a
	// race this check cannot see.
	last := int64(0)
	if known, err := s.db.FederatedIdentityByDID(r.Context(), ann.OriginUAIASN, ann.AgentDID); err == nil {
		last = known.LastSequence
	} else if !errors.Is(err, store.ErrNotFound) {
		WriteStoreError(w, r, err)
		return
	}
	if err := federation.CheckSequence(last, ann.Sequence); err != nil {
		s.rejectAnnouncement(w, r, ann.AgentDID, err)
		return
	}

	if err := s.db.RecordFederatedIdentity(r.Context(), store.FederatedIdentity{
		OriginASN: ann.OriginUAIASN, AgentDID: ann.AgentDID,
		RemoteStatus: ann.AgentStatus, CredentialHash: ann.CredentialHash,
		LastSequence: ann.Sequence, SignatureStatus: "VERIFIED",
	}); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.rejectAnnouncement(w, r, ann.AgentDID, federation.ErrStaleSequence)
			return
		}
		WriteStoreError(w, r, err)
		return
	}
	_ = s.db.MarkPeer(r.Context(), ann.OriginUAIASN, "ACTIVE", "", now)
	s.auditFederation(r, "FEDERATION_ANNOUNCEMENT_ACCEPTED", "federated_identity", ann.AgentDID,
		"SUCCESS", map[string]any{
			"origin_uai_asn": ann.OriginUAIASN, "sequence": ann.Sequence,
			"remote_status": ann.AgentStatus,
		})
	WriteJSON(w, http.StatusAccepted, map[string]any{
		"result":    "ACCEPTED",
		"agent_did": ann.AgentDID,
		"sequence":  ann.Sequence,
		"note": "Recorded as another registry's claim about its own identity. It is not an " +
			"agent of this registry and confers no authority here.",
	})
}

func (s *Server) rejectAnnouncement(w http.ResponseWriter, r *http.Request, did string, cause error) {
	reason := federation.Reason(cause)
	s.auditFederation(r, "FEDERATION_ANNOUNCEMENT_REJECTED", "federated_identity", did,
		"REFUSED", map[string]any{"reason": reason, "detail": cause.Error()})
	status := http.StatusBadRequest
	switch reason {
	case "INVALID_SIGNATURE":
		status = http.StatusUnauthorized
	case "UNKNOWN_PEER", "PEER_NOT_ACTIVE", "WRONG_AUTHORITY":
		status = http.StatusForbidden
	case "STALE_SEQUENCE":
		status = http.StatusConflict
	}
	WriteProblem(w, r, status, "UAI_FEDERATION_REJECTED", cause.Error(),
		WithRemediation("Rejected with reason "+reason+"."))
}

func (s *Server) refuseFederation(w http.ResponseWriter, r *http.Request,
	operation, kind, object string, cause error) {
	reason := federation.Reason(cause)
	s.auditFederation(r, operation, kind, object, "REFUSED",
		map[string]any{"reason": reason, "detail": cause.Error()})
	status := http.StatusBadRequest
	switch reason {
	case "INVALID_SIGNATURE":
		status = http.StatusUnauthorized
	case "UNKNOWN_PEER", "PEER_NOT_ACTIVE":
		status = http.StatusForbidden
	}
	WriteProblem(w, r, status, "UAI_FEDERATION_REJECTED", cause.Error(),
		WithRemediation("Rejected with reason "+reason+"."))
}

// ── GET /v1/federation/identities ───────────────────────────────────────────

// FederatedIdentityView is deliberately shaped so it cannot be mistaken for an
// agent: it carries an origin, a remote status, and no local fields at all.
type FederatedIdentityView struct {
	AgentDID        string         `json:"agent_did"`
	OriginUAIASN    federation.ASN `json:"origin_uai_asn"`
	RemoteStatus    string         `json:"remote_status"`
	CredentialHash  string         `json:"credential_hash"`
	LastSequence    int64          `json:"last_sequence"`
	SignatureStatus string         `json:"signature_status"`
	LastSeenAt      time.Time      `json:"last_seen_at"`
}

func (s *Server) federationIdentities(w http.ResponseWriter, r *http.Request) {
	if s.federationOff(w, r) {
		return
	}
	rows, err := s.db.FederatedIdentities(r.Context())
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	out := make([]FederatedIdentityView, 0, len(rows))
	for _, f := range rows {
		out = append(out, FederatedIdentityView{
			AgentDID: f.AgentDID, OriginUAIASN: f.OriginASN, RemoteStatus: f.RemoteStatus,
			CredentialHash: f.CredentialHash, LastSequence: f.LastSequence,
			SignatureStatus: f.SignatureStatus, LastSeenAt: f.LastSeenAt,
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"identities": out,
		"note": "Claims made by other registries about identities they issued. None of " +
			"these is an agent of this registry.",
	})
}

// ── audit ───────────────────────────────────────────────────────────────────

// auditFederation records a federated operation in the registry's audit log.
//
// A failure to record is logged and does not fail the request that succeeded,
// with one exception the callers own: a refusal is recorded before the refusal
// is written, so a rejected announcement leaves a trace even if the response
// never reaches the sender.
func (s *Server) auditFederation(r *http.Request, operation, kind, object, outcome string,
	detail map[string]any) {
	if s.federation == nil {
		return
	}
	err := s.db.RecordAudit(r.Context(), s.federation.Signer, store.AuditEvent{
		ActorDID: s.federation.Registry.DID, ActorType: "REGISTRY",
		Operation: operation, ObjectKind: kind, ObjectID: object,
		Source: "federation", Outcome: outcome, Detail: detail,
		OccurredAt: s.now(),
	})
	if err != nil {
		logAuditFailure(operation, object, err)
	}
}

// randomHex is 128 bits of freshness for a hello this registry sends.
func randomHex() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// logAuditFailure records that the registry could not record something.
//
// Logged loudly rather than returned: the operation it describes already
// happened, and failing the response would tell the caller their request was
// refused when it was not. What must never happen is silence.
func logAuditFailure(operation, object string, err error) {
	slog.Error("audit event could not be recorded",
		"operation", operation, "object", object, "err", err)
}
