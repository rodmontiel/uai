package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rodmontiel/uai/internal/api"
	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/federation"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// A federation fixture: this registry, one configured peer, and the peer's key.
//
// The two registries are distinct key pairs on purpose. Every test below is
// about one of them saying something the other has to judge, and a shared key
// would make all of them pass for the wrong reason.
type fed struct {
	*env
	localASN   federation.ASN
	localKey   uaicrypto.Signer
	peerASN    federation.ASN
	peerSigner uaicrypto.Signer
	peerDID    string
}

// Seeded at random, like the ULID counter above, because these tests share one
// database with every other run. A fixed starting number meant the second `go
// test` collided with the peers the first one left behind -- and the failure
// read as a bug in the peering code rather than in the fixture.
var asnSeq atomic.Int64

func init() {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	asnSeq.Store(int64(binary.BigEndian.Uint32(b[:])%1_000_000_000) + 1_000_000)
}

func nextASN() federation.ASN { return federation.ASN(asnSeq.Add(2)) }

func setupFederation(t *testing.T) *fed {
	t.Helper()
	e := setup(t)
	ctx := context.Background()

	local, peer := nextASN(), nextASN()
	localSigner, localPub, err := uaicrypto.GenerateEd25519Signer(
		federation.RegistryDID(local) + "#key-1")
	if err != nil {
		t.Fatal(err)
	}
	localJWK, err := uaicrypto.JWKFromPublic(localPub)
	if err != nil {
		t.Fatal(err)
	}
	localJWK.Kid = federation.RegistryDID(local) + "#key-1"

	// One registry identity per database. Other tests in this package share the
	// database, so the row may already be there from a previous ASN; the tests
	// below never depend on which, because everything they check is signed.
	reg := store.Registry{
		ASN: local, DID: federation.RegistryDID(local), Name: "Test Registry",
		PublicJWK: localJWK, Endpoint: "https://local.test/federation",
		ProtocolVersion: federation.ProtocolVersion, Status: "ACTIVE",
	}
	if err := e.db.SetLocalRegistry(ctx, reg); err != nil {
		// Already claimed by an earlier test in this run: adopt it and sign as
		// that one instead, so the fixture stays truthful.
		existing, rErr := e.db.LocalRegistry(ctx)
		if rErr != nil {
			t.Fatal(err)
		}
		local = existing.ASN
		localSigner, localPub, err = uaicrypto.GenerateEd25519Signer(existing.DID + "#key-1")
		if err != nil {
			t.Fatal(err)
		}
		localJWK, err = uaicrypto.JWKFromPublic(localPub)
		if err != nil {
			t.Fatal(err)
		}
		localJWK.Kid = existing.DID + "#key-1"
		existing.PublicJWK = localJWK
		if err := e.db.SetLocalRegistry(ctx, existing); err != nil {
			t.Fatal(err)
		}
		reg = existing
	}
	stored, err := e.db.LocalRegistry(ctx)
	if err != nil {
		t.Fatal(err)
	}

	peerSigner, peerPub, err := uaicrypto.GenerateEd25519Signer(
		federation.RegistryDID(peer) + "#key-1")
	if err != nil {
		t.Fatal(err)
	}
	peerJWK, err := uaicrypto.JWKFromPublic(peerPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.db.CreatePeer(ctx, store.Peer{
		ID: "peer-" + ulid("P"), LocalASN: stored.ASN, RemoteASN: peer,
		RemoteDID: federation.RegistryDID(peer), Endpoint: "https://peer.test/federation",
		PublicJWK: peerJWK,
	}); err != nil {
		t.Fatal(err)
	}

	srv := api.NewServer(e.db, api.WithScheme("http"),
		api.WithIssuer("did:web:pdp.uai.test", localSigner), api.WithBundle(e.bundle),
		api.WithFederation(&api.Federation{Registry: stored, Signer: localSigner}))
	return &fed{env: &env{db: e.db, srv: srv.Routes(), agent: e.agent, signer: e.signer,
		ownerID: e.ownerID, bundle: e.bundle},
		localASN: stored.ASN, localKey: localSigner,
		peerASN: peer, peerSigner: peerSigner, peerDID: federation.RegistryDID(peer)}
}

func (f *fed) post(t *testing.T, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://api.uai.test"+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)
	return rec
}

func (f *fed) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://api.uai.test"+path, nil)
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)
	return rec
}

func (f *fed) peerHello(t *testing.T, at time.Time) federation.Hello {
	t.Helper()
	pubJWK, err := uaicrypto.JWKFromPublic(f.peerSigner.Public())
	if err != nil {
		t.Fatal(err)
	}
	h, err := federation.Sign(f.peerSigner, federation.Hello{
		UAIASN: f.peerASN, RegistryDID: f.peerDID, RegistryName: "Partner Registry",
		Endpoint: "https://peer.test/federation", PublicJWK: pubJWK,
		Timestamp: uaicrypto.NewTimestamp(at), Nonce: nonce(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (f *fed) announcement(t *testing.T, seq int64, mutate func(*federation.Announcement)) federation.Announcement {
	t.Helper()
	a := federation.Announcement{
		OriginUAIASN: f.peerASN,
		AgentDID:     federation.AgentDID(f.peerASN, "01JY8RA3C7K2V9M0QW4T6Z8XPD"),
		AgentStatus:  "ACTIVE", Timestamp: uaicrypto.NewTimestamp(time.Now()),
		Sequence: seq, CredentialHash: "sha256:" + fmt.Sprintf("%064d", 1),
	}
	signed, err := federation.SignAnnouncement(f.peerSigner, a)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		// Mutating AFTER signing is the whole point of these cases: the bytes
		// the peer signed and the bytes we receive differ.
		mutate(&signed)
	}
	return signed
}

func problemCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var p struct {
		Title string `json:"title"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("response is not a problem document: %s", rec.Body.String())
	}
	return p.Title
}

// ── the registry ────────────────────────────────────────────────────────────

func TestFederationRegistryCanBeRetrieved(t *testing.T) {
	f := setupFederation(t)
	rec := f.get(t, "/v1/federation/registry")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var view api.RegistryView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.UAIASN != f.localASN {
		t.Errorf("uai_asn = %d, want %d", view.UAIASN, f.localASN)
	}
	if view.RegistryDID != federation.RegistryDID(f.localASN) {
		t.Errorf("registry_did = %q", view.RegistryDID)
	}
	if view.ProtocolVersion != federation.ProtocolVersion {
		t.Errorf("protocol_version = %q", view.ProtocolVersion)
	}
	// The published key is a uaicrypto.JWK, a type with no member that can hold
	// a private key at all. That is stronger than a test: there is no field to
	// forget to clear. Asserting the public half is present is what is left.
	if view.PublicJWK.X == "" || view.PublicJWK.Kty == "" {
		t.Fatalf("the registry published no usable key: %+v", view.PublicJWK)
	}
}

// TestFederationOffIsAnHonestFourOhFour: a registry with no ASN has not
// silently joined anything.
func TestFederationOffIsAnHonestFourOhFour(t *testing.T) {
	e := setup(t)
	srv := api.NewServer(e.db, api.WithScheme("http"),
		api.WithIssuer("did:web:pdp.uai.test", e.signer)).Routes()
	req := httptest.NewRequest(http.MethodGet, "http://api.uai.test/v1/federation/registry", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404: %s", rec.Code, rec.Body)
	}
	if got := problemCode(t, rec); got != "UAI_FEDERATION_NOT_CONFIGURED" {
		t.Errorf("title = %q", got)
	}
}

// ── peering ─────────────────────────────────────────────────────────────────

func TestValidPeerHandshakeSucceeds(t *testing.T) {
	f := setupFederation(t)
	rec := f.post(t, "/v1/federation/handshake", f.peerHello(t, time.Now()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var reply federation.Hello
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Type != federation.TypeHello || reply.UAIASN != f.localASN {
		t.Fatalf("the answer did not introduce this registry: %+v", reply)
	}
	if reply.Signature.Value == "" {
		t.Fatal("this registry answered a handshake without signing")
	}
	peer, err := f.db.PeerByASN(context.Background(), f.peerASN)
	if err != nil {
		t.Fatal(err)
	}
	if peer.Status != "ACTIVE" {
		t.Fatalf("peering is %s after a good handshake, want ACTIVE", peer.Status)
	}
}

func TestHandshakeFromUnknownRegistryFails(t *testing.T) {
	f := setupFederation(t)
	stranger := nextASN()
	signer, pub, err := uaicrypto.GenerateEd25519Signer(federation.RegistryDID(stranger) + "#key-1")
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := uaicrypto.JWKFromPublic(pub)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := federation.Sign(signer, federation.Hello{
		UAIASN: stranger, RegistryDID: federation.RegistryDID(stranger),
		RegistryName: "Nobody", Endpoint: "https://nobody.test", PublicJWK: jwk,
		Timestamp: uaicrypto.NewTimestamp(time.Now()), Nonce: nonce(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// The signature is perfectly good. Being able to sign is not being known.
	rec := f.post(t, "/v1/federation/handshake", hello)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", rec.Code, rec.Body)
	}
}

func TestHandshakeWithInvalidSignatureFails(t *testing.T) {
	f := setupFederation(t)
	hello := f.peerHello(t, time.Now())
	hello.RegistryName = "Renamed After Signing"
	rec := f.post(t, "/v1/federation/handshake", hello)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401: %s", rec.Code, rec.Body)
	}
	peer, err := f.db.PeerByASN(context.Background(), f.peerASN)
	if err != nil {
		t.Fatal(err)
	}
	if peer.Status == "ACTIVE" {
		t.Fatal("a handshake with a broken signature made the peering ACTIVE")
	}
}

func TestHandshakeWithExpiredTimestampFails(t *testing.T) {
	f := setupFederation(t)
	old := time.Now().Add(-federation.MaxClockSkew - time.Minute)
	rec := f.post(t, "/v1/federation/handshake", f.peerHello(t, old))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body)
	}
}

// TestHandshakeCannotBeReplayed: the same hello twice is a captured message.
func TestHandshakeCannotBeReplayed(t *testing.T) {
	f := setupFederation(t)
	hello := f.peerHello(t, time.Now())
	if rec := f.post(t, "/v1/federation/handshake", hello); rec.Code != http.StatusOK {
		t.Fatalf("the first handshake should succeed: %d %s", rec.Code, rec.Body)
	}
	if rec := f.post(t, "/v1/federation/handshake", hello); rec.Code == http.StatusOK {
		t.Fatal("the same hello was accepted twice")
	}
}

// ── announcements ───────────────────────────────────────────────────────────

func (f *fed) activate(t *testing.T) {
	t.Helper()
	if rec := f.post(t, "/v1/federation/handshake", f.peerHello(t, time.Now())); rec.Code != http.StatusOK {
		t.Fatalf("handshake: %d %s", rec.Code, rec.Body)
	}
}

func TestValidAnnouncementIsAccepted(t *testing.T) {
	f := setupFederation(t)
	f.activate(t)
	ann := f.announcement(t, 1042, nil)
	rec := f.post(t, "/v1/federation/announcements", ann)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}

	// Stored, and stored as what it is.
	got, err := f.db.FederatedIdentityByDID(context.Background(), f.peerASN, ann.AgentDID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastSequence != 1042 || got.RemoteStatus != "ACTIVE" ||
		got.SignatureStatus != "VERIFIED" || got.OriginASN != f.peerASN {
		t.Fatalf("stored wrong: %+v", got)
	}

	// FED-002: it is not an agent of this registry, and asking for it as one
	// has to fail. A federated identity that answered /v1/agents would be a
	// local identity in everything but the table it sits in.
	rec = f.get(t, "/v1/agents/uai:agent:01JY8RA3C7K2V9M0QW4T6Z8XPD")
	if rec.Code == http.StatusOK {
		t.Fatal("a federated identity was served as a local agent (FED-002)")
	}
}

func TestAnnouncementWithInvalidSignatureIsRejected(t *testing.T) {
	f := setupFederation(t)
	f.activate(t)
	ann := f.announcement(t, 1, func(a *federation.Announcement) { a.AgentStatus = "REVOKED" })
	rec := f.post(t, "/v1/federation/announcements", ann)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401: %s", rec.Code, rec.Body)
	}
	if _, err := f.db.FederatedIdentityByDID(context.Background(), f.peerASN, ann.AgentDID); err == nil {
		t.Fatal("an announcement with a broken signature was stored (FED-001)")
	}
}

func TestAnnouncementFromUnknownPeerIsRejected(t *testing.T) {
	f := setupFederation(t)
	f.activate(t)
	stranger := nextASN()
	signer, _, err := uaicrypto.GenerateEd25519Signer(federation.RegistryDID(stranger) + "#key-1")
	if err != nil {
		t.Fatal(err)
	}
	ann, err := federation.SignAnnouncement(signer, federation.Announcement{
		OriginUAIASN: stranger,
		AgentDID:     federation.AgentDID(stranger, "01JY8RA3C7K2V9M0QW4T6Z8XPD"),
		AgentStatus:  "ACTIVE", Timestamp: uaicrypto.NewTimestamp(time.Now()),
		Sequence: 1, CredentialHash: "sha256:" + fmt.Sprintf("%064d", 2),
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := f.post(t, "/v1/federation/announcements", ann)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", rec.Code, rec.Body)
	}
}

func TestAnnouncementFromAPendingPeerIsRejected(t *testing.T) {
	f := setupFederation(t) // no handshake: the peering is PENDING
	rec := f.post(t, "/v1/federation/announcements", f.announcement(t, 1, nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", rec.Code, rec.Body)
	}
}

func TestOldSequenceIsRejected(t *testing.T) {
	f := setupFederation(t)
	f.activate(t)
	if rec := f.post(t, "/v1/federation/announcements", f.announcement(t, 100, nil)); rec.Code != http.StatusAccepted {
		t.Fatalf("the first announcement should be accepted: %d %s", rec.Code, rec.Body)
	}
	for _, seq := range []int64{100, 99, 1} {
		rec := f.post(t, "/v1/federation/announcements", f.announcement(t, seq, nil))
		if rec.Code != http.StatusConflict {
			t.Fatalf("sequence %d: status %d, want 409: %s", seq, rec.Code, rec.Body)
		}
	}
	// And the stored row still says what the newest accepted one said.
	got, err := f.db.FederatedIdentityByDID(context.Background(), f.peerASN,
		federation.AgentDID(f.peerASN, "01JY8RA3C7K2V9M0QW4T6Z8XPD"))
	if err != nil {
		t.Fatal(err)
	}
	if got.LastSequence != 100 {
		t.Fatalf("last_sequence = %d after replays, want 100", got.LastSequence)
	}
}

func TestModifiedAgentDIDIsRejected(t *testing.T) {
	f := setupFederation(t)
	f.activate(t)
	ann := f.announcement(t, 1, func(a *federation.Announcement) {
		a.AgentDID = federation.AgentDID(f.peerASN, "01JY8RA3C7K2V9M0QW4T6Z8XPE")
	})
	rec := f.post(t, "/v1/federation/announcements", ann)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401: %s", rec.Code, rec.Body)
	}
}

// TestPeerCannotAnnounceAnotherRegistrysAgent: a valid key is not authority.
func TestPeerCannotAnnounceAnotherRegistrysAgent(t *testing.T) {
	f := setupFederation(t)
	f.activate(t)
	victim := nextASN()
	ann, err := federation.SignAnnouncement(f.peerSigner, federation.Announcement{
		OriginUAIASN: f.peerASN,
		AgentDID:     federation.AgentDID(victim, "01JY8RA3C7K2V9M0QW4T6Z8XPD"),
		AgentStatus:  "REVOKED", Timestamp: uaicrypto.NewTimestamp(time.Now()),
		Sequence: 1, CredentialHash: "sha256:" + fmt.Sprintf("%064d", 3),
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := f.post(t, "/v1/federation/announcements", ann)
	if rec.Code == http.StatusAccepted {
		t.Fatal("a peer revoked an identity belonging to a registry it does not speak for")
	}
}

// ── FED-003 ─────────────────────────────────────────────────────────────────

// TestPeeringDoesNotConferAgentTrust. An accepted announcement records another
// registry's claim; it does not create a local identity, a credential, or any
// capability. This is the invariant the whole model rests on.
func TestPeeringDoesNotConferAgentTrust(t *testing.T) {
	f := setupFederation(t)
	f.activate(t)
	ann := f.announcement(t, 7, nil)
	if rec := f.post(t, "/v1/federation/announcements", ann); rec.Code != http.StatusAccepted {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	ctx := context.Background()

	var agents int
	if err := f.db.Pool().QueryRow(ctx,
		`SELECT count(*) FROM agents WHERE did = $1`, ann.AgentDID).Scan(&agents); err != nil {
		t.Fatal(err)
	}
	if agents != 0 {
		t.Fatal("a federated announcement created a local agent (FED-002)")
	}
	var creds, grants int
	if err := f.db.Pool().QueryRow(ctx,
		`SELECT (SELECT count(*) FROM credentials),
		        (SELECT count(*) FROM capability_grants
		          WHERE granted_by_did = $1)`, f.peerDID).Scan(&creds, &grants); err != nil {
		t.Fatal(err)
	}
	if grants != 0 {
		t.Fatal("a peer granted a capability by announcing (FED-003)")
	}
}

// ── audit ───────────────────────────────────────────────────────────────────

func TestFederationOperationsAreAudited(t *testing.T) {
	f := setupFederation(t)
	f.activate(t)
	ann := f.announcement(t, 5, nil)
	if rec := f.post(t, "/v1/federation/announcements", ann); rec.Code != http.StatusAccepted {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// And one that is refused, because a log of successes is an advertisement.
	f.post(t, "/v1/federation/announcements", f.announcement(t, 1, nil))

	ctx := context.Background()
	events, err := f.db.AuditEventsFor(ctx, "federated_identity", ann.AgentDID, 10)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range events {
		seen[e.Operation] = true
	}
	for _, want := range []string{"FEDERATION_ANNOUNCEMENT_ACCEPTED", "FEDERATION_ANNOUNCEMENT_REJECTED"} {
		if !seen[want] {
			t.Errorf("%s was not recorded; got %v", want, seen)
		}
	}
	peerEvents, err := f.db.AuditEventsFor(ctx, "federation_peer", f.peerDID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(peerEvents) == 0 {
		t.Error("the handshake was not audited")
	}
}

func TestMain(m *testing.M) { os.Exit(m.Run()) }
