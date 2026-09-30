package api

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/rodmontiel/uai/pkg/assurance"
	"github.com/rodmontiel/uai/pkg/spiffe"
)

// attestedRuntime is what a bind establishes about where an agent runs.
type attestedRuntime struct {
	SpiffeID    string
	CertHash    string
	ImageDigest string
	Attestor    string
	ExpiresAt   time.Time
	Level       assurance.RuntimeAttestation
}

// refusal is a problem response that has not been written yet, so that the
// function deciding it does not also have to own the response writer.
type refusal struct {
	status      int
	code        string
	detail      string
	remediation string
}

func (f *refusal) write(w http.ResponseWriter, r *http.Request) {
	WriteProblem(w, r, f.status, f.code, f.detail, WithRemediation(f.remediation))
}

// selfDeclared is the binding UAI recorded before phase 12, and still records
// when no trust bundle is configured.
//
// `Attestor: "self-declared"` was already in the code and already accurate: the
// agent signed a statement about where it was running and nothing checked it.
// What changes here is that the string becomes an assurance INPUT, so an honest
// comment turns into an honest answer at /verify.
func selfDeclared(req BindRequest, now time.Time) *attestedRuntime {
	return &attestedRuntime{
		SpiffeID: req.SpiffeID, CertHash: req.SVIDCertHash, ImageDigest: req.ImageDigest,
		Attestor: "self-declared", ExpiresAt: now.Add(SVIDTTL),
		Level: assurance.NoRuntime,
	}
}

// runtimeFor establishes the runtime a bind may record.
//
// When a trust bundle is configured the SVID is REQUIRED, and everything about
// the runtime is read off the certificate — never off the request. The body's
// svid_spiffe_id and svid_cert_hash still have to agree with it, because those
// are the values inside the signed statement that gets stored and re-verified
// years later: a statement saying something the certificate does not is a
// record nobody could ever check.
func (s *Server) runtimeFor(r *http.Request, uaiID string, req BindRequest,
	now time.Time) (*attestedRuntime, *refusal) {

	if s.spiffe == nil {
		return selfDeclared(req, now), nil
	}
	chain := peerChain(r)
	if len(chain) == 0 {
		return nil, &refusal{http.StatusUnauthorized, "UAI_RUNTIME_ATTESTATION_REQUIRED",
			"This registry verifies runtimes, so a bind must present an X509-SVID as a client certificate.",
			"Fetch an SVID from the SPIRE agent's Workload API and connect with mTLS. " +
				"An svid_spiffe_id in the body is the agent describing itself."}
	}
	svid, err := spiffe.Verify(chain, s.spiffe, now)
	if err != nil {
		return nil, svidRefusal(err)
	}
	// §9.1 step 6. Without it, any workload holding a valid SVID in this trust
	// domain could bind itself to any identity in the registry.
	if err := svid.Attests(uaiID); err != nil {
		return nil, svidRefusal(err)
	}
	if req.SpiffeID != "" && req.SpiffeID != svid.ID.String() {
		return nil, &refusal{http.StatusBadRequest, "UAI_RUNTIME_MISMATCH",
			fmt.Sprintf("The signed statement names %s and the certificate proves %s.",
				req.SpiffeID, svid.ID),
			"The statement is what gets stored and re-verified later; it has to say what is true."}
	}
	if req.SVIDCertHash != "" && req.SVIDCertHash != svid.CertHash {
		return nil, &refusal{http.StatusBadRequest, "UAI_RUNTIME_MISMATCH",
			"The signed statement names a different certificate than the one presented.",
			"svid_cert_hash must be the SHA-256 of the presented leaf certificate."}
	}

	return &attestedRuntime{
		SpiffeID: svid.ID.String(), CertHash: svid.CertHash,
		// Recorded because it is worth something as a claim, and NOT counted
		// toward assurance, because §6.8's AL2 runtime column asks for an image
		// digest the ATTESTOR observed, not one the agent typed.
		ImageDigest: req.ImageDigest,
		Attestor:    "spiffe://" + s.spiffe.TrustDomain,
		// The certificate's own NotAfter, not a constant. A binding claiming an
		// hour when the SVID expires in five minutes would report a runtime as
		// current after the attestor stopped vouching for it.
		ExpiresAt: svid.ExpiresAt,
		Level:     assurance.SVIDOnly,
	}, nil
}

// peerChain returns the client certificate chain, leaf first, or nil.
func peerChain(r *http.Request) []*x509.Certificate {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates
}

// svidRefusal maps a verification failure to a response.
//
// The cases are separated on purpose. "Not trusted", "wrong trust domain" and
// "wrong subject" look alike in a log and mean completely different things: a
// forgery, a federation gap, and an attempt to bind somebody else's identity.
// Only the third is an attack on this registry.
func svidRefusal(err error) *refusal {
	switch {
	case errors.Is(err, spiffe.ErrWrongSubject):
		return &refusal{http.StatusForbidden, "UAI_RUNTIME_IDENTITY_MISMATCH", err.Error(),
			"The SVID is genuine. It attests a different agent than the one being bound."}
	case errors.Is(err, spiffe.ErrWrongTrustDomain):
		return &refusal{http.StatusForbidden, "UAI_RUNTIME_FOREIGN_TRUST_DOMAIN", err.Error(),
			"This registry is not federated with that trust domain."}
	case errors.Is(err, spiffe.ErrInvalidSVID), errors.Is(err, spiffe.ErrInvalidID):
		return &refusal{http.StatusBadRequest, "UAI_RUNTIME_SVID_INVALID", err.Error(),
			"The certificate presented is not a well-formed X509-SVID."}
	default:
		return &refusal{http.StatusForbidden, "UAI_RUNTIME_NOT_ATTESTED", err.Error(),
			"No trusted attestor vouches for this certificate."}
	}
}

// assuranceFor derives an identity's assurance level from what the registry
// actually holds (§6.8), rather than reading the column written at registration.
//
// The column was written once, as "UAI-AL0", and nothing ever wrote it again.
// Every identity was AL0 for life and the AL2 rules in the policy bundle could
// not fire, which made the field look like a setting somebody forgot rather than
// a fact about evidence.
//
// Returns AL0 on any error. An assurance level that fails open would be a claim
// about an identity we could not check, which is the one thing /verify must
// never produce.
//
// It takes a context rather than a request because every surface that reports
// an assurance level must reach the same answer -- the identity card, the
// passport, the credentials, the policy input -- and some of them run without
// a request in hand. A second way to obtain this number is a second answer.
func (s *Server) assuranceFor(ctx context.Context, agentID string, now time.Time) assurance.Result {
	in, err := s.db.AssuranceEvidence(ctx, agentID, now)
	if err != nil {
		return assurance.Result{Level: assurance.AL0, LimitedBy: "evidence",
			Detail: "the registry could not read this identity's assurance evidence"}
	}
	return assurance.FromEvidence(in.KeyProtections, in.OwnerVerification, in.Attestor, in.ImageDigest)
}

// runtimeAttestationOf reports what the runtime dimension reached, for the
// policy input. Taken off the derived result so the PDP and /verify can never
// disagree about the same identity.
func runtimeAttestationOf(res assurance.Result) assurance.RuntimeAttestation {
	switch res.Reached[assurance.DimRuntime] {
	case assurance.AL3:
		return assurance.RemoteAttestation
	case assurance.AL2:
		return assurance.SVIDWithImage
	case assurance.AL1:
		return assurance.SVIDOnly
	default:
		return assurance.NoRuntime
	}
}
