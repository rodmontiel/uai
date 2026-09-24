package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// didDocument serves an agent's DID Document (§6.3).
//
// It is what makes an attestation checkable by someone who has never talked to
// us before: the signature names a key id, and this is where that id resolves
// to key material. Every key the agent has ever used appears, with the window
// it was valid in — because verifying a historical signature against today's
// key set is the most common way a verifier silently invalidates history on
// every rotation.
func (s *Server) didDocument(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUAIID(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	agent, err := s.db.AgentByUAIID(r.Context(), id.String())
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	rows, err := s.db.AgentKeys(r.Context(), agent.ID)
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	methods := make([]map[string]any, 0, len(rows))
	assertion := make([]string, 0, len(rows))
	for _, k := range rows {
		var jwk map[string]any
		if err := json.Unmarshal(k.PublicJWK, &jwk); err != nil {
			continue
		}
		kid := agent.DID + "#" + k.KeyID
		method := map[string]any{
			"id": kid, "type": "JsonWebKey2020", "controller": agent.DID,
			"publicKeyJwk": jwk,
			// Not part of the W3C core terms, and included anyway: a verifier
			// checking a two-year-old attestation needs to know which key was
			// valid then, and a document that only says "these are the keys"
			// cannot answer that.
			"uai:validFrom":  k.ValidFrom.UTC().Format(time.RFC3339),
			"uai:protection": k.Protection,
		}
		if k.ValidUntil != nil {
			method["uai:validUntil"] = k.ValidUntil.UTC().Format(time.RFC3339)
		}
		if k.RevokedAt != nil {
			method["uai:revokedAt"] = k.RevokedAt.UTC().Format(time.RFC3339)
		}
		if k.Compromised != nil {
			// A compromise is reported separately from a revocation because the
			// two mean different things to a verifier: a revoked key stops
			// signing new things, a compromised one retroactively taints what
			// it already signed.
			method["uai:compromiseDeclaredAt"] = k.Compromised.UTC().Format(time.RFC3339)
		}
		methods = append(methods, method)
		assertion = append(assertion, kid)
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	WriteJSON(w, http.StatusOK, map[string]any{
		"@context":           []string{"https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		"id":                 agent.DID,
		"verificationMethod": methods,
		"assertionMethod":    assertion,
		"authentication":     assertion,
		"uai:status":         agent.Status,
		"uai:registeredAt":   agent.RegisteredAt.UTC().Format(time.RFC3339),
	})
}

// latestCheckpoint serves the newest signed checkpoint with its witness
// co-signatures.
//
// Public and unauthenticated: a checkpoint everyone can fetch is what makes a
// split view detectable. If we served different checkpoints to different
// callers, the only way anyone would find out is by comparing what they were
// each given — which requires them to be able to fetch it at all.
func (s *Server) latestCheckpoint(w http.ResponseWriter, r *http.Request) {
	if s.translog == nil {
		WriteProblem(w, r, http.StatusServiceUnavailable, "UAI_LOG_UNAVAILABLE",
			"This deployment runs without a transparency log.")
		return
	}
	cp, err := s.translog.Checkpoint(r.Context(), s.now().UTC())
	if err != nil {
		WriteStoreError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, cp)
}

// trustAnchors publishes the key set a verifier needs (§5.1, anchor 2).
//
// Public keys only, and that is the whole point: an auditor should need nothing
// from us beyond these, and everything else we serve should be checkable
// against them. A verifier that had to trust the API to tell it whether a
// receipt was genuine would be trusting the party the receipt is evidence
// about.
func (s *Server) trustAnchors(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"note": "These are the roots a verifier needs. Everything else this API serves — " +
			"the registry, the credentials, this response — is checkable against them, and " +
			"none of it has to be trusted.",
	}
	if s.issuer != nil {
		out["credential_issuer"] = map[string]any{
			"did": s.issuerDID, "kid": s.issuer.KID(),
			"public_jwk": jwkOf(s.issuer.Public()),
		}
	}
	if s.bundle != nil {
		out["policy"] = map[string]any{
			"version": s.bundle.Version(), "bundle_hash": s.bundle.Hash(),
			"revocation_threshold": s.bundle.Threshold(),
			"min_countries":        s.bundle.MinCountries(),
		}
	}
	if s.translog != nil {
		anchors := s.translog.TrustAnchors()
		logKeys := map[string]any{}
		for kid, key := range anchors.LogKeys {
			logKeys[kid] = jwkOf(key)
		}
		witnesses := map[string]any{}
		for name, key := range anchors.WitnessKeys {
			witnesses[name] = jwkOf(key)
		}
		out["transparency_log"] = map[string]any{
			"origin": s.translog.Origin(), "size": s.translog.Size(),
			"log_keys": logKeys, "witness_keys": witnesses,
			"min_witnesses": anchors.MinWitnesses,
			"note": "Local witnesses provide the MECHANISM, not the independence. Split-view " +
				"detection rests on witnesses being run by parties who would not collude with " +
				"the log, and processes on one host are not that.",
		}
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	WriteJSON(w, http.StatusOK, out)
}

// jwkOf renders a public key as a JWK, or nil when it cannot be rendered.
func jwkOf(key any) any {
	jwk, err := uaicrypto.JWKFromPublic(key)
	if err != nil {
		return nil
	}
	return jwk
}
