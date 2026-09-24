package main

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rodmontiel/uai/pkg/keys"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// didDocument is the subset of a DID Document this tool reads.
type didDocument struct {
	ID                 string `json:"id"`
	VerificationMethod []struct {
		ID           string          `json:"id"`
		PublicKeyJWK json.RawMessage `json:"publicKeyJwk"`
		ValidFrom    string          `json:"uai:validFrom"`
		ValidUntil   string          `json:"uai:validUntil"`
		RevokedAt    string          `json:"uai:revokedAt"`
		Compromised  string          `json:"uai:compromiseDeclaredAt"`
		Protection   string          `json:"uai:protection"`
	} `json:"verificationMethod"`
}

// keyset resolves a key id as it was valid at a moment.
type keyset struct {
	history  *keys.History
	resolver func(kid string, at time.Time) (crypto.PublicKey, error)
	count    int
}

func (k keyset) at(kid string, when time.Time) (crypto.PublicKey, error) {
	if k.resolver == nil {
		return nil, fmt.Errorf("no verification methods to resolve %s against", kid)
	}
	pub, err := k.resolver(kid, when)
	if err != nil {
		return nil, fmt.Errorf("%s was not usable at %s: %w",
			kid, when.UTC().Format(time.RFC3339), err)
	}
	return pub, nil
}

// keys builds a validity-aware key set from the document.
//
// The validity windows are the reason this tool reads a DID Document at all
// rather than just taking a public key: a signature made before a key was
// revoked stays verifiable and one made after does not, and a verifier that
// only knows "here is the key" cannot tell those apart.
func (d didDocument) keys() (keyset, error) {
	history := keys.NewHistory(d.ID)
	count := 0
	for _, m := range d.VerificationMethod {
		pub, err := uaicrypto.PublicFromJWKBytes(m.PublicKeyJWK)
		if err != nil {
			// Skipped rather than fatal: one unreadable method must not make
			// every other key in the document unusable.
			continue
		}
		k := keys.Key{KID: m.ID, Public: pub, Protection: keys.Protection(m.Protection)}
		k.ValidFrom = parseTime(m.ValidFrom)
		k.ValidUntil = parseTime(m.ValidUntil)
		k.RevokedAt = parseTime(m.RevokedAt)
		k.CompromiseDeclaredAt = parseTime(m.Compromised)
		if err := history.Add(k); err != nil {
			continue
		}
		count++
	}
	if count == 0 {
		return keyset{}, nil
	}
	return keyset{history: history, resolver: history.Resolver(), count: count}, nil
}

func (k keyset) String() string { return fmt.Sprintf("%d keys", k.count) }

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
