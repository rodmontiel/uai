// Package policy verifies GASC policy bundles.
//
// It contains no policy evaluator and takes no external dependencies, and both
// are deliberate. Evaluating Rego is one thing; deciding whether a body of
// rules is the one the governance process actually approved is another, and the
// second is what a relying party has to be able to check for itself.
//
// Concretely: an auditor handed a decision record must be able to fetch the
// bundle by hash, confirm that it carries the required approvals and that it
// chains to the version it replaced, and do all of that without running OPA and
// without trusting the service that made the decision. That check lives here.
package policy

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// Errors returned by bundle verification.
var (
	ErrManifestInvalid   = errors.New("policy: bundle manifest is invalid")
	ErrHashMismatch      = errors.New("policy: bundle content does not match the manifest hash")
	ErrThresholdNotMet   = errors.New("policy: approval signatures do not meet the threshold")
	ErrUnknownSigner     = errors.New("policy: approval by a signer outside the authority set")
	ErrChainBroken       = errors.New("policy: previous_policy_hash does not match the version being replaced")
	ErrNotEffective      = errors.New("policy: bundle is not in effect at that time")
	ErrDuplicateApproval = errors.New("policy: one signer approved twice")
)

// Approval is one M-of-N signature over the bundle hash.
type Approval struct {
	Signer string              `json:"signer"`
	Alg    uaicrypto.Algorithm `json:"alg"`
	Value  string              `json:"value"`
}

// Manifest describes a bundle (§12.1.1).
type Manifest struct {
	PolicyID           string     `json:"policy_id"`
	PolicyVersion      string     `json:"policy_version"`
	EffectiveDate      time.Time  `json:"effective_date"`
	SunsetDate         *time.Time `json:"sunset_date,omitempty"`
	Jurisdictions      []string   `json:"jurisdictions"`
	RiskClasses        []string   `json:"risk_classes"`
	PreviousPolicyHash string     `json:"previous_policy_hash,omitempty"`
	BundleHash         string     `json:"bundle_hash"`
	Approvals          []Approval `json:"approval_signatures"`
	Threshold          string     `json:"threshold"`
}

// Version is the "GASC-2027.4" form used in decision records.
func (m Manifest) Version() string { return m.PolicyID + "-" + m.PolicyVersion }

// ParseThreshold reads the "M-of-N" form.
func (m Manifest) ParseThreshold() (need, of int, err error) {
	parts := strings.Split(m.Threshold, "-of-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("%w: threshold %q is not M-of-N", ErrManifestInvalid, m.Threshold)
	}
	if need, err = strconv.Atoi(parts[0]); err != nil {
		return 0, 0, fmt.Errorf("%w: threshold %q: %v", ErrManifestInvalid, m.Threshold, err)
	}
	if of, err = strconv.Atoi(parts[1]); err != nil {
		return 0, 0, fmt.Errorf("%w: threshold %q: %v", ErrManifestInvalid, m.Threshold, err)
	}
	if need < 1 || of < need {
		return 0, 0, fmt.Errorf("%w: threshold %q is not satisfiable", ErrManifestInvalid, m.Threshold)
	}
	return need, of, nil
}

// Validate checks the manifest's own consistency.
func (m Manifest) Validate() error {
	switch {
	case m.PolicyID == "":
		return fmt.Errorf("%w: policy_id", ErrManifestInvalid)
	case m.PolicyVersion == "":
		return fmt.Errorf("%w: policy_version", ErrManifestInvalid)
	case m.EffectiveDate.IsZero():
		return fmt.Errorf("%w: effective_date", ErrManifestInvalid)
	case m.BundleHash == "":
		return fmt.Errorf("%w: bundle_hash", ErrManifestInvalid)
	case len(m.Jurisdictions) == 0:
		// An empty list is not "everywhere": "*" says everywhere, and the
		// difference decides whether an omission fails open or closed.
		return fmt.Errorf("%w: jurisdictions must be explicit, use [\"*\"] for all", ErrManifestInvalid)
	}
	if m.SunsetDate != nil && !m.SunsetDate.After(m.EffectiveDate) {
		return fmt.Errorf("%w: sunset_date is not after effective_date", ErrManifestInvalid)
	}
	if _, err := uaicrypto.ParseDigest(m.BundleHash); err != nil {
		return fmt.Errorf("%w: bundle_hash: %v", ErrManifestInvalid, err)
	}
	if m.PreviousPolicyHash != "" {
		if _, err := uaicrypto.ParseDigest(m.PreviousPolicyHash); err != nil {
			return fmt.Errorf("%w: previous_policy_hash: %v", ErrManifestInvalid, err)
		}
	}
	_, _, err := m.ParseThreshold()
	return err
}

// EffectiveAt reports whether the bundle is in force at t.
func (m Manifest) EffectiveAt(t time.Time) error {
	if t.Before(m.EffectiveDate) {
		return fmt.Errorf("%w: effective from %s", ErrNotEffective,
			m.EffectiveDate.UTC().Format(time.RFC3339))
	}
	if m.SunsetDate != nil && !t.Before(*m.SunsetDate) {
		return fmt.Errorf("%w: sunset %s", ErrNotEffective, m.SunsetDate.UTC().Format(time.RFC3339))
	}
	return nil
}

// Files maps a bundle path to that file's contents.
type Files map[string][]byte

// HashContent computes a bundle's hash from its files.
//
// The hash is over a canonical map of path to content digest, not over a tar
// stream. Archive formats carry ordering, timestamps and permissions that
// differ between the machine that built the bundle and the machine that checks
// it, and any of those differences would produce a different hash for identical
// policy. What is being committed to is the CONTENT at each PATH, so that is
// exactly what is hashed.
//
// manifest.json is excluded because it carries the hash, and .signatures/
// because they are made over it.
func HashContent(files Files) (string, error) {
	digests := make(map[string]string, len(files))
	paths := make([]string, 0, len(files))
	for path := range files {
		if path == "manifest.json" || strings.HasPrefix(path, ".signatures/") {
			continue
		}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		sum, err := uaicrypto.Digest(uaicrypto.DomainPolicyBundle, files[path])
		if err != nil {
			return "", err
		}
		digests[path] = uaicrypto.FormatDigest(sum)
	}
	if len(digests) == 0 {
		return "", fmt.Errorf("%w: a bundle with no policy files decides nothing", ErrManifestInvalid)
	}
	sum, err := uaicrypto.DigestObject(uaicrypto.DomainPolicyBundle, digests)
	if err != nil {
		return "", err
	}
	return uaicrypto.FormatDigest(sum), nil
}

// Authority is the set of keys allowed to approve bundles, by verification
// method.
type Authority map[string]crypto.PublicKey

// Verify checks that files are the bundle the manifest describes, and that the
// governance process actually approved them.
//
// The order matters. Content is checked before signatures because a signature
// over the right hash says nothing about files that do not produce that hash,
// and reporting "signature valid" for a tampered bundle would be worse than
// useless.
func Verify(m Manifest, files Files, authority Authority) error {
	if err := m.Validate(); err != nil {
		return err
	}
	computed, err := HashContent(files)
	if err != nil {
		return err
	}
	if computed != m.BundleHash {
		return fmt.Errorf("%w: files hash to %s, manifest says %s", ErrHashMismatch, computed, m.BundleHash)
	}

	need, _, err := m.ParseThreshold()
	if err != nil {
		return err
	}
	digest, err := uaicrypto.ParseDigest(m.BundleHash)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(m.Approvals))
	valid := 0
	for _, a := range m.Approvals {
		if seen[a.Signer] {
			// Counting one signer twice would turn a 3-of-5 into a 1-of-5 for
			// anyone holding one key.
			return fmt.Errorf("%w: %s", ErrDuplicateApproval, a.Signer)
		}
		seen[a.Signer] = true
		pub, known := authority[a.Signer]
		if !known {
			// Refused rather than ignored. An unknown approver is either a
			// misconfiguration or an attempt to pad the count, and silently
			// skipping it would hide both.
			return fmt.Errorf("%w: %s", ErrUnknownSigner, a.Signer)
		}
		sig := uaicrypto.Signature{
			Alg: a.Alg, KID: a.Signer, Domain: uaicrypto.DomainPolicyBundle, Value: a.Value,
		}
		if err := uaicrypto.Verify(pub, uaicrypto.DomainPolicyBundle, digest, sig); err != nil {
			return fmt.Errorf("%w: %s: %v", ErrThresholdNotMet, a.Signer, err)
		}
		valid++
	}
	if valid < need {
		return fmt.Errorf("%w: %d valid of %s", ErrThresholdNotMet, valid, m.Threshold)
	}
	return nil
}

// VerifySuccession checks that a bundle replaces the one it claims to.
//
// Policy history is as tamper-evident as action history (§12.1.1): without this
// link a bundle could be swapped for an older, more permissive one and nothing
// in the manifest would say so.
func VerifySuccession(next, previous Manifest) error {
	if next.PreviousPolicyHash == "" {
		return fmt.Errorf("%w: %s declares no predecessor", ErrChainBroken, next.Version())
	}
	if next.PreviousPolicyHash != previous.BundleHash {
		return fmt.Errorf("%w: %s points at %s, %s hashes to %s",
			ErrChainBroken, next.Version(), next.PreviousPolicyHash,
			previous.Version(), previous.BundleHash)
	}
	if !next.EffectiveDate.After(previous.EffectiveDate) {
		return fmt.Errorf("%w: %s is not effective after %s", ErrChainBroken,
			next.Version(), previous.Version())
	}
	return nil
}

// ParseManifest decodes a manifest document.
func ParseManifest(raw []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrManifestInvalid, err)
	}
	return m, nil
}

// SignBundle produces one approval over a bundle hash.
func SignBundle(s uaicrypto.Signer, bundleHash string) (Approval, error) {
	digest, err := uaicrypto.ParseDigest(bundleHash)
	if err != nil {
		return Approval{}, err
	}
	sig, err := s.Sign(uaicrypto.DomainPolicyBundle, digest)
	if err != nil {
		return Approval{}, err
	}
	return Approval{Signer: s.KID(), Alg: sig.Alg, Value: sig.Value}, nil
}
