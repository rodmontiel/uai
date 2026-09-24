// Command uai-policy builds, signs and verifies GASC policy bundles.
//
// The bundle in this repository is committed WITH its manifest and signatures,
// and the private approval keys are not committed. That is not an oversight: it
// means editing a .rego or a data file makes the bundle fail verification until
// somebody holding the governance keys signs it again. Policy cannot be changed
// by whoever can write to the repository, which is the whole point of §12.1.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rodmontiel/uai/internal/keyfile"
	"github.com/rodmontiel/uai/internal/pdp"
	"github.com/rodmontiel/uai/pkg/policy"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keys":
		err = genKeys(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  uai-policy keys   -out .keys -n 5 -authority policy/authority.json
  uai-policy sign   -bundle policy/gasc-2027.4 -keys .keys/gasc-1.jwk,... -threshold 3-of-5
  uai-policy verify -bundle policy/gasc-2027.4 -authority policy/authority.json`)
	os.Exit(2)
}

// genKeys creates a development approval set and publishes the public half.
func genKeys(args []string) error {
	fs := flag.NewFlagSet("keys", flag.ExitOnError)
	out := fs.String("out", ".keys", "directory for the private keys")
	n := fs.Int("n", 5, "size of the approval set")
	authorityPath := fs.String("authority", "policy/authority.json", "where to write the public set")
	prefix := fs.String("did", "did:web:council.uai.world", "DID of the policy authority")
	_ = fs.Parse(args)

	set := map[string]uaicrypto.JWK{}
	for i := 1; i <= *n; i++ {
		kid := fmt.Sprintf("%s#gasc-%d", *prefix, i)
		path := filepath.Join(*out, fmt.Sprintf("gasc-%d.jwk", i))
		if err := keyfile.Generate(path, kid); err != nil {
			return err
		}
		jwk, err := keyfile.PublicJWK(path)
		if err != nil {
			return err
		}
		set[kid] = jwk
		fmt.Printf("wrote %s  (%s)\n", path, kid)
	}
	body, err := json.MarshalIndent(map[string]any{
		"_comment": "Public keys of the GASC approval set. In production this set is read from " +
			"UAIPolicyRegistry on-chain; here it is a file so the committed bundle can be " +
			"verified by anyone who clones the repository.",
		"keys": set,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(*authorityPath, append(body, '\n'), 0o644)
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	dir := fs.String("bundle", "", "bundle directory")
	keys := fs.String("keys", "", "comma-separated private key files")
	threshold := fs.String("threshold", "3-of-5", "M-of-N")
	policyID := fs.String("id", "GASC", "policy id")
	version := fs.String("version", "", "policy version (default: from the directory name)")
	effective := fs.String("effective", "",
		"effective date (default: keep the one in the existing manifest)")
	previous := fs.String("previous", "", "previous_policy_hash")
	_ = fs.Parse(args)
	if *dir == "" || *keys == "" {
		return fmt.Errorf("uai-policy sign: -bundle and -keys are required")
	}
	v := *version
	if v == "" {
		v = strings.TrimPrefix(filepath.Base(*dir), strings.ToLower(*policyID)+"-")
	}

	// The effective date is CARRIED FORWARD, not defaulted.
	//
	// It used to default to a fixed future date, so re-signing a bundle after
	// editing one rule silently moved when the whole thing took effect -- and a
	// gateway that fails closed then refuses to start, which is correct
	// behaviour reporting a change nobody made. Re-signing answers "who
	// approves these rules"; it must not also answer "when do they apply".
	effectiveAt, err := effectiveDate(*dir, *effective)
	if err != nil {
		return err
	}

	files, err := readBundle(*dir)
	if err != nil {
		return err
	}
	hash, err := policy.HashContent(files)
	if err != nil {
		return err
	}

	m := policy.Manifest{
		PolicyID: *policyID, PolicyVersion: v, EffectiveDate: effectiveAt,
		Jurisdictions:      []string{"*"},
		RiskClasses:        []string{"INFORMATIONAL", "LOW", "MODERATE", "HIGH", "CRITICAL"},
		PreviousPolicyHash: *previous, BundleHash: hash, Threshold: *threshold,
	}
	for _, path := range strings.Split(*keys, ",") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		jwk, err := keyfile.PublicJWK(path)
		if err != nil {
			return err
		}
		signer, err := keyfile.Load(path, jwk.Kid)
		if err != nil {
			return err
		}
		approval, err := policy.SignBundle(signer, hash)
		if err != nil {
			return err
		}
		m.Approvals = append(m.Approvals, approval)
	}
	sort.Slice(m.Approvals, func(i, j int) bool { return m.Approvals[i].Signer < m.Approvals[j].Signer })

	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*dir, "manifest.json"), append(body, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("signed %s\n  version %s\n  hash    %s\n  %d of %s approvals\n",
		*dir, m.Version(), hash, len(m.Approvals), *threshold)
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	dir := fs.String("bundle", "", "bundle directory")
	authorityPath := fs.String("authority", "policy/authority.json", "public approval set")
	at := fs.String("at", "", "evaluate effectiveness at this time (default: the effective date)")
	_ = fs.Parse(args)
	if *dir == "" {
		return fmt.Errorf("uai-policy verify: -bundle is required")
	}
	authority, err := pdp.LoadAuthorityFile(*authorityPath)
	if err != nil {
		return err
	}
	when := time.Now()
	if *at != "" {
		if when, err = time.Parse(time.RFC3339, *at); err != nil {
			return err
		}
	}
	raw, err := os.ReadFile(filepath.Join(*dir, "manifest.json"))
	if err != nil {
		return fmt.Errorf("uai-policy: %w", err)
	}
	m, err := policy.ParseManifest(raw)
	if err != nil {
		return err
	}
	if when.Before(m.EffectiveDate) {
		// Verifying a bundle that is not yet in force is normal: it is what
		// staging a release means. Effectiveness is checked at load time by the
		// PDP, not here.
		when = m.EffectiveDate
	}
	bundle, err := pdp.Load(context.Background(), os.DirFS(*dir), authority, when)
	if err != nil {
		return err
	}
	fmt.Printf("%s verifies\n  hash       %s\n  threshold  %s (%d approvals)\n  effective  %s\n  compiles   yes\n",
		bundle.Version(), bundle.Hash(), m.Threshold, len(m.Approvals),
		m.EffectiveDate.UTC().Format(time.RFC3339))
	return nil
}

func readBundle(dir string) (policy.Files, error) {
	files := policy.Files{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = content
		return nil
	})
	return files, err
}

// effectiveDate resolves the effective date for a signing run.
//
// An explicit -effective always wins. Otherwise the existing manifest's date is
// kept. A bundle with no manifest and no flag is refused rather than given a
// date: staging a policy for a future quarter is a deliberate governance act,
// and picking one on the operator's behalf would make it an accident.
func effectiveDate(dir, explicit string) (time.Time, error) {
	if explicit != "" {
		return time.Parse(time.RFC3339, explicit)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return time.Time{}, fmt.Errorf(
			"uai-policy sign: no manifest to take the effective date from; pass -effective: %w", err)
	}
	var existing policy.Manifest
	if err := json.Unmarshal(raw, &existing); err != nil {
		return time.Time{}, err
	}
	if existing.EffectiveDate.IsZero() {
		return time.Time{}, fmt.Errorf(
			"uai-policy sign: the existing manifest has no effective date; pass -effective")
	}
	return existing.EffectiveDate, nil
}
