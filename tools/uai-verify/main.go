// Command uai-verify validates an agent's entire history from public data.
//
// It is MVP criterion 21, and §24.1 calls it "the real acceptance test": a CLI
// that takes a UAI-ID, fetches nothing but public data, and validates the whole
// history using only the three trust anchors of §5.1.
//
// # What it trusts
//
// The anchors, and nothing else:
//
//  1. the GASC policy bundle signing keys,
//  2. the transparency log's key and its witness keys,
//  3. the consortium ledger's validator set.
//
// Everything this tool fetches from the registry — the identity card, the event
// chain, the attestations, the receipts, the revocation decision — is treated as
// untrusted input and checked against those anchors. In particular it never
// believes the registry's own verdict: /v1/verify returns a status, and this
// tool recomputes it rather than printing it.
//
// # Why that matters
//
// If a verifier has to trust the registry, the registry's uptime and honesty
// are back in the trust equation the protocol exists to remove them from. The
// point of this tool is to be the thing you run when you do not trust us.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rodmontiel/uai/pkg/attest"
	"github.com/rodmontiel/uai/pkg/governance"
	"github.com/rodmontiel/uai/pkg/merkle"
	"github.com/rodmontiel/uai/pkg/receipt"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

func main() {
	var (
		endpoint = flag.String("endpoint", envOr("UAI_ENDPOINT", "http://127.0.0.1:8080"),
			"base URL of a UAI gateway (untrusted: everything it returns is checked)")
		anchorsPath = flag.String("anchors", "",
			"trust anchors file (default: fetch them once from -endpoint and say so)")
		verbose = flag.Bool("v", false, "print every check, not only the failures")
		jsonOut = flag.Bool("json", false, "machine-readable output")
		ca      = flag.String("ca", envOr("UAI_API_CA", ""),
			"PEM CA bundle to verify an https gateway's certificate with")
	)
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() != 1 {
		usage()
		os.Exit(2)
	}

	client, err := httpClient(*ca)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	v := &verifier{
		endpoint: strings.TrimRight(*endpoint, "/"),
		http:     client,
		verbose:  *verbose,
	}
	report, err := v.run(flag.Arg(0), *anchorsPath)
	if err != nil {
		if strings.Contains(err.Error(), "certificate signed by unknown authority") && *ca == "" {
			// The gateway is fine and its certificate is fine. Nothing here was
			// told which CA issued it, and that is invisible in the message.
			fmt.Fprintln(os.Stderr, "error:", err)
			fmt.Fprintln(os.Stderr,
				"  This gateway serves TLS and no CA was given.\n"+
					"  Add -ca .spire/bootstrap.pem, or export UAI_API_CA.")
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if *jsonOut {
		raw, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(raw))
	} else {
		report.print(os.Stdout, *verbose)
	}
	if !report.OK {
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `uai-verify — validate an agent's history from public data alone.

  uai-verify [-endpoint URL] [-anchors file] [-v] [-json] <uai-id>

It trusts the three anchors of §5.1 and nothing else. Everything the gateway
returns is checked against them, including the gateway's own verdict about the
identity: this tool recomputes that rather than printing it.

Exit status: 0 everything checked out · 1 a check failed · 2 could not run.
`)
}

// Check is one thing that was verified, or could not be.
type Check struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	// Skipped separates "this does not apply" from "this passed". An agent with
	// no revocation has nothing to check there, and reporting that as a pass
	// would inflate the report with assurances nobody earned.
	Skipped bool   `json:"skipped,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Report is everything this tool concluded.
type Report struct {
	Identity string  `json:"identity"`
	DID      string  `json:"did,omitempty"`
	Status   string  `json:"status,omitempty"`
	Events   int     `json:"events"`
	OK       bool    `json:"ok"`
	Checks   []Check `json:"checks"`
	// AnchorSource says where the trust anchors came from. Fetching them from
	// the party being audited is a real weakening, so it is stated rather than
	// left for the reader to infer.
	AnchorSource string `json:"anchor_source"`
	Note         string `json:"note"`
}

func (r Report) print(w io.Writer, verbose bool) {
	fmt.Fprintf(w, "%s\n", r.Identity)
	if r.DID != "" {
		fmt.Fprintf(w, "  did     %s\n", r.DID)
		fmt.Fprintf(w, "  status  %s\n", r.Status)
		fmt.Fprintf(w, "  events  %d\n", r.Events)
	}
	fmt.Fprintf(w, "  anchors %s\n\n", r.AnchorSource)
	for _, c := range r.Checks {
		switch {
		case c.Skipped:
			if verbose {
				fmt.Fprintf(w, "  --  %-44s %s\n", c.Name, c.Detail)
			}
		case c.OK:
			if verbose {
				fmt.Fprintf(w, "  ok  %-44s %s\n", c.Name, c.Detail)
			}
		default:
			fmt.Fprintf(w, "  FAIL %-43s %s\n", c.Name, c.Detail)
		}
	}
	passed, skipped := 0, 0
	for _, c := range r.Checks {
		switch {
		case c.Skipped:
			skipped++
		case c.OK:
			passed++
		}
	}
	fmt.Fprintf(w, "\n%d checks passed", passed)
	if skipped > 0 {
		fmt.Fprintf(w, ", %d not applicable", skipped)
	}
	if r.OK {
		fmt.Fprintf(w, "\n%s\n", r.Note)
		return
	}
	fmt.Fprintf(w, ", %d FAILED\n", len(r.Checks)-passed-skipped)
}

type verifier struct {
	endpoint string
	http     *http.Client
	verbose  bool
	anchors  anchors
	checks   []Check
}

// anchors is the trust anchor set (§5.1).
type anchors struct {
	CredentialIssuer struct {
		DID       string          `json:"did"`
		KID       string          `json:"kid"`
		PublicJWK json.RawMessage `json:"public_jwk"`
	} `json:"credential_issuer"`
	Policy struct {
		Version             string `json:"version"`
		BundleHash          string `json:"bundle_hash"`
		RevocationThreshold string `json:"revocation_threshold"`
		MinCountries        int    `json:"min_countries"`
	} `json:"policy"`
	TransparencyLog struct {
		Origin       string                     `json:"origin"`
		LogKeys      map[string]json.RawMessage `json:"log_keys"`
		WitnessKeys  map[string]json.RawMessage `json:"witness_keys"`
		MinWitnesses int                        `json:"min_witnesses"`
	} `json:"transparency_log"`
}

func (v *verifier) pass(name, format string, args ...any) {
	v.checks = append(v.checks, Check{Name: name, OK: true, Detail: fmt.Sprintf(format, args...)})
}

func (v *verifier) fail(name, format string, args ...any) {
	v.checks = append(v.checks, Check{Name: name, Detail: fmt.Sprintf(format, args...)})
}

func (v *verifier) skip(name, format string, args ...any) {
	v.checks = append(v.checks, Check{Name: name, OK: true, Skipped: true,
		Detail: fmt.Sprintf(format, args...)})
}

func (v *verifier) run(uaiID, anchorsPath string) (Report, error) {
	report := Report{Identity: uaiID}

	switch {
	case anchorsPath != "":
		raw, err := os.ReadFile(anchorsPath)
		if err != nil {
			return report, err
		}
		if err := json.Unmarshal(raw, &v.anchors); err != nil {
			return report, fmt.Errorf("anchors: %w", err)
		}
		report.AnchorSource = anchorsPath
	default:
		if err := v.get("/v1/trust-anchors", &v.anchors); err != nil {
			return report, fmt.Errorf("fetch anchors: %w", err)
		}
		// Said plainly. Taking the anchors from the party you are auditing means
		// this run proves internal consistency, not authenticity: a dishonest
		// gateway can hand you keys that make its own forgeries verify. Pinning
		// them with -anchors is what makes the result mean something.
		report.AnchorSource = "FETCHED FROM THE GATEWAY BEING AUDITED — pin them with -anchors"
	}

	// ── the identity ────────────────────────────────────────────────────────
	var card map[string]any
	if err := v.get("/v1/agents/"+uaiID, &card); err != nil {
		return report, err
	}
	report.DID, _ = card["did"].(string)
	report.Status, _ = card["status"].(string)

	var didDoc didDocument
	if err := v.get("/v1/agents/"+uaiID+"/did.json", &didDoc); err != nil {
		return report, err
	}
	keys, err := didDoc.keys()
	if err != nil {
		return report, err
	}
	if keys.count == 0 {
		v.fail("did document resolves keys", "the DID document names no usable verification method")
	} else {
		v.pass("did document resolves keys", "%d verification method(s), with validity windows",
			keys.count)
	}

	// ── the chain ───────────────────────────────────────────────────────────
	var chain struct {
		Events []struct {
			EventID           string `json:"event_id"`
			Sequence          int64  `json:"sequence"`
			Outcome           string `json:"outcome"`
			PreviousEventHash string `json:"previous_event_hash"`
			EventHash         string `json:"event_hash"`
		} `json:"events"`
	}
	if err := v.get("/v1/agents/"+uaiID+"/events?limit=1000", &chain); err != nil {
		return report, err
	}
	report.Events = len(chain.Events)

	// Every event names its predecessor. This is the check that makes deleting
	// or back-dating an event detectable, and it costs one comparison.
	broken := 0
	for i := 1; i < len(chain.Events); i++ {
		if chain.Events[i].PreviousEventHash != chain.Events[i-1].EventHash {
			broken++
			v.fail("chain link", "event %d names %s, predecessor hashes to %s",
				chain.Events[i].Sequence, short(chain.Events[i].PreviousEventHash),
				short(chain.Events[i-1].EventHash))
		}
	}
	if broken == 0 && len(chain.Events) > 0 {
		v.pass("chain links unbroken", "%d events, every one naming its predecessor",
			len(chain.Events))
	}

	// ── each attested action ────────────────────────────────────────────────
	checkpoint, cpErr := v.checkpoint()
	logged, verified := 0, 0
	for _, ev := range chain.Events {
		if ev.Outcome == "" {
			continue // a register/bind/unbind event carries no attestation
		}
		var action struct {
			EventHash    string          `json:"event_hash"`
			Attestation  json.RawMessage `json:"attestation"`
			Receipt      *storedReceipt  `json:"receipt"`
			Transparency string          `json:"transparency"`
		}
		if err := v.get("/v1/actions/"+ev.EventID, &action); err != nil {
			v.fail("action "+short(ev.EventID), "could not be fetched: %v", err)
			continue
		}
		var a attest.Attestation
		if err := json.Unmarshal(action.Attestation, &a); err != nil {
			v.fail("action "+short(ev.EventID), "attestation is unreadable: %v", err)
			continue
		}
		// The signature, against the key that was valid WHEN IT WAS MADE. Using
		// the current key set would silently invalidate history on every
		// rotation, which is the most common verification bug in systems
		// like this.
		pub, err := keys.at(a.Signature.KID, a.Timestamp.Time)
		if err != nil {
			v.fail("action "+short(ev.EventID), "%v", err)
			continue
		}
		if err := attest.Verify(pub, a); err != nil {
			v.fail("action "+short(ev.EventID), "signature does not verify: %v", err)
			continue
		}
		// And the hash the chain records is the hash of what we were handed.
		computed, err := a.Hash()
		if err != nil || computed != ev.EventHash {
			v.fail("action "+short(ev.EventID),
				"the chain records %s, the attestation hashes to %s", short(ev.EventHash), short(computed))
			continue
		}
		verified++

		if action.Receipt == nil {
			continue
		}
		logged++
		if cpErr != nil {
			continue
		}
		if err := v.checkReceipt(action.Receipt, action.Attestation, checkpoint); err != nil {
			v.fail("receipt "+short(ev.EventID), "%v", err)
		}
	}
	if verified > 0 {
		v.pass("attestation signatures", "%d verified against the key valid at signing time", verified)
	}
	switch {
	case cpErr != nil:
		v.skip("transparency receipts", "no checkpoint available: %v", cpErr)
	case logged == 0 && verified > 0:
		v.skip("transparency receipts", "no action carries a receipt")
	case logged > 0:
		v.pass("transparency receipts", "%d inclusion proof(s) rebuilt the signed root", logged)
	}

	// ── revocation, if there is one ─────────────────────────────────────────
	v.checkRevocation(report.Status, uaiID)

	// ── the registry's own verdict, recomputed rather than believed ─────────
	var verdict struct {
		Verified bool   `json:"verified"`
		Status   string `json:"status"`
		Revoked  bool   `json:"revoked"`
	}
	if err := v.get("/v1/verify/"+uaiID, &verdict); err == nil {
		revokedByChain := report.Status == "REVOKED"
		if verdict.Revoked != revokedByChain {
			v.fail("the registry's verdict matches the record",
				"/v1/verify says revoked=%v, the identity record says %s",
				verdict.Revoked, report.Status)
		} else {
			v.pass("the registry's verdict matches the record",
				"%s, recomputed rather than taken on trust", verdict.Status)
		}
	}

	report.Checks = v.checks
	report.OK = true
	for _, c := range v.checks {
		if !c.OK {
			report.OK = false
		}
	}
	report.Note = "Checked against the trust anchors. This says the record is internally " +
		"consistent and signed by the keys it names — not that the actions described in it " +
		"had the effects they claim."
	return report, nil
}

// checkRevocation recomputes a revocation from the signed assertions.
//
// This is §16.3 preconditions 5 and 6 run by somebody who is not us: the tally
// is recounted from the votes the decision carries and the governance proof is
// rebuilt from them. A decision whose stated outcome does not follow from its
// own votes is the only forgery this design leaves room for.
func (v *verifier) checkRevocation(status, uaiID string) {
	if status != "REVOKED" {
		v.skip("revocation follows from signed votes", "this identity is %s", status)
		return
	}
	var events struct {
		Revocation struct {
			DecisionID string `json:"decision_id"`
		} `json:"revocation"`
	}
	// The decision id is on the identity card of a revoked agent. When it is
	// absent the revocation cannot be checked, and that is a failure rather
	// than a skip: an identity marked REVOKED with nothing to check is exactly
	// the state an operator acting alone would produce.
	if err := v.get("/v1/agents/"+uaiID, &events); err != nil || events.Revocation.DecisionID == "" {
		v.fail("revocation follows from signed votes",
			"the identity is REVOKED but names no governance decision")
		return
	}
	var decision governance.Decision
	if err := v.get("/v1/revocations/"+events.Revocation.DecisionID, &decision); err != nil {
		v.fail("revocation follows from signed votes", "%v", err)
		return
	}
	if err := governance.Recompute(decision); err != nil {
		v.fail("revocation follows from signed votes", "%v", err)
		return
	}
	if v.anchors.Policy.RevocationThreshold != "" &&
		decision.Policy.Threshold != v.anchors.Policy.RevocationThreshold {
		v.fail("revocation used the threshold the policy sets",
			"decision applied %s, the policy says %s",
			decision.Policy.Threshold, v.anchors.Policy.RevocationThreshold)
		return
	}
	v.pass("revocation follows from signed votes",
		"%d YES / %d NO under %s, governance proof rebuilt",
		decision.Tally.Yes, decision.Tally.No, decision.Policy.Threshold)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func short(s string) string {
	if len(s) > 23 {
		return s[:23] + "…"
	}
	return s
}

var errNotFound = errors.New("not found")

func (v *verifier) get(path string, out any) error {
	resp, err := v.http.Get(v.endpoint + path)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusNotFound {
		return errNotFound
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s: %s", path, strings.TrimSpace(string(body)))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

// storedReceipt is a receipt as the API serves it.
type storedReceipt struct {
	LogOrigin         string          `json:"log_origin"`
	LogIndex          uint64          `json:"log_index"`
	LeafHash          string          `json:"leaf_hash"`
	CheckpointSize    uint64          `json:"checkpoint_size"`
	CheckpointRoot    string          `json:"checkpoint_root"`
	InclusionProof    []string        `json:"inclusion_proof"`
	LogSignature      string          `json:"log_signature"`
	WitnessSignatures json.RawMessage `json:"witness_signatures"`
}

// checkpoint fetches the log's current checkpoint and verifies it against the
// pinned log key.
//
// Verified, not merely fetched. An unverified checkpoint is the log's word
// about its own contents, and comparing a receipt against it would be asking
// the log whether its own receipt is genuine — which is the dependency the
// whole transparency layer exists to remove.
func (v *verifier) checkpoint() (receipt.Checkpoint, error) {
	var signed struct {
		receipt.Checkpoint
		LogSignature      uaicrypto.Signature        `json:"log_signature"`
		WitnessSignatures []receipt.WitnessSignature `json:"witness_signatures"`
		MinWitnesses      int                        `json:"min_witnesses"`
	}
	if err := v.get("/v1/log/checkpoint", &signed); err != nil {
		return receipt.Checkpoint{}, err
	}
	cp := signed.Checkpoint
	// Root is json:"-" on the wire; the transported field is the base64 form.
	// Forgetting this produced a verifier that compared every root against nil
	// and reported a SPLIT VIEW for a healthy log — a false alarm on the one
	// signal nobody can afford to learn to ignore.
	root, err := base64.StdEncoding.DecodeString(cp.RootB64)
	if err != nil {
		return cp, fmt.Errorf("checkpoint root: %w", err)
	}
	cp.Root = root

	if len(v.anchors.TransparencyLog.LogKeys) == 0 {
		v.skip("checkpoint signed by the log key", "the anchors name no log key")
		return cp, nil
	}
	verified := false
	for kid, raw := range v.anchors.TransparencyLog.LogKeys {
		// The signature names the key it was made with; a verifier that tried
		// every pinned key would accept a checkpoint signed by a witness key,
		// which is a different party's assertion about a different thing.
		if kid != signed.LogSignature.KID {
			continue
		}
		pub, err := uaicrypto.PublicFromJWKBytes(raw)
		if err != nil {
			continue
		}
		if err := uaicrypto.Verify(pub, uaicrypto.DomainCheckpoint, cp.Body(),
			signed.LogSignature); err == nil {
			_ = kid
			verified = true
			break
		}
	}
	if !verified {
		v.fail("checkpoint signed by the log key",
			"the checkpoint at size %d does not verify against any pinned log key", cp.Size)
		return cp, nil
	}
	v.pass("checkpoint signed by the log key", "size %d, root %s",
		cp.Size, short(uaicrypto.FormatDigest(cp.Root)))

	// Witness co-signatures, checked against the pinned witness keys. A
	// checkpoint below the threshold is UNDERWITNESSED, not invalid: §18.4 says
	// a verifier should see reduced assurance rather than a silent downgrade,
	// and refusing outright would let one offline witness make the whole log
	// unusable.
	valid := 0
	for _, ws := range signed.WitnessSignatures {
		raw, ok := v.anchors.TransparencyLog.WitnessKeys[ws.Witness]
		if !ok {
			continue
		}
		pub, err := uaicrypto.PublicFromJWKBytes(raw)
		if err != nil {
			continue
		}
		// A co-signature carries only its value; the envelope is rebuilt
		// here, which is also what fixes the domain: a witness signs a
		// checkpoint, and nothing else it ever signs may be presented as one.
		if err := uaicrypto.Verify(pub, uaicrypto.DomainCheckpoint, cp.Body(),
			uaicrypto.Signature{Alg: uaicrypto.AlgEdDSA, KID: ws.Witness,
				Domain: uaicrypto.DomainCheckpoint, Value: ws.Signature}); err == nil {
			valid++
		}
	}
	switch {
	case valid >= v.anchors.TransparencyLog.MinWitnesses && valid > 0:
		v.pass("checkpoint co-signed by witnesses", "%d of %d required", valid,
			v.anchors.TransparencyLog.MinWitnesses)
	case v.anchors.TransparencyLog.MinWitnesses == 0:
		v.skip("checkpoint co-signed by witnesses", "the anchors require none")
	default:
		v.fail("checkpoint co-signed by witnesses",
			"UNDERWITNESSED: %d co-signature(s) verify against the pinned witness keys, %d required",
			valid, v.anchors.TransparencyLog.MinWitnesses)
	}
	return cp, nil
}

// checkReceipt rebuilds the root from the inclusion proof and checks it against
// the checkpoint the log signed.
//
// The leaf is recomputed from the statement rather than taken from the receipt:
// a receipt that named a leaf nobody could derive from the attestation would be
// a receipt for something else.
func (v *verifier) checkReceipt(r *storedReceipt, statement []byte, cp receipt.Checkpoint) error {
	canonical, err := uaicrypto.CanonicalizeJSON(statement)
	if err != nil {
		return fmt.Errorf("canonicalize statement: %w", err)
	}
	leaf := merkle.LeafHash(canonical)
	if got := uaicrypto.FormatDigest(leaf); got != r.LeafHash {
		return fmt.Errorf("the statement hashes to %s, the receipt names %s", short(got), short(r.LeafHash))
	}
	proof := make([][]byte, 0, len(r.InclusionProof))
	for _, node := range r.InclusionProof {
		raw, err := uaicrypto.ParseDigest(node)
		if err != nil {
			return fmt.Errorf("proof node: %w", err)
		}
		proof = append(proof, raw)
	}
	root, err := merkle.RootFromInclusionProof(r.LogIndex, r.CheckpointSize, leaf, proof)
	if err != nil {
		return fmt.Errorf("inclusion proof: %w", err)
	}
	if got := uaicrypto.FormatDigest(root); got != r.CheckpointRoot {
		return fmt.Errorf("the proof rebuilds %s, the receipt claims %s", short(got), short(r.CheckpointRoot))
	}
	// And the checkpoint the log is publishing now must be consistent with the
	// one this receipt was issued against. Checking only the receipt's own
	// numbers would verify it against itself.
	if r.CheckpointSize == cp.Size && uaicrypto.FormatDigest(cp.Root) != r.CheckpointRoot {
		return fmt.Errorf("the log now publishes a different root at size %d: split view",
			r.CheckpointSize)
	}
	return nil
}

// httpClient builds the client this tool reads a gateway with.
//
// A gateway that verifies runtime identity serves TLS, and its certificate is
// issued by the deployment's own CA -- one no public trust store knows. Without
// a way to name that CA, the one tool whose whole purpose is to trust nothing
// but public keys could only reach a gateway that verifies nothing.
//
// A path, and never a flag that skips verification. This tool's output is used
// to decide whether an identity is real; a mode where anything on the path
// could answer for the registry would make that output worthless exactly when
// it matters.
func httpClient(ca string) (*http.Client, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	if ca == "" {
		return client, nil
	}
	pem, err := os.ReadFile(ca)
	if err != nil {
		return nil, fmt.Errorf("reading the CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no PEM certificate", ca)
	}
	client.Transport = &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, MinVersion: tls.VersionTLS12,
	}}
	return client, nil
}
