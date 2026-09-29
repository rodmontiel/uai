// Command uai-federate is the operator's side of federation.
//
// It holds the registry signing key, which the gateway process also holds and
// no agent ever does. Peering is this registry speaking for itself: adding a
// peer, introducing itself, and announcing an identity it issued are all acts
// of the installation, not of anything running inside it.
//
//	uai-federate show     [-endpoint ...]
//	uai-federate peer add -asn 2001 -endpoint https://b.example -pubkey b.jwk
//	uai-federate peer add -asn 2001 -endpoint https://b.example -trust-on-first-use
//	uai-federate peers
//	uai-federate handshake -asn 2001
//	uai-federate announce  -uai-id uai:agent:01J… -to 2001
//	uai-federate identities
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rodmontiel/uai/internal/keyfile"
	"github.com/rodmontiel/uai/pkg/federation"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "show":
		err = show(os.Args[2:])
	case "peers":
		err = list(os.Args[2:], "peers")
	case "identities":
		err = list(os.Args[2:], "identities")
	case "peer":
		err = peerCmd(os.Args[2:])
	case "handshake":
		err = handshake(os.Args[2:])
	case "announce":
		err = announce(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "uai-federate: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "uai-federate:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `uai-federate — this registry's side of a federation.

  uai-federate show
      What this registry publishes about itself as a UAI-AS.

  uai-federate peer add -asn 2001 -endpoint https://b.example -pubkey b.jwk
      Configure a peering. Signed with THIS registry's key, because deciding
      who may send us federated statements is an act of this installation.
      -trust-on-first-use fetches the key from the endpoint instead, and says
      so: it trusts whoever answers that URL right now.

  uai-federate peers
  uai-federate identities
      What is configured, and what peers have said.

  uai-federate handshake -asn 2001
      Send our REGISTRY_HELLO to a peer and record theirs. PENDING → ACTIVE.

  uai-federate announce -uai-id uai:agent:01J… -to 2001
      Tell a peer about an identity WE issued. A registry may speak for its own
      identities and for no others.

Defaults: -endpoint $UAI_ENDPOINT, -ca $UAI_API_CA, -key $UAI_REGISTRY_KEY or
.keys/registry.jwk.
`)
}

// ── shared plumbing ─────────────────────────────────────────────────────────

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type client struct {
	base string
	http *http.Client
}

func newClient(endpoint, ca string) (*client, error) {
	c := &client{base: strings.TrimRight(endpoint, "/"),
		http: &http.Client{Timeout: 30 * time.Second}}
	if ca == "" {
		return c, nil
	}
	pem, err := os.ReadFile(ca)
	if err != nil {
		return nil, fmt.Errorf("reading the CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no PEM certificate", ca)
	}
	c.http.Transport = &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, MinVersion: tls.VersionTLS12,
	}}
	return c, nil
}

func (c *client) do(method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w\n%s", method, c.base+path, err, dialHint(err))
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return problem(method, c.base+path, resp.StatusCode, payload)
	}
	if out != nil {
		return json.Unmarshal(payload, out)
	}
	return nil
}

func problem(method, url string, status int, payload []byte) error {
	var p struct {
		Title, Detail, Remediation string
	}
	if json.Unmarshal(payload, &p) != nil || p.Title == "" {
		body := strings.TrimSpace(string(payload))
		if strings.Contains(body, "HTTP request to an HTTPS server") {
			return fmt.Errorf("%s %s → %d\n  %s\n"+
				"  This gateway serves TLS, and the endpoint says http.\n"+
				"  Use -endpoint https://… -ca .spire/bootstrap.pem.", method, url, status, body)
		}
		return fmt.Errorf("%s %s → %d\n  %s", method, url, status, body)
	}
	msg := fmt.Sprintf("%s %s → %d %s\n  %s", method, url, status, p.Title, p.Detail)
	if p.Remediation != "" {
		msg += "\n  " + p.Remediation
	}
	return errors.New(msg)
}

func dialHint(err error) string {
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return "  This gateway serves TLS and nothing here says which CA to trust.\n" +
			"  Add -ca .spire/bootstrap.pem, or export UAI_API_CA."
	}
	if strings.Contains(err.Error(), "server gave HTTP response to HTTPS client") {
		return "  This gateway serves plain HTTP, and the endpoint says https."
	}
	return "  Is the gateway running? ./deploy.sh up"
}

func nonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// localRegistry reads what this registry says about itself, which is also the
// check that federation is configured at all.
func localRegistry(c *client) (federation.ASN, string, error) {
	var view struct {
		UAIASN      federation.ASN `json:"uai_asn"`
		RegistryDID string         `json:"registry_did"`
	}
	if err := c.do("GET", "/v1/federation/registry", nil, &view); err != nil {
		return 0, "", err
	}
	return view.UAIASN, view.RegistryDID, nil
}

func registrySigner(path string, asn federation.ASN) (uaicrypto.Signer, error) {
	return keyfile.Load(path, federation.RegistryDID(asn)+"#key-1")
}

// ── commands ────────────────────────────────────────────────────────────────

type common struct {
	endpoint, ca, key string
}

func bind(fs *flag.FlagSet) *common {
	c := &common{}
	fs.StringVar(&c.endpoint, "endpoint", envOr("UAI_ENDPOINT", "http://127.0.0.1:8080"), "gateway URL")
	fs.StringVar(&c.ca, "ca", envOr("UAI_API_CA", ""), "PEM CA bundle for an https gateway")
	fs.StringVar(&c.key, "key", envOr("UAI_REGISTRY_KEY", ".keys/registry.jwk"),
		"this registry's signing key")
	return c
}

func show(args []string) error {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	c := bind(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	api, err := newClient(c.endpoint, c.ca)
	if err != nil {
		return err
	}
	var view map[string]any
	if err := api.do("GET", "/v1/federation/registry", nil, &view); err != nil {
		return err
	}
	fmt.Printf("  UAI-AS      %v\n", view["uai_asn"])
	fmt.Printf("  registry    %v\n", view["name"])
	fmt.Printf("  did         %v\n", view["registry_did"])
	fmt.Printf("  status      %v\n", view["status"])
	fmt.Printf("  endpoint    %v\n", view["federation_endpoint"])
	fmt.Printf("  protocol    %v\n", view["protocol_version"])
	return nil
}

func list(args []string, what string) error {
	fs := flag.NewFlagSet(what, flag.ExitOnError)
	c := bind(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	api, err := newClient(c.endpoint, c.ca)
	if err != nil {
		return err
	}
	var out map[string]any
	if err := api.do("GET", "/v1/federation/"+what, nil, &out); err != nil {
		return err
	}
	rows, _ := out[what].([]any)
	if len(rows) == 0 {
		fmt.Printf("  (none yet)\n")
		return nil
	}
	if what == "peers" {
		fmt.Printf("  %-8s %-34s %-10s %s\n", "UAI-AS", "REGISTRY DID", "STATUS", "ENDPOINT")
		for _, r := range rows {
			m, _ := r.(map[string]any)
			fmt.Printf("  %-8v %-34v %-10v %v\n", m["remote_uai_asn"],
				m["remote_registry_did"], m["status"], m["remote_endpoint"])
		}
		return nil
	}
	fmt.Printf("  %-46s %-8s %-12s %s\n", "AGENT DID", "ORIGIN", "STATUS", "SIGNATURE")
	for _, r := range rows {
		m, _ := r.(map[string]any)
		fmt.Printf("  %-46v AS%-6v %-12v %v\n", m["agent_did"], m["origin_uai_asn"],
			m["remote_status"], m["signature_status"])
	}
	fmt.Println()
	fmt.Println("  These belong to other registries. None of them is an agent of this one.")
	return nil
}

func peerCmd(args []string) error {
	if len(args) == 0 || args[0] != "add" {
		return errors.New("usage: uai-federate peer add -asn N -endpoint URL [-pubkey FILE | -trust-on-first-use]")
	}
	fs := flag.NewFlagSet("peer add", flag.ExitOnError)
	c := bind(fs)
	asn := fs.Uint("asn", 0, "the remote registry's UAI-AS number")
	remote := fs.String("endpoint-remote", "", "the remote registry's federation endpoint")
	pubkey := fs.String("pubkey", "", "file holding the remote registry's public JWK")
	tofu := fs.Bool("trust-on-first-use", false,
		"fetch the remote key from its endpoint instead of being given it")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *asn == 0 || *remote == "" {
		return errors.New("-asn and -endpoint-remote are required")
	}
	api, err := newClient(c.endpoint, c.ca)
	if err != nil {
		return err
	}
	localASN, _, err := localRegistry(api)
	if err != nil {
		return err
	}

	var jwk uaicrypto.JWK
	switch {
	case *pubkey != "":
		raw, err := os.ReadFile(*pubkey)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &jwk); err != nil {
			return fmt.Errorf("%s is not a JWK: %w", *pubkey, err)
		}
	case *tofu:
		// Said out loud every time. This trusts whoever answers that URL at this
		// moment; if it is not the registry you meant, everything downstream --
		// signatures, sequences, authority -- verifies perfectly against the
		// wrong key.
		fmt.Fprintf(os.Stderr,
			"  trust on first use: taking AS%d's key from %s.\n"+
				"  Whoever answers that URL now becomes the key every later message is\n"+
				"  checked against. Out of band is better.\n", *asn, *remote)
		peerAPI, err := newClient(*remote, c.ca)
		if err != nil {
			return err
		}
		var view struct {
			PublicKey uaicrypto.JWK `json:"public_key"`
			UAIASN    uint          `json:"uai_asn"`
		}
		if err := peerAPI.do("GET", "/v1/federation/registry", nil, &view); err != nil {
			return err
		}
		if view.UAIASN != *asn {
			return fmt.Errorf("%s says it is AS%d, not AS%d", *remote, view.UAIASN, *asn)
		}
		jwk = view.PublicKey
	default:
		return errors.New("give the peer's key with -pubkey, or accept -trust-on-first-use")
	}

	signer, err := registrySigner(c.key, localASN)
	if err != nil {
		return fmt.Errorf("this registry's signing key: %w", err)
	}
	n, err := nonce()
	if err != nil {
		return err
	}
	req := map[string]any{
		"remote_uai_asn":      *asn,
		"remote_registry_did": federation.RegistryDID(federation.ASN(*asn)),
		"remote_endpoint":     *remote,
		"remote_public_key":   jwk,
		"nonce":               n,
	}
	sig, err := uaicrypto.SignObject(signer, uaicrypto.DomainFederationPeering, req)
	if err != nil {
		return err
	}
	req["signature"] = sig

	var out map[string]any
	if err := api.do("POST", "/v1/federation/peers", req, &out); err != nil {
		return err
	}
	fmt.Printf("  peer        AS%d  %v\n", *asn, out["status"])
	fmt.Printf("  endpoint    %s\n", *remote)
	fmt.Println()
	fmt.Println("  PENDING until a handshake. And a peering is not trust in its agents:")
	fmt.Println("  it only means this registry will read what that one sends.")
	return nil
}

func handshake(args []string) error {
	fs := flag.NewFlagSet("handshake", flag.ExitOnError)
	c := bind(fs)
	asn := fs.Uint("asn", 0, "the peer to greet")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *asn == 0 {
		return errors.New("-asn is required")
	}
	api, err := newClient(c.endpoint, c.ca)
	if err != nil {
		return err
	}
	localASN, localDID, err := localRegistry(api)
	if err != nil {
		return err
	}
	var reg struct {
		Name      string        `json:"name"`
		Endpoint  string        `json:"federation_endpoint"`
		PublicKey uaicrypto.JWK `json:"public_key"`
	}
	if err := api.do("GET", "/v1/federation/registry", nil, &reg); err != nil {
		return err
	}
	// Where the peer lives, as WE recorded it. Not as the peer says, which is
	// the whole point of having configured it.
	var peers struct {
		Peers []struct {
			RemoteASN uint   `json:"remote_uai_asn"`
			Endpoint  string `json:"remote_endpoint"`
			Status    string `json:"status"`
		} `json:"peers"`
	}
	if err := api.do("GET", "/v1/federation/peers", nil, &peers); err != nil {
		return err
	}
	target := ""
	for _, p := range peers.Peers {
		if p.RemoteASN == *asn {
			target = p.Endpoint
		}
	}
	if target == "" {
		return fmt.Errorf("AS%d is not a configured peer here. Add it first:\n"+
			"  uai-federate peer add -asn %d -endpoint-remote https://…", *asn, *asn)
	}

	signer, err := registrySigner(c.key, localASN)
	if err != nil {
		return err
	}
	n, err := nonce()
	if err != nil {
		return err
	}
	hello, err := federation.Sign(signer, federation.Hello{
		UAIASN: localASN, RegistryDID: localDID, RegistryName: reg.Name,
		Endpoint: reg.Endpoint, PublicJWK: reg.PublicKey,
		Timestamp: uaicrypto.NewTimestamp(time.Now()), Nonce: n,
	})
	if err != nil {
		return err
	}
	peerAPI, err := newClient(target, c.ca)
	if err != nil {
		return err
	}
	var reply federation.Hello
	if err := peerAPI.do("POST", "/v1/federation/handshake", hello, &reply); err != nil {
		return err
	}
	fmt.Printf("  sent        %s from AS%d\n", hello.Type, localASN)
	fmt.Printf("  answered    %s from AS%d (%s)\n", reply.Type, reply.UAIASN, reply.RegistryName)
	fmt.Printf("  peering     AS%d is now ACTIVE at the far end\n", localASN)
	fmt.Println()
	fmt.Println("  Run the same command from the other side to make it ACTIVE here too:")
	fmt.Printf("  a handshake proves one direction, and both registries decide separately.\n")
	return nil
}

func announce(args []string) error {
	fs := flag.NewFlagSet("announce", flag.ExitOnError)
	c := bind(fs)
	uaiID := fs.String("uai-id", "", "an identity THIS registry issued")
	to := fs.Uint("to", 0, "the peer to tell")
	seq := fs.Int64("sequence", 0, "sequence number (default: unix seconds)")
	// For demonstrating the refusal, and for nothing else. A registry announcing
	// a DID that names another registry as its authority is the attack the
	// receiving side exists to refuse, and a demo that only ever shows the happy
	// path has not shown that the refusal works.
	forge := fs.String("forge-did", "",
		"announce this DID instead of the identity's own, to show the refusal")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *uaiID == "" || *to == 0 {
		return errors.New("-uai-id and -to are required")
	}
	api, err := newClient(c.endpoint, c.ca)
	if err != nil {
		return err
	}
	localASN, _, err := localRegistry(api)
	if err != nil {
		return err
	}

	// The identity, from our own registry. An announcement about an agent this
	// registry did not issue is one the receiver will refuse, and it should.
	var agent struct {
		UAIID              string `json:"uai_id"`
		Status             string `json:"status"`
		IdentityCommitment string `json:"identity_commitment"`
	}
	if *forge == "" {
		if err := api.do("GET", "/v1/agents/"+*uaiID, nil, &agent); err != nil {
			return err
		}
	} else {
		agent.Status = "REVOKED"
		agent.IdentityCommitment = "sha256:" + strings.Repeat("f", 64)
		fmt.Fprintf(os.Stderr, "  forging: announcing %s, which this registry did not issue.\n",
			*forge)
	}
	ulid := (*uaiID)[strings.LastIndex(*uaiID, ":")+1:]

	var peers struct {
		Peers []struct {
			RemoteASN uint   `json:"remote_uai_asn"`
			Endpoint  string `json:"remote_endpoint"`
			Status    string `json:"status"`
		} `json:"peers"`
	}
	if err := api.do("GET", "/v1/federation/peers", nil, &peers); err != nil {
		return err
	}
	target, status := "", ""
	for _, p := range peers.Peers {
		if p.RemoteASN == *to {
			target, status = p.Endpoint, p.Status
		}
	}
	if target == "" {
		return fmt.Errorf("AS%d is not a configured peer here", *to)
	}
	if status != "ACTIVE" {
		return fmt.Errorf("the peering with AS%d is %s. Run: uai-federate handshake -asn %d",
			*to, status, *to)
	}

	signer, err := registrySigner(c.key, localASN)
	if err != nil {
		return err
	}
	sequence := *seq
	if sequence == 0 {
		sequence = time.Now().Unix()
	}
	announced := federation.AgentDID(localASN, ulid)
	if *forge != "" {
		announced = *forge
	}
	ann, err := federation.SignAnnouncement(signer, federation.Announcement{
		OriginUAIASN: localASN,
		AgentDID:     announced,
		AgentStatus:  agent.Status,
		Timestamp:    uaicrypto.NewTimestamp(time.Now()),
		Sequence:     sequence,
		// The commitment, not the identity's contents. Nothing in an
		// announcement says what an agent does, who owns it or what it touched.
		CredentialHash: agent.IdentityCommitment,
	})
	if err != nil {
		return err
	}
	peerAPI, err := newClient(target, c.ca)
	if err != nil {
		return err
	}
	var out map[string]any
	if err := peerAPI.do("POST", "/v1/federation/announcements", ann, &out); err != nil {
		return err
	}
	fmt.Printf("  announced   %s\n", ann.AgentDID)
	fmt.Printf("  status      %s\n", ann.AgentStatus)
	fmt.Printf("  sequence    %d\n", ann.Sequence)
	fmt.Printf("  to          AS%d → %v\n", *to, out["result"])
	return nil
}
