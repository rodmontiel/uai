// Command uai-register creates an owner and registers agents under it.
//
// It exists because there was no way to do either without writing code. §8.2
// registration is a two-sided proof — the owner's key and the agent's key must
// each sign a statement naming the same subject — and doing that by hand means
// reimplementing canonicalization, domain separation and the challenge exchange
// for a one-off. The demo did it in Python and nobody else could.
//
// Creating an OWNER needs the database, and that is architectural rather than a
// shortcut: an owner is who answers for an agent, and a route that let anyone
// create one would make "registered to an owner" mean "registered to a name
// somebody typed". It is a registrar's act, like uai-grant is an owner's.
//
//	uai-register owner -dsn ... -name "ACME Robotics" -org-did did:web:acme.example
//	uai-register agent -owner-did did:uai:owner:... -name "DeliveryOptimizer"
//	uai-register show  -dsn ...
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/rodmontiel/uai/internal/keyfile"
	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/challenge"
	"github.com/rodmontiel/uai/pkg/pop"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
	"github.com/rodmontiel/uai/pkg/uaiid"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "owner":
		err = createOwner(os.Args[2:])
	case "agent":
		err = registerAgent(os.Args[2:])
	case "bind":
		err = bindCommand(os.Args[2:])
	case "show":
		err = show(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "uai-register: %v\n", err)
		os.Exit(1)
	}
}

// refuseRootOverAnotherUsersKeys stops `sudo uai-register` from writing keys
// the person who ran it cannot read.
//
// Nothing here needs root: the database is reached over TCP and the files go
// into the working tree. Run under sudo, keyfile.Generate writes root:root 0600
// and every later command fails with "permission denied" on a file that looks
// fine in `ls` -- and the fix, chown, is one nobody thinks of because the
// original error said nothing about ownership.
//
// Root is only refused when it would write into somebody else's directory, so
// an all-root container is unaffected.
func refuseRootOverAnotherUsersKeys(dir string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	for dir != "" && dir != "/" {
		info, err := os.Stat(dir)
		if err != nil {
			dir = dirOf(dir)
			continue
		}
		sys, ok := info.Sys().(*syscall.Stat_t)
		if !ok || sys.Uid == 0 {
			return nil
		}
		return fmt.Errorf("running as root, and %s belongs to uid %d.\n"+
			"  The key would be written as root and unreadable to that user afterwards.\n"+
			"  Nothing here needs root: drop the sudo.", dir, sys.Uid)
	}
	return nil
}

func usage() {
	fmt.Fprint(os.Stderr, `uai-register — create an owner, and register agents under it.

  uai-register owner -name "ACME Robotics" -org-did did:web:acme.example [-dsn ...]
      Creates the organization, the owner and the owner's signing key.
      Needs the database: an owner is a registrar's act, not an API call.
      -reuse-key registers with the key already on disk instead of a new one,
      for a key that outlived the database that recorded it.

  uai-register agent -owner-did did:uai:owner:… -name "DeliveryOptimizer" [-endpoint ...]
      Registers an agent: generates its key, answers both halves of the §8.2
      proof, and prints the UAI-ID. Add -bind to attach a runtime.

  uai-register bind -uai-id uai:agent:… -key .keys/myagent.jwk [-svid .spire/svid]
      Attaches a runtime, which is what takes an identity from REGISTERED to
      ACTIVE. A separate step on purpose: a SPIRE entry names the agent,
      so it cannot be created until the agent has an identifier.

  uai-register show [-dsn ...]
      Lists the owners and agents this database holds.

Defaults: -dsn $PG_DSN, -endpoint $UAI_ENDPOINT or http://127.0.0.1:8080,
keys under .keys/ (which is gitignored, and must stay that way).
`)
}

// ── owner ───────────────────────────────────────────────────────────────────

func createOwner(args []string) error {
	fs := flag.NewFlagSet("owner", flag.ExitOnError)
	dsn := fs.String("dsn", os.Getenv("PG_DSN"), "PostgreSQL connection string")
	name := fs.String("name", "", "display name of the owner")
	orgDID := fs.String("org-did", "", "the organization's DID, e.g. did:web:acme.example")
	orgName := fs.String("org-name", "", "legal name of the organization (defaults to -name)")
	jurisdiction := fs.String("jurisdiction", "AR", "ISO 3166-1 alpha-2 country the owner answers in")
	keyPath := fs.String("key", ".keys/owner.jwk", "where to write the owner's signing key")
	reuse := fs.Bool("reuse-key", false,
		"register with the key already at -key instead of generating a new one")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dsn == "" {
		return errors.New("no database: pass -dsn or set PG_DSN")
	}
	if *name == "" || *orgDID == "" {
		return errors.New("-name and -org-did are required")
	}
	if *orgName == "" {
		*orgName = *name
	}
	if !strings.HasPrefix(*orgDID, "did:web:") {
		// did:web is the only organization DID method the registry resolves.
		// Saying so here beats a constraint violation three calls later.
		return fmt.Errorf("-org-did must be a did:web, got %q", *orgDID)
	}

	ctx := context.Background()
	db, err := store.Open(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer db.Close()

	// The key first: if this fails, nothing has been written, and the operator
	// retries from a clean state instead of from a half-made owner.
	id, err := uaiid.NewULID()
	if err != nil {
		return err
	}
	ownerDID := "did:uai:owner:" + id.String()
	_, statErr := os.Stat(*keyPath)
	switch {
	case statErr == nil && !*reuse:
		// Refusing is right; refusing without saying what to do instead is not.
		// The usual reason this file exists is that the owner was already
		// created, and the next step is to use it -- so look up which one it is
		// and hand back the command.
		msg := fmt.Sprintf("%s already exists. An owner key is what vouches for every agent "+
			"under it; overwriting one orphans them all.", *keyPath)
		did, lookupErr := ownerOfKey(ctx, db, *keyPath)
		if lookupErr == nil && did != "" {
			return fmt.Errorf("%s\n\n  That key belongs to %s, which already exists.\n"+
				"  You do not need a new owner. Register an agent under it:\n\n"+
				"    uai-register agent -owner-did %s -name \"MyAgent\"\n\n"+
				"  `uai-register show` lists what this database already holds.",
				msg, did, did)
		}
		// A key with no owner behind it. The ordinary way to get here is a
		// database that was deleted while the keys stayed on disk, and the key
		// is still yours -- so the answer is to register it again, not to
		// delete a private key because a tool told you to.
		return fmt.Errorf("%s\n\n  No owner in this database uses it, so it is a key without a "+
			"record -- from another database, or from one that was deleted.\n"+
			"  Register an owner with the key you already hold:\n\n"+
			"    uai-register owner -reuse-key -name %q -org-did %s\n\n"+
			"  Or pass -key somewhere else to make a second, unrelated owner.",
			msg, *name, *orgDID)
	case statErr != nil && *reuse:
		return fmt.Errorf("-reuse-key was given, but %s does not exist. "+
			"Drop the flag to generate a key there", *keyPath)
	case statErr != nil:
		if err := refuseRootOverAnotherUsersKeys(dirOf(*keyPath)); err != nil {
			return err
		}
		if err := os.MkdirAll(dirOf(*keyPath), 0o700); err != nil {
			return err
		}
		if err := keyfile.Generate(*keyPath, ownerDID+"#key-1"); err != nil {
			return fmt.Errorf("writing %s: %w", *keyPath, err)
		}
	default:
		// Reusing. Two things have to hold before this key gets a second
		// identity: that it is a usable key at all, and that no owner in THIS
		// database already speaks with it. Skipping the second would put one
		// key behind two owners, which is the confusion the refusal above
		// exists to prevent -- and -reuse-key must not become a way around it.
		if _, err := keyfile.Load(*keyPath, ownerDID+"#key-1"); err != nil {
			return fmt.Errorf("-reuse-key: %w", err)
		}
		did, lookupErr := ownerOfKey(ctx, db, *keyPath)
		if lookupErr != nil {
			return fmt.Errorf("-reuse-key: checking whether %s is already registered: %w",
				*keyPath, lookupErr)
		}
		if did != "" {
			return fmt.Errorf("-reuse-key: %s already belongs to %s in this database.\n"+
				"  Registering it again would put one key behind two owners, and a signature\n"+
				"  from it would no longer say which one made the statement.\n\n"+
				"  Register an agent under the owner that exists:\n\n"+
				"    uai-register agent -owner-did %s -name \"MyAgent\"",
				*keyPath, did, did)
		}
		if err := keyfile.SetKID(*keyPath, ownerDID+"#key-1"); err != nil {
			return fmt.Errorf("-reuse-key: relabelling %s: %w", *keyPath, err)
		}
	}
	jwk, err := keyfile.PublicJWK(*keyPath)
	if err != nil {
		return err
	}
	pub, err := json.Marshal(jwk)
	if err != nil {
		return err
	}

	orgID := "org-" + id.String()
	if err := db.CreateOrganization(ctx, store.Organization{
		ID: orgID, DID: *orgDID, LegalName: *orgName, Jurisdiction: *jurisdiction,
	}); err != nil {
		if !errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("creating the organization: %w", err)
		}
		// Reusing an organization is normal: several owners answer for one
		// company. Finding its id is not something the caller should have to do.
		var existing string
		lookupErr := db.Pool().QueryRow(ctx,
			`SELECT id FROM organizations WHERE did = $1`, *orgDID).Scan(&existing)
		if lookupErr != nil {
			return fmt.Errorf("the organization %s exists and could not be read: %w",
				*orgDID, lookupErr)
		}
		orgID = existing
		fmt.Printf("  organization  %s  (already registered)\n", *orgDID)
	}

	ownerID := "own-" + id.String()
	if err := db.CreateOwner(ctx, store.Owner{
		ID: ownerID, UAIID: "uai:owner:" + id.String(), DID: ownerDID,
		OrganizationID: orgID, DisplayName: *name, Jurisdiction: *jurisdiction,
	}); err != nil {
		return fmt.Errorf("creating the owner: %w", err)
	}
	// valid_from a minute in the past: a key valid from "now" is not yet valid
	// for a request already in flight, and the first thing this key does is sign
	// a registration seconds later.
	if _, err := db.Pool().Exec(ctx, `
		INSERT INTO owner_keys (id, owner_id, key_id, alg, public_jwk, protection, valid_from)
		VALUES ($1,$2,'key-1','EdDSA',$3::jsonb,'SOFTWARE',$4)`,
		"ok-"+id.String(), ownerID, string(pub), time.Now().Add(-time.Minute)); err != nil {
		return fmt.Errorf("recording the owner's key: %w", err)
	}

	fmt.Printf("  organization  %s\n", *orgDID)
	fmt.Printf("  owner         %s\n", ownerDID)
	if *reuse {
		fmt.Printf("  key           %s  (reused; relabelled for this owner)\n", *keyPath)
	} else {
		fmt.Printf("  key           %s\n", *keyPath)
	}
	fmt.Println()
	fmt.Println("  Register an agent under it:")
	fmt.Printf("    uai-register agent -owner-did %s -name \"MyAgent\"\n", ownerDID)
	fmt.Println()
	fmt.Println("  The owner key signs for every agent under it. It is the one file here")
	fmt.Println("  whose loss cannot be undone by re-running anything.")
	return nil
}

// ownerOfKey reports which owner a private key file belongs to, by matching its
// public half against what the registry recorded.
func ownerOfKey(ctx context.Context, db *store.DB, keyPath string) (string, error) {
	jwk, err := keyfile.PublicJWK(keyPath)
	if err != nil {
		return "", err
	}
	thumb, err := jwk.ThumbprintString()
	if err != nil {
		return "", err
	}
	rows, err := db.Pool().Query(ctx, `
		SELECT o.did, k.public_jwk FROM owner_keys k JOIN owners o ON o.id = k.owner_id`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var did string
		var raw []byte
		if err := rows.Scan(&did, &raw); err != nil {
			return "", err
		}
		var stored uaicrypto.JWK
		if json.Unmarshal(raw, &stored) != nil {
			continue
		}
		// Compared by thumbprint rather than by bytes: the same key can be
		// serialized with different member order and still be the same key.
		if s, err := stored.ThumbprintString(); err == nil && s == thumb {
			return did, nil
		}
	}
	return "", nil
}

// ── agent ───────────────────────────────────────────────────────────────────

func registerAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	endpoint := fs.String("endpoint", envOr("UAI_ENDPOINT", "http://127.0.0.1:8080"), "gateway URL")
	ca := fs.String("ca", envOr("UAI_API_CA", ""), "PEM CA bundle to verify an https gateway with")
	svidDir := fs.String("svid", envOr("UAI_SVID_DIR", ""),
		"directory holding an X509-SVID (svid.N.pem/.key) to present when binding")
	ownerDID := fs.String("owner-did", "", "the owner registering this agent")
	ownerKey := fs.String("owner-key", ".keys/owner.jwk", "the owner's signing key")
	name := fs.String("name", "", "logical name of the agent")
	agentType := fs.String("type", "autonomous_task_agent", "agent type")
	version := fs.String("version", "1.0.0", "agent version")
	jurisdiction := fs.String("jurisdiction", "AR", "primary jurisdiction")
	keyPath := fs.String("key", "", "where to write the agent's key (default .keys/<name>.jwk)")
	bind := fs.Bool("bind", false, "also bind a runtime, so the identity becomes ACTIVE")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ownerDID == "" || *name == "" {
		return errors.New("-owner-did and -name are required")
	}
	if *keyPath == "" {
		*keyPath = ".keys/" + slug(*name) + ".jwk"
	}
	if _, err := os.Stat(*keyPath); err == nil {
		return fmt.Errorf("%s already exists. That key IS an identity; overwriting it would "+
			"register a second agent whose history starts empty while the first one's stays "+
			"under a key nobody holds", *keyPath)
	}
	if err := refuseRootOverAnotherUsersKeys(dirOf(*keyPath)); err != nil {
		return err
	}
	owner, err := keyfile.Load(*ownerKey, *ownerDID+"#key-1")
	if err != nil {
		return fmt.Errorf("the owner's key: %w", err)
	}

	api, err := newClient(strings.TrimRight(*endpoint, "/"), *ca, "")
	if err != nil {
		return err
	}

	// 1. Open the registration. This mints nothing: an unanswered registration
	//    produces no identifier and expires.
	var opened struct {
		RegistrationID string `json:"registration_id"`
		ChallengeOwner string `json:"challenge_owner"`
		ChallengeAgent string `json:"challenge_agent"`
	}
	if err := api.post("/v1/agents", map[string]any{
		"logical_name": *name, "agent_type": *agentType, "owner_did": *ownerDID,
		"primary_jurisdiction": *jurisdiction, "version": *version,
	}, &opened); err != nil {
		return err
	}

	// 2. The agent's key. Generated here and never sent anywhere but as a public
	//    JWK: UAI must not be able to sign as an agent it registered.
	if err := os.MkdirAll(dirOf(*keyPath), 0o700); err != nil {
		return err
	}
	if err := keyfile.Generate(*keyPath, "did:key:pending#key-1"); err != nil {
		return err
	}
	agentSigner, err := keyfile.Load(*keyPath, "did:key:pending#key-1")
	if err != nil {
		return err
	}
	jwk, err := keyfile.PublicJWK(*keyPath)
	if err != nil {
		return err
	}
	thumb, err := jwk.ThumbprintString()
	if err != nil {
		return err
	}
	publicJWK, err := json.Marshal(jwk)
	if err != nil {
		return err
	}

	// 3. Both halves of the proof, each over a statement naming the SAME
	//    subject. Either signature alone proves nothing (§8.2).
	statement := func(role challenge.Role, value string) challenge.Ownership {
		return challenge.Ownership{
			Challenge: value, RegistrationID: opened.RegistrationID, Role: role,
			AgentKeyThumbprint: thumb, OwnerDID: *ownerDID,
		}
	}
	ownerStmt := statement(challenge.RoleOwner, opened.ChallengeOwner)
	ownerSig, err := challenge.Sign(owner, ownerStmt)
	if err != nil {
		return err
	}
	if err := api.post("/v1/agents/"+opened.RegistrationID+"/prove", map[string]any{
		"role": "owner", "challenge": ownerStmt.Challenge,
		"agent_key_thumbprint": thumb, "signature": ownerSig,
	}, nil); err != nil {
		return fmt.Errorf("the owner's proof: %w", err)
	}

	agentStmt := statement(challenge.RoleAgent, opened.ChallengeAgent)
	agentSig, err := challenge.Sign(agentSigner, agentStmt)
	if err != nil {
		return err
	}
	var minted struct {
		UAIID          string `json:"uai_id"`
		DID            string `json:"did"`
		Status         string `json:"status"`
		AssuranceLevel string `json:"assurance_level"`
	}
	if err := api.post("/v1/agents/"+opened.RegistrationID+"/prove", map[string]any{
		"role": "agent", "challenge": agentStmt.Challenge,
		"agent_key_thumbprint": thumb, "public_jwk": json.RawMessage(publicJWK),
		"signature": agentSig,
	}, &minted); err != nil {
		return fmt.Errorf("the agent's proof: %w", err)
	}

	fmt.Printf("  uai-id     %s\n", minted.UAIID)
	fmt.Printf("  did        %s\n", minted.DID)
	fmt.Printf("  status     %s\n", minted.Status)
	fmt.Printf("  key        %s\n", *keyPath)

	if *bind {
		// An SVID is presented as a client certificate, so binding an attested
		// runtime needs its own connection.
		binder := api
		svidPEM := ""
		if *svidDir != "" {
			svidPEM = svidNaming(*svidDir, lastSegment(minted.UAIID))
			if svidPEM == "" {
				return fmt.Errorf("no SVID in %s names %s.\n"+
					"  A workload holds one SVID per registration entry that matches it, and\n"+
					"  binding needs the one for THIS identity. Register it and fetch again:\n"+
					"    make spire-entry ULID=%s && make spire-svid",
					*svidDir, minted.UAIID, lastSegment(minted.UAIID))
			}
			binder, err = newClient(strings.TrimRight(*endpoint, "/"), *ca, svidPEM)
			if err != nil {
				return err
			}
		}
		status, err := bindRuntime(binder, minted.UAIID, *keyPath, minted.DID, svidPEM)
		if err != nil {
			return fmt.Errorf("binding a runtime: %w", err)
		}
		how := "self-declared runtime"
		if svidPEM != "" {
			how = "runtime attested by SPIRE"
		}
		fmt.Printf("  status     %s  (%s)\n", status, how)
	}
	fmt.Println()
	fmt.Println("  Verify it, trusting nothing but public keys:")
	fmt.Printf("    uai-verify %s\n", minted.UAIID)
	if !*bind {
		fmt.Println()
		fmt.Println("  It is REGISTERED, not ACTIVE: registration is a claim, and the binding")
		fmt.Println("  that follows it is the proof. Re-run with -bind, or bind from your SDK.")
	}
	return nil
}

// bindRuntime performs the two-call exchange of §9.1.1.
func bindRuntime(api *client, uaiID, keyPath, did, svidPEM string) (string, error) {
	signer, err := keyfile.Load(keyPath, did+"#key-1")
	if err != nil {
		return "", err
	}
	var opened struct {
		Challenge string `json:"challenge"`
		Audience  string `json:"audience"`
	}
	if err := api.postSigned(signer, uaiID, "/v1/agents/"+uaiID+"/bind",
		map[string]any{}, &opened); err != nil {
		return "", err
	}
	// With an SVID, both values come off the certificate and the registry
	// checks them against it. Without one they are the agent describing itself,
	// the registry records them as self-declared, and the assurance level
	// reports the difference rather than hiding it.
	spiffeID := "spiffe://uai.local/agents/" + lastSegment(uaiID) + "/i/cli"
	certHash := "sha256:" + strings.Repeat("0", 64)
	if svidPEM != "" {
		var err error
		if spiffeID, certHash, err = svidIdentity(svidPEM); err != nil {
			return "", err
		}
	}
	stmt := challenge.Binding{
		Challenge: opened.Challenge, Operation: challenge.OpBind, UAIID: uaiID,
		Audience: opened.Audience, SpiffeID: spiffeID, SVIDCertHash: certHash,
	}
	sig, err := challenge.SignBinding(signer, stmt)
	if err != nil {
		return "", err
	}
	var bound struct {
		Status string `json:"status"`
	}
	if err := api.postSigned(signer, uaiID, "/v1/agents/"+uaiID+"/bind", map[string]any{
		"challenge": opened.Challenge, "svid_spiffe_id": spiffeID,
		"svid_cert_hash": certHash, "signature": sig,
	}, &bound); err != nil {
		return "", err
	}
	return bound.Status, nil
}

// ── bind ────────────────────────────────────────────────────────────────────

func bindCommand(args []string) error {
	fs := flag.NewFlagSet("bind", flag.ExitOnError)
	endpoint := fs.String("endpoint", envOr("UAI_ENDPOINT", "http://127.0.0.1:8080"), "gateway URL")
	ca := fs.String("ca", envOr("UAI_API_CA", ""), "PEM CA bundle to verify an https gateway with")
	uaiID := fs.String("uai-id", "", "the identity to bind")
	keyPath := fs.String("key", "", "the agent's signing key")
	svidDir := fs.String("svid", envOr("UAI_SVID_DIR", ""),
		"directory holding an X509-SVID to present; without it the runtime is self-declared")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *uaiID == "" || *keyPath == "" {
		return errors.New("-uai-id and -key are required")
	}
	did := "did:uai:agent:" + lastSegment(*uaiID)

	svidPEM := ""
	if *svidDir != "" {
		svidPEM = svidNaming(*svidDir, lastSegment(*uaiID))
		if svidPEM == "" {
			return fmt.Errorf("no SVID in %s names %s.\n"+
				"  A workload holds one SVID per registration entry that matches it, and\n"+
				"  binding needs the one for THIS identity:\n"+
				"    make spire-entry ULID=%s && make spire-svid",
				*svidDir, *uaiID, lastSegment(*uaiID))
		}
	}
	api, err := newClient(strings.TrimRight(*endpoint, "/"), *ca, svidPEM)
	if err != nil {
		return err
	}
	status, err := bindRuntime(api, *uaiID, *keyPath, did, svidPEM)
	if err != nil {
		return err
	}
	how := "self-declared runtime"
	if svidPEM != "" {
		id, _, _ := svidIdentity(svidPEM)
		how = "attested as " + id
	}
	fmt.Printf("  uai-id     %s\n", *uaiID)
	fmt.Printf("  status     %s\n", status)
	fmt.Printf("  runtime    %s\n", how)
	return nil
}

// ── show ────────────────────────────────────────────────────────────────────

func show(args []string) error {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	dsn := fs.String("dsn", os.Getenv("PG_DSN"), "PostgreSQL connection string")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dsn == "" {
		return errors.New("no database: pass -dsn or set PG_DSN")
	}
	ctx := context.Background()
	db, err := store.Open(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	rows, err := db.Pool().Query(ctx, `
		SELECT o.did, o.display_name, coalesce(g.did, ''), count(a.id)
		  FROM owners o
		  LEFT JOIN organizations g ON g.id = o.organization_id
		  LEFT JOIN agents a ON a.owner_id = o.id
		 GROUP BY o.did, o.display_name, g.did
		 ORDER BY o.display_name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	fmt.Printf("  %-46s %-22s %s\n", "OWNER", "ORGANIZATION", "AGENTS")
	found := 0
	for rows.Next() {
		var did, name, org string
		var n int
		if err := rows.Scan(&did, &name, &org, &n); err != nil {
			return err
		}
		fmt.Printf("  %-46s %-22s %d  (%s)\n", did, org, n, name)
		found++
	}
	if found == 0 {
		fmt.Println("  (none yet — start with: uai-register owner -name \"…\" -org-did did:web:…)")
		return nil
	}

	agents, err := db.Pool().Query(ctx, `
		SELECT uai_id, logical_name, status::text, assurance_level::text
		  FROM agents ORDER BY registered_at DESC LIMIT 50`)
	if err != nil {
		return err
	}
	defer agents.Close()
	fmt.Println()
	fmt.Printf("  %-40s %-22s %-12s %s\n", "UAI-ID", "NAME", "STATUS", "ASSURANCE")
	for agents.Next() {
		var id, name, status, al string
		if err := agents.Scan(&id, &name, &status, &al); err != nil {
			return err
		}
		fmt.Printf("  %-40s %-22s %-12s %s\n", id, name, status, al)
	}
	return nil
}

// ── the smallest HTTP client that does this ─────────────────────────────────

type client struct {
	base string
	http *http.Client
}

// newClient builds the transport this call needs: a private CA when the gateway
// serves TLS from SPIRE, and a client certificate when a bind has to present an
// SVID.
func newClient(base, caPath, svidPEM string) (*client, error) {
	c := &client{base: base, http: http.DefaultClient}
	if caPath == "" && svidPEM == "" {
		return c, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("the CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s contains no certificates", caPath)
		}
		cfg.RootCAs = pool
	}
	if svidPEM != "" {
		cert, err := tls.LoadX509KeyPair(svidPEM, strings.TrimSuffix(svidPEM, ".pem")+".key")
		if err != nil {
			return nil, fmt.Errorf("the SVID: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	c.http = &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	return c, nil
}

// svidNaming returns the SVID in dir whose SPIFFE ID names this agent.
//
// A workload holds one SVID per registration entry that matches it, and a
// selector like unix:uid matches more than one. Taking svid.0 gets whichever
// entry SPIRE returned first, which binds the wrong identity while looking like
// it worked.
func svidNaming(dir, ulid string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "svid.") || !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		path := dir + "/" + e.Name()
		id, _, err := svidIdentity(path)
		if err == nil && strings.Contains(id, "/agents/"+ulid+"/") {
			return path
		}
	}
	return ""
}

// svidIdentity reads the SPIFFE ID and the leaf digest out of a certificate.
func svidIdentity(pemPath string) (string, string, error) {
	raw, err := os.ReadFile(pemPath)
	if err != nil {
		return "", "", err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return "", "", fmt.Errorf("%s is not PEM", pemPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", err
	}
	if len(cert.URIs) != 1 {
		return "", "", fmt.Errorf("%s carries %d URI SANs; an X509-SVID has exactly one",
			pemPath, len(cert.URIs))
	}
	sum := sha256.Sum256(cert.Raw)
	return cert.URIs[0].String(), "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (c *client) post(path string, body, out any) error {
	return c.do(http.MethodPost, path, body, out, nil, "")
}

func (c *client) postSigned(signer uaicrypto.Signer, uaiID, path string, body, out any) error {
	return c.do(http.MethodPost, path, body, out, signer, uaiID)
}

func (c *client) do(method, path string, body, out any, signer uaicrypto.Signer, uaiID string) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	url := c.base + path
	req, err := http.NewRequest(method, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	nonce, err := randomNonce()
	if err != nil {
		return err
	}
	req.Header.Set("Idempotency-Key", "reg-"+nonce)
	if signer != nil {
		if err := pop.SignRequest(signer, req, raw, uaicrypto.DomainChallenge, uaiID, nonce); err != nil {
			return err
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w\n%s", method, url, err, dialHint(err))
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return problem(method, url, resp.StatusCode, payload)
	}
	if out != nil {
		return json.Unmarshal(payload, out)
	}
	return nil
}

// problem renders an RFC 9457 response the way its author intended it to read:
// the code, what happened, and what to do about it.
func problem(method, url string, status int, payload []byte) error {
	var p struct {
		Title       string `json:"title"`
		Detail      string `json:"detail"`
		Remediation string `json:"remediation"`
	}
	if json.Unmarshal(payload, &p) != nil || p.Title == "" {
		body := strings.TrimSpace(string(payload))
		// Not a UAI problem document, because it never reached the application:
		// Go's TLS server answers a plain HTTP request with this, which is why
		// the case arrives here and not as a dial error.
		if strings.Contains(body, "HTTP request to an HTTPS server") {
			return fmt.Errorf("%s %s → %d\n  %s\n"+
				"  This gateway serves TLS, and the endpoint says http.\n"+
				"  Use -endpoint https://localhost:8080 -ca .spire/bootstrap.pem,\n"+
				"  or export UAI_ENDPOINT and UAI_API_CA as `./deploy.sh up` prints them.",
				method, url, status, body)
		}
		return fmt.Errorf("%s %s → %d\n  %s", method, url, status, body)
	}
	msg := fmt.Sprintf("%s %s → %d %s\n  %s", method, url, status, p.Title, p.Detail)
	if p.Remediation != "" {
		msg += "\n  " + p.Remediation
	}
	return errors.New(msg)
}

// randomNonce is 128 bits of randomness, which is what both the replay cache
// and the idempotency ledger key off.
func randomNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func dirOf(path string) string {
	if i := strings.LastIndex(path, "/"); i > 0 {
		return path[:i]
	}
	return "."
}

func lastSegment(s string) string {
	if i := strings.LastIndex(s, ":"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// slug turns a display name into a filename that will not surprise anyone.
func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ', r == '-', r == '_':
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "agent"
	}
	return out
}

// dialHint turns a transport failure into the one sentence that fixes it.
//
// All of these used to print "Is the gateway running?", which is right for a
// refused connection and wrong for every other case: against a gateway that is
// running and serving TLS it sends the reader to restart a healthy stack
// instead of to the flag they left out. A remediation that is wrong most of the
// time is worse than none -- it is followed.
func dialHint(err error) string {
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	text := err.Error()
	switch {
	case errors.As(err, &unknown):
		return "  The gateway serves TLS and nothing here says which CA to trust.\n" +
			"  Add -ca .spire/bootstrap.pem, or export UAI_API_CA=.spire/bootstrap.pem.\n" +
			"  `./deploy.sh up` prints the pair that matches the stack it started."
	case errors.As(err, &hostname):
		return "  The gateway's certificate does not name this host. Reach it by the name\n" +
			"  the certificate carries, or re-mint it with `./deploy.sh up`."
	case errors.As(err, &invalid):
		return "  The gateway's certificate is not valid right now. Every SVID expires --\n" +
			"  that is the point of them. `./deploy.sh up` mints a fresh one."
	case strings.Contains(text, "server gave HTTP response to HTTPS client"):
		return "  This gateway serves plain HTTP, and the endpoint says https.\n" +
			"  Use -endpoint http://127.0.0.1:8080 and unset UAI_API_CA.\n" +
			"  `./deploy.sh status` says which one it is serving."
	default:
		return "  Is the gateway running? ./deploy.sh up, or make run-gateway"
	}
}
