// Command uai-grant is the owner's side of a capability request.
//
// It exists because §22.9 says approval happens "out of band", and out of band
// still needs a band. Without this, an agent could ask for a capability and
// nobody could ever answer — which would make the request endpoint a place
// where requests go to expire.
//
// It is deliberately NOT part of the API. Every command here needs the owner's
// private key, which the agent's process does not have and must never have; a
// route that did this would be a route an agent could reach.
//
//	uai-grant list    -dsn ... [-owner did:uai:owner:...]
//	uai-grant approve -dsn ... -request capreq-... -key owner.jwk [-expires 2160h]
//	uai-grant deny    -dsn ... -request capreq-... -key owner.jwk [-note "..."]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rodmontiel/uai/internal/keyfile"
	"github.com/rodmontiel/uai/internal/store"
	"github.com/rodmontiel/uai/pkg/capability"
	"github.com/rodmontiel/uai/pkg/uaiid"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "list":
		err = list(os.Args[2:])
	case "approve":
		err = decide(os.Args[2:], capability.EffectApprove)
	case "deny":
		err = decide(os.Args[2:], capability.EffectDeny)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `uai-grant — decide the capability requests an agent has filed.

  uai-grant list    -dsn <postgres> [-owner <did>]
  uai-grant approve -dsn <postgres> -request <id> -key <owner.jwk> -owner <did> [-expires 2160h]
  uai-grant deny    -dsn <postgres> -request <id> -key <owner.jwk> -owner <did> [-note "..."]

Approval needs the owner's signing key. Nothing an agent can reach — no API
route, no MCP tool, no SDK method — can produce that signature, and the database
refuses a grant from any party that does not answer for the agent.
`)
}

func open(dsn string) (*store.DB, context.Context, func(), error) {
	if dsn == "" {
		// Naming the variable as well as the flag: the reader who hits this has
		// almost always opened a new terminal and lost the export, and "-dsn is
		// required" sends them to look for a flag they already know about.
		return nil, nil, nil, errors.New("no database: pass -dsn or set PG_DSN")
	}
	ctx := context.Background()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		return nil, nil, nil, err
	}
	return db, ctx, db.Close, nil
}

func list(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	dsn := fs.String("dsn", os.Getenv("PG_DSN"), "PostgreSQL connection string")
	owner := fs.String("owner", "", "only this owner's requests (default: all)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, ctx, closeDB, err := open(*dsn)
	if err != nil {
		return err
	}
	defer closeDB()

	pending, err := db.PendingCapabilityRequests(ctx, *owner, time.Now())
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		fmt.Println("no pending capability requests")
		return nil
	}
	for _, p := range pending {
		fmt.Printf("%s\n", p.ID)
		fmt.Printf("  agent      %s (%s)\n", p.AgentUAIID, p.AgentDID)
		fmt.Printf("  owner      %s\n", p.OwnerDID)
		fmt.Printf("  capability %s\n", p.Capability)
		// Printed in full and never truncated: it is the entire basis on which
		// a human is about to widen what an autonomous process may do.
		fmt.Printf("  because    %s\n", p.Justification)
		if p.Purpose != "" {
			fmt.Printf("  purpose    %s\n", p.Purpose)
		}
		fmt.Printf("  asked      %s (expires %s)\n\n",
			p.RequestedAt.UTC().Format(time.RFC3339), p.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return nil
}

func decide(args []string, effect capability.Effect) error {
	name := strings.ToLower(string(effect))
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	dsn := fs.String("dsn", os.Getenv("PG_DSN"), "PostgreSQL connection string")
	requestID := fs.String("request", "", "the capability request to decide")
	keyPath := fs.String("key", "", "the owner's signing key (JWK)")
	ownerDID := fs.String("owner", os.Getenv("UAI_OWNER_DID"), "the owner's DID")
	// A default expiry, not "forever". A capability granted with no end date is
	// one nobody will revisit, and the agent that holds it keeps it through
	// every change of purpose it was granted for.
	expires := fs.Duration("expires", 90*24*time.Hour, "how long the grant lasts; 0 means no expiry")
	note := fs.String("note", "", "a note recorded with the decision")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case *requestID == "":
		return errors.New("-request is required")
	case *keyPath == "":
		return errors.New("-key is required: a decision is signed by the owner, not asserted")
	case *ownerDID == "":
		return errors.New("-owner is required")
	}

	signer, err := keyfile.Load(*keyPath, *ownerDID+"#key-1")
	if err != nil {
		return fmt.Errorf("owner key: %w", err)
	}
	db, ctx, closeDB, err := open(*dsn)
	if err != nil {
		return err
	}
	defer closeDB()

	request, err := db.CapabilityRequestByID(ctx, *requestID)
	if err != nil {
		return err
	}
	if request.State != "PENDING" {
		return fmt.Errorf("request %s is already %s; a decision is made once", request.ID, request.State)
	}
	// The key must belong to the owner this request was filed against. Without
	// this, any owner's key would decide any agent's request, and the database
	// would then hold a grant attributed to a party who never saw it.
	if request.OwnerDID != *ownerDID {
		return fmt.Errorf("request %s belongs to %s, not %s",
			request.ID, request.OwnerDID, *ownerDID)
	}

	now := time.Now().UTC().Truncate(time.Second)
	decision := capability.Decision{
		Role: capability.RoleDecision, RequestID: request.ID,
		AgentDID: request.AgentDID, OwnerDID: request.OwnerDID,
		Capability: request.Capability, Effect: effect, DecidedAt: now, Note: *note,
	}
	var expiresAt *time.Time
	if effect == capability.EffectApprove && *expires > 0 {
		at := now.Add(*expires)
		decision.ExpiresAt = at
		expiresAt = &at
	}
	sig, err := capability.SignDecision(signer, decision)
	if err != nil {
		return err
	}

	state := "DENIED"
	if effect == capability.EffectApprove {
		state = "APPROVED"
	}
	id, err := uaiid.NewULID()
	if err != nil {
		return err
	}
	if err := db.DecideCapabilityRequest(ctx, request.ID, state, request.OwnerDID,
		sig.Value, *note, now, "grant-"+id.String(), expiresAt); err != nil {
		return err
	}

	fmt.Printf("%s %s for %s\n", state, request.Capability, request.AgentUAIID)
	if expiresAt != nil {
		fmt.Printf("  expires %s\n", expiresAt.Format(time.RFC3339))
	} else if effect == capability.EffectApprove {
		fmt.Printf("  no expiry — nobody will be asked to revisit this\n")
	}
	fmt.Printf("  signed by %s\n", signer.KID())
	return nil
}
