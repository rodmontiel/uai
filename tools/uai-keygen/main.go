// Command uai-keygen creates an issuer signing key.
//
// UAI never generates an AGENT's key -- a registry that can generate your key
// can impersonate you. The issuer's own key is different: it belongs to the
// operator running this service, and it has to come from somewhere.
//
// In production this is an HSM or a KMS (§23.5). This tool exists so that a
// development stack has a real, persistent key instead of one generated at boot,
// because a key generated at boot issues credentials that stop verifying at the
// next restart.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rodmontiel/uai/internal/keyfile"
)

func main() {
	var (
		out = flag.String("out", ".keys/issuer.jwk", "where to write the key")
		did = flag.String("did", "did:web:credentials.uai.world", "issuer DID")
		kid = flag.String("kid", "", "verification method (default <did>#key-1)")
	)
	flag.Parse()

	method := *kid
	if method == "" {
		method = *did + "#key-1"
	}
	if err := keyfile.Generate(*out, method); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s\n  issuer %s\n  method %s\n", *out, *did, method)
	fmt.Println("\nThis key signs every credential this deployment issues. Replacing it")
	fmt.Println("invalidates every credential issued under it, so back it up and do not")
	fmt.Println("commit it. Production uses an HSM or KMS instead (docs/protocol/16-deployment.md).")
}
