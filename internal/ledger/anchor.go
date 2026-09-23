// Package ledger writes witnessed checkpoints to the consortium ledger and,
// through a pluggable adapter, to a chain the operator does not control.
package ledger

import (
	"context"
	"errors"
	"fmt"
)

// ErrNoPublicAnchor is returned by an adapter that publishes nowhere.
//
// It is an error and not a fabricated anchor, and that distinction is the whole
// design of the noop adapter. A development build that returned a plausible
// transaction hash would make receipts claim durability nobody provided, and
// the claim would be indistinguishable from a real one until somebody went
// looking for the transaction. Publishing nothing must LOOK like publishing
// nothing.
var ErrNoPublicAnchor = errors.New("ledger: this deployment publishes no public anchor")

// PublicAnchor records where an epoch root reached an external chain.
type PublicAnchor struct {
	Adapter string
	ChainID uint64
	Tx      string
	Block   uint64
	Epoch   uint64
}

// PublicAnchorAdapter publishes epoch roots outside the consortium.
//
// §17.4 names ethereum-l1, base, arbitrum, bitcoin-ots and noop-dev. They
// differ only in where the root lands, which is why this is an interface: the
// property being bought — pinning history somewhere the operator cannot rewrite
// — does not depend on which chain provides it, and switching should be a
// configuration change rather than a redesign.
type PublicAnchorAdapter interface {
	Name() string
	Publish(ctx context.Context, epoch uint64, root []byte) (PublicAnchor, error)
}

// NoopAdapter is the development adapter. It publishes nothing and says so.
type NoopAdapter struct{}

// Name identifies the adapter in logs and in configuration.
func (NoopAdapter) Name() string { return "noop-dev" }

// Publish always refuses.
//
// The consortium anchor still happens; what is absent is the second, public
// pinning. A verifier therefore sees VERIFIED_UNANCHORED for the public layer,
// which is the truthful answer for a deployment that has not bought it.
func (NoopAdapter) Publish(_ context.Context, epoch uint64, _ []byte) (PublicAnchor, error) {
	return PublicAnchor{Adapter: "noop-dev", Epoch: epoch}, fmt.Errorf("%w: epoch %d", ErrNoPublicAnchor, epoch)
}
