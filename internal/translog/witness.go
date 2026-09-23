// Package translog is the transparency service: a persistent append-only log
// that issues SCITT-style receipts (§18.1).
package translog

import (
	"errors"
	"fmt"
	"sync"

	"github.com/rodmontiel/uai/pkg/merkle"
	"github.com/rodmontiel/uai/pkg/receipt"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

// ErrInconsistent is a witness refusing to co-sign a checkpoint that does not
// extend the one it last signed.
//
// The refusal is the point. A log operator trying to show verifier A one
// history and verifier B another must obtain witness signatures for two
// inconsistent checkpoints; an honest witness cannot provide the second, and
// the attempt leaves a refusal behind.
var ErrInconsistent = errors.New("translog: checkpoint is not consistent with what this witness already signed")

// Witness co-signs checkpoints after checking they extend its own view.
//
// IMPORTANT, and not a detail: a witness running in this process provides the
// MECHANISM but not the INDEPENDENCE. Split-view detection rests on witnesses
// being operated by parties who would not collude with the log, and two
// goroutines cannot be that. §18.3 gives the MVP two local witnesses and
// production at least three independent operators; everything below implements
// the first honestly and is ready for the second.
type Witness struct {
	name   string
	signer uaicrypto.Signer

	mu       sync.Mutex
	lastSize uint64
	lastRoot []byte
}

// NewWitness builds a witness with no prior view.
func NewWitness(name string, signer uaicrypto.Signer) *Witness {
	return &Witness{name: name, signer: signer}
}

// Name identifies the witness in a receipt.
func (w *Witness) Name() string { return w.name }

// Public returns the key a verifier checks the co-signature against.
func (w *Witness) Public() any { return w.signer.Public() }

// CoSign verifies that cp extends what this witness last signed and, if so,
// signs it.
//
// proof is a Merkle consistency proof from the witness's last size to cp.Size.
// It is checked before signing, never after: a witness that signed first and
// verified later would have already produced the artifact an attacker wanted.
func (w *Witness) CoSign(cp receipt.Checkpoint, proof [][]byte) (receipt.WitnessSignature, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.lastSize > 0 {
		if cp.Size < w.lastSize {
			return receipt.WitnessSignature{}, fmt.Errorf("%w: size went from %d to %d",
				ErrInconsistent, w.lastSize, cp.Size)
		}
		if cp.Size == w.lastSize {
			// Same size, so it must be the same root. A different one at the
			// same size is precisely a split view.
			if string(cp.Root) != string(w.lastRoot) {
				return receipt.WitnessSignature{}, fmt.Errorf("%w: two roots at size %d",
					ErrInconsistent, cp.Size)
			}
		} else if err := merkle.VerifyConsistency(w.lastSize, cp.Size, w.lastRoot, cp.Root, proof); err != nil {
			return receipt.WitnessSignature{}, fmt.Errorf("%w: %v", ErrInconsistent, err)
		}
	}

	sig, err := receipt.CoSign(w.signer, w.name, cp)
	if err != nil {
		return receipt.WitnessSignature{}, err
	}
	w.lastSize, w.lastRoot = cp.Size, append([]byte(nil), cp.Root...)
	return sig, nil
}

// View reports what the witness last co-signed, which is what an auditor asks
// it for when checking whether the log showed everyone the same history.
func (w *Witness) View() (size uint64, root []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastSize, append([]byte(nil), w.lastRoot...)
}
