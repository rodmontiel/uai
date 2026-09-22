package receipt_test

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/rodmontiel/uai/pkg/merkle"
	"github.com/rodmontiel/uai/pkg/receipt"
	"github.com/rodmontiel/uai/pkg/uaicrypto"
)

const logKID = "did:web:log.uai.world#key-1"

type harness struct {
	tree       *merkle.Tree
	statements [][]byte
	anchors    receipt.TrustAnchors
	logSigner  uaicrypto.Signer
	witnesses  map[string]uaicrypto.Signer
}

func setup(t *testing.T, n int, minWitnesses int) *harness {
	t.Helper()
	logSigner, logPub, err := uaicrypto.GenerateEd25519Signer(logKID)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{
		tree:      merkle.New(),
		logSigner: logSigner,
		witnesses: map[string]uaicrypto.Signer{},
		anchors: receipt.TrustAnchors{
			LogKeys:      map[string]any{logKID: logPub},
			WitnessKeys:  map[string]any{},
			MinWitnesses: minWitnesses,
		},
	}
	for _, name := range []string{"witness-de", "witness-jp", "witness-ca"} {
		s, pub, err := uaicrypto.GenerateEd25519Signer(name)
		if err != nil {
			t.Fatal(err)
		}
		h.witnesses[name] = s
		h.anchors.WitnessKeys[name] = pub
	}
	for i := 0; i < n; i++ {
		st := []byte(`{"statement":` + string(rune('0'+i)) + `}`)
		h.statements = append(h.statements, st)
		h.tree.Append(st)
	}
	return h
}

func (h *harness) issue(t *testing.T, index uint64, witnesses ...string) receipt.Receipt {
	t.Helper()
	r, err := receipt.Issue(h.logSigner, "uai.world/log/1", h.tree, index, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range witnesses {
		ws, err := receipt.CoSign(h.witnesses[name], name, r.Checkpoint)
		if err != nil {
			t.Fatal(err)
		}
		r.WitnessSignatures = append(r.WitnessSignatures, ws)
	}
	return r
}

func TestCheckpointBodyFormat(t *testing.T) {
	// The trailing newline is part of the signed bytes. A verifier that drops
	// it computes a different signing input and rejects every genuine checkpoint.
	root := make([]byte, merkle.HashSize)
	cp := receipt.Checkpoint{Origin: "uai.world/log/1", Size: 184300, Root: root}
	want := "uai.world/log/1\n184300\n" + base64.StdEncoding.EncodeToString(root) + "\n"
	if string(cp.Body()) != want {
		t.Fatalf("body = %q, want %q", cp.Body(), want)
	}
	back, err := receipt.ParseCheckpointBody(cp.Body())
	if err != nil {
		t.Fatal(err)
	}
	if back.Origin != cp.Origin || back.Size != cp.Size || string(back.Root) != string(root) {
		t.Fatalf("checkpoint did not survive the round trip: %+v", back)
	}
}

func TestCheckpointBodyRejectsMalformed(t *testing.T) {
	for name, body := range map[string]string{
		"missing trailing newline": "uai.world/log/1\n10\nAAAA",
		"empty origin":             "\n10\nAAAA\n",
		"non numeric size":         "uai.world/log/1\nten\nAAAA\n",
		"root wrong length":        "uai.world/log/1\n10\nAAAA\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := receipt.ParseCheckpointBody([]byte(body)); err == nil {
				t.Fatal("a malformed checkpoint parsed")
			}
		})
	}
}

func TestVerifyAnchoredAndUnanchored(t *testing.T) {
	h := setup(t, 9, 2)
	r := h.issue(t, 4, "witness-de", "witness-jp")

	status, err := receipt.Verify(r, h.statements[4], h.anchors)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Between an event and its next anchor, this is the strongest truthful
	// answer. Reporting VERIFIED here would overstate the evidence.
	if status != receipt.StatusVerifiedUnanchored {
		t.Fatalf("status = %s, want %s", status, receipt.StatusVerifiedUnanchored)
	}

	r.Anchor = &receipt.Anchor{ChainID: 13370, Tx: "0xabc", Block: 8829112, Epoch: 412}
	status, err = receipt.Verify(r, h.statements[4], h.anchors)
	if err != nil {
		t.Fatal(err)
	}
	if status != receipt.StatusVerified {
		t.Fatalf("status = %s, want %s", status, receipt.StatusVerified)
	}
}

func TestVerifyEveryIndex(t *testing.T) {
	h := setup(t, 16, 1)
	for i := range h.statements {
		r := h.issue(t, uint64(i), "witness-de")
		if _, err := receipt.Verify(r, h.statements[i], h.anchors); err != nil {
			t.Fatalf("index %d: %v", i, err)
		}
	}
}

func TestWrongStatementRejected(t *testing.T) {
	h := setup(t, 8, 1)
	r := h.issue(t, 3, "witness-de")
	if _, err := receipt.Verify(r, []byte(`{"statement":"forged"}`), h.anchors); !errors.Is(err, receipt.ErrLeafMismatch) {
		t.Fatalf("expected ErrLeafMismatch, got %v", err)
	}
}

func TestTamperedProofRejected(t *testing.T) {
	h := setup(t, 8, 1)
	r := h.issue(t, 3, "witness-de")
	if len(r.InclusionProof) == 0 {
		t.Fatal("expected a non-empty audit path")
	}
	r.InclusionProof[0] = uaicrypto.FormatDigest(merkle.LeafHash([]byte("junk")))
	if _, err := receipt.Verify(r, h.statements[3], h.anchors); !errors.Is(err, receipt.ErrBadInclusion) {
		t.Fatalf("expected ErrBadInclusion, got %v", err)
	}
}

func TestTamperedCheckpointRejected(t *testing.T) {
	h := setup(t, 8, 1)
	r := h.issue(t, 3, "witness-de")
	// Growing the claimed size without re-signing: the log signature no longer
	// covers the checkpoint being presented.
	r.Checkpoint.Size = 99
	if _, err := receipt.Verify(r, h.statements[3], h.anchors); err == nil {
		t.Fatal("a tampered checkpoint verified")
	}
}

func TestUnknownLogKeyRejected(t *testing.T) {
	h := setup(t, 4, 1)
	r := h.issue(t, 0, "witness-de")
	h.anchors.LogKeys = map[string]any{"did:web:other.example#key-1": nil}
	if _, err := receipt.Verify(r, h.statements[0], h.anchors); !errors.Is(err, receipt.ErrUnknownLogKey) {
		t.Fatalf("expected ErrUnknownLogKey, got %v", err)
	}
}

func TestUnderwitnessedReported(t *testing.T) {
	h := setup(t, 8, 2)
	r := h.issue(t, 1, "witness-de") // only one co-signature

	status, err := receipt.Verify(r, h.statements[1], h.anchors)
	if !errors.Is(err, receipt.ErrNotEnoughWitnesses) {
		t.Fatalf("expected ErrNotEnoughWitnesses, got %v", err)
	}
	// The status must say what is wrong rather than silently degrading: a
	// verifier that cannot express UNDERWITNESSED cannot detect a split view.
	if status != receipt.StatusUnderwitnessed {
		t.Fatalf("status = %s, want %s", status, receipt.StatusUnderwitnessed)
	}
}

func TestRepeatedWitnessCannotInflateTheCount(t *testing.T) {
	h := setup(t, 8, 2)
	r := h.issue(t, 1, "witness-de")
	// The same witness co-signing twice is still one independent witness.
	r.WitnessSignatures = append(r.WitnessSignatures, r.WitnessSignatures[0])
	if _, err := receipt.Verify(r, h.statements[1], h.anchors); !errors.Is(err, receipt.ErrNotEnoughWitnesses) {
		t.Fatalf("a repeated witness inflated the count: %v", err)
	}
}

func TestUnknownWitnessDoesNotCount(t *testing.T) {
	h := setup(t, 8, 1)
	r := h.issue(t, 1)
	r.WitnessSignatures = append(r.WitnessSignatures, receipt.WitnessSignature{
		Witness: "witness-invented", Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
	})
	if _, err := receipt.Verify(r, h.statements[1], h.anchors); !errors.Is(err, receipt.ErrNotEnoughWitnesses) {
		t.Fatalf("an invented witness counted: %v", err)
	}
}

func TestSplitViewIsDetectable(t *testing.T) {
	// Two logs with the same origin and size but different content produce
	// different roots. A witness that already co-signed one cannot co-sign the
	// other without the inconsistency being visible in the signed bodies.
	a := setup(t, 8, 1)
	b := setup(t, 8, 1)
	b.tree = merkle.New()
	for i := 0; i < 8; i++ {
		b.tree.Append([]byte(`{"statement":"rewritten` + string(rune('0'+i)) + `"}`))
	}
	ra := a.issue(t, 0, "witness-de")
	rb, err := receipt.Issue(b.logSigner, "uai.world/log/1", b.tree, 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if string(ra.Checkpoint.Body()) == string(rb.Checkpoint.Body()) {
		t.Fatal("two different histories produced the same checkpoint body")
	}
}

func TestIndexOutsideCheckpointRejected(t *testing.T) {
	h := setup(t, 4, 1)
	r := h.issue(t, 0, "witness-de")
	r.LogIndex = 99
	if _, err := receipt.Verify(r, h.statements[0], h.anchors); !errors.Is(err, receipt.ErrIndexOutOfTree) {
		t.Fatalf("expected ErrIndexOutOfTree, got %v", err)
	}
	if _, err := receipt.Issue(h.logSigner, "uai.world/log/1", h.tree, 99, time.Now()); !errors.Is(err, receipt.ErrIndexOutOfTree) {
		t.Fatalf("issuing for an out-of-range index should fail, got %v", err)
	}
}
