package latticesig

import (
	"errors"
	"testing"
)

func TestCrossParameterSetRejected(t *testing.T) {
	seed := testSeed()
	kp128, _ := GenerateKey(seed, Toy128)
	kp256, _ := GenerateKey(seed, Lite256)
	msg := []byte("cross")

	sig128, err := Sign(kp128.Secret, msg)
	if err != nil {
		t.Fatal(err)
	}
	// same seed, different parameter set -> must not verify
	if err := Verify(kp256.Public, msg, sig128); err == nil {
		t.Fatal("signature verified across different parameter sets")
	} else if !errors.Is(err, ErrUnsupportedParams) && !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSignatureSizes(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	sig, _ := Sign(kp.Secret, []byte("size"))
	b, _ := sig.MarshalBinary()
	t.Logf("toy128 signature blob = %d bytes (N=%d)", len(b), Toy128.N)
	if len(b) != headerLen+checksumLen+32+2*Toy128.N {
		t.Fatalf("unexpected signature size %d", len(b))
	}
}
