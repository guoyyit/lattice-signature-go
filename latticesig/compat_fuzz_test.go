package latticesig

import (
	"errors"
	"testing"
)

// TestOldVersionStillVerifies confirms every version in the accepted range
// [minAcceptedVer, payloadVersion] parses and verifies. v0 uses the fixed
// legacy vectors (genuine old layout); v1 uses the current encoder.
func TestOldVersionStillVerifies(t *testing.T) {
	msg := []byte("legacy interop message")

	// v0: fixed legacy vectors.
	pk0, err := UnmarshalPublicKey(v0PubVector)
	if err != nil {
		t.Fatalf("v0 pub: %v", err)
	}
	if err := VerifyEncoded(pk0, msg, v0SigVector); err != nil {
		t.Fatalf("v0 blob rejected: %v", err)
	}

	// v1: current encoder.
	kp, _ := GenerateKey(testSeed(), Toy128)
	sig, _ := Sign(kp.Secret, msg)
	b, _ := sig.MarshalBinary()
	if err := VerifyEncoded(kp.Public, msg, b); err != nil {
		t.Fatalf("v1 blob rejected: %v", err)
	}

	// The accepted range is exactly {0, 1}.
	if minAcceptedVer != 0 || payloadVersion != 1 {
		t.Fatalf("unexpected version range [%d, %d]", minAcceptedVer, payloadVersion)
	}
}

// TestHugeRandomBlobsDoNotPanic feeds malformed bytes of varying sizes and
// requires the decoder/verifier to return an error rather than panic/hang.
func TestHugeRandomBlobsDoNotPanic(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	sizes := []int{0, 1, 4, 8, 12, 13, 16, 100, 1000, 64 * 1024, 200 * 1024}
	for _, n := range sizes {
		buf := make([]byte, n)
		// deterministic pseudo-fill so the test is reproducible
		for i := range buf {
			buf[i] = byte((i*1103515245 + 12345) >> 16)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("size %d panicked: %v", n, r)
				}
			}()
			if _, err := UnmarshalSignature(buf); err == nil {
				// improbable; if it decodes it must verify-fail cleanly
			}
			if err := VerifyEncoded(kp.Public, []byte("m"), buf); err == nil {
				t.Fatalf("random blob size %d unexpectedly verified", n)
			}
			_, _ = UnmarshalPublicKey(buf)
			_, _ = UnmarshalSecretKey(buf)
		}()
	}
}

// TestHugeMessageBounded verifies an oversized message returns
// ErrMessageTooLarge quickly (no allocation-driven hang in hash path).
func TestHugeMessageBounded(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	big := make([]byte, Toy128.MaxMsg+10_000_000)
	err := Verify(kp.Public, big, &Signature{params: Toy128, z: make(poly, Toy128.N), ch: [32]byte{}})
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("expected too-large, got %v", err)
	}
}

// TestLargeMessageSignsAndVerifies confirms messages far larger than one hash
// block are handled correctly.
func TestLargeMessageSignsAndVerifies(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	msg := make([]byte, 256*1024)
	for i := range msg {
		msg[i] = byte(i)
	}
	sig, err := Sign(kp.Secret, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(kp.Public, msg, sig); err != nil {
		t.Fatal(err)
	}
}
