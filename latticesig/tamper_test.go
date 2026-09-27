package latticesig

import (
	"errors"
	"testing"
)

// flipEveryBit mutates each bit of every byte and requires fn to reject it.
func flipEveryBit(t *testing.T, name string, blob []byte, fn func([]byte) error) {
	t.Helper()
	original := make([]byte, len(blob))
	copy(original, blob)
	for i := 0; i < len(blob); i++ {
		for bit := uint(0); bit < 8; bit++ {
			copy(blob, original)
			blob[i] ^= 1 << bit
			if err := fn(blob); err == nil {
				t.Fatalf("%s: mutation byte %d bit %d was accepted", name, i, bit)
			}
		}
	}
	copy(blob, original)
}

func TestSingleBitTamperSignature(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	msg := []byte("tamper target")
	sig, _ := Sign(kp.Secret, msg)
	b, _ := sig.MarshalBinary()

	flipEveryBit(t, "sig", b, func(mut []byte) error {
		return VerifyEncoded(kp.Public, msg, mut)
	})
}

func TestSingleBitTamperPublicKey(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	msg := []byte("tamper pubkey target")
	sig, _ := Sign(kp.Secret, msg)
	sigB, _ := sig.MarshalBinary()
	pubB, _ := kp.Public.MarshalBinary()

	flipEveryBit(t, "pub", pubB, func(mut []byte) error {
		pk, err := UnmarshalPublicKey(mut)
		if err != nil {
			return err // checksum/structural rejection
		}
		return VerifyEncoded(pk, msg, sigB)
	})
}

func TestWrongMessageRejected(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	sig, _ := Sign(kp.Secret, []byte("original"))
	if err := Verify(kp.Public, []byte("forged"), sig); err == nil {
		t.Fatal("signature verified under wrong message")
	}
}

func TestWrongKeyRejected(t *testing.T) {
	kp1, _ := GenerateKey(testSeed(), Toy128)
	kp2, _ := GenerateKey([]byte("0000000000000000different-seed-32b!"), Toy128)
	sig, _ := Sign(kp1.Secret, []byte("m"))
	err := Verify(kp2.Public, []byte("m"), sig)
	if err == nil {
		t.Fatal("signature verified under wrong key")
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestVerifyErrorIs(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	sig, _ := Sign(kp.Secret, []byte("m"))
	err := Verify(kp.Public, []byte("n"), sig)
	if err == nil {
		t.Fatal("expected failure")
	}
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *VerifyError, got %T %v", err, err)
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected Is(ErrInvalidSignature), got %v", err)
	}
}
