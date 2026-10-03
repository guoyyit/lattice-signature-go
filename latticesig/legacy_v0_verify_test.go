package latticesig

import (
	"bytes"
	"testing"
)

// TestLegacyV0RoundTrip verifies the independent legacy encoder produces v0
// blobs that parse and interoperate with the current v1 code.
func TestLegacyV0RoundTrip(t *testing.T) {
	seed := testSeed()
	p := Toy128
	msg := []byte("legacy interop message")

	a, tPub, s, _ := legacyV0KeyDerivation(seed, p)
	pubV0 := legacyMarshalPublicKeyV0(p, a, tPub)

	// v0 public key parses.
	pk, err := UnmarshalPublicKey(pubV0)
	if err != nil {
		t.Fatalf("unmarshal v0 pub: %v", err)
	}

	// v0 secret key: build embedded v0 pub blob, then v0 secret blob.
	skV0 := legacyMarshalSecretKeyV0(p, seed, s, pubV0)
	sk, err := UnmarshalSecretKey(skV0)
	if err != nil {
		t.Fatalf("unmarshal v0 secret: %v", err)
	}

	// v0 secret key produces a signature that verifies.
	sig, err := Sign(sk, msg)
	if err != nil {
		t.Fatalf("sign with v0 secret: %v", err)
	}
	if err := Verify(pk, msg, sig); err != nil {
		t.Fatalf("verify v0-secret signature: %v", err)
	}

	// v0 signature blob parses and verifies.
	sigV0 := legacyMarshalSignatureV0(p, sig.z, sig.ch)
	if err := VerifyEncoded(pk, msg, sigV0); err != nil {
		t.Fatalf("verify v0 sig blob: %v", err)
	}

	// v0 signature rejects tampered message.
	if err := VerifyEncoded(pk, []byte("tampered"), sigV0); err == nil {
		t.Fatal("v0 signature verified under tampered message")
	}

	// v0 public key + current (v1) signature verifies.
	kp, _ := GenerateKey(seed, p)
	sigV1, _ := Sign(kp.Secret, msg)
	if err := Verify(pk, msg, sigV1); err != nil {
		t.Fatalf("v0 pub + v1 sig: %v", err)
	}

	// current (v1) public key + v0 signature verifies.
	pkV1, _ := UnmarshalPublicKey(mustMarshalPub(t, kp.Public))
	if err := Verify(pkV1, msg, sig); err != nil {
		t.Fatalf("v1 pub + v0 sig (from v0 secret): %v", err)
	}

	// v0 public key cannot be re-marshaled to v1 (no aSeed).
	if _, err := pk.MarshalBinary(); err == nil {
		t.Fatal("v0 pub key should not re-marshal to v1")
	}

	// Determinism: same inputs produce identical v0 blobs.
	pubV0b := legacyMarshalPublicKeyV0(p, a, tPub)
	if !bytes.Equal(pubV0, pubV0b) {
		t.Fatal("v0 pub blob not deterministic")
	}
}

func mustMarshalPub(t *testing.T, pk *PublicKey) []byte {
	t.Helper()
	b, err := pk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
