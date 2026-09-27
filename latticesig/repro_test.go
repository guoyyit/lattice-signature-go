package latticesig

import (
	"bytes"
	"testing"
)

func testSeed() []byte { return bytes.Repeat([]byte{0x77}, 32) }

func TestDeterministicKeyGen(t *testing.T) {
	p := Toy128
	k1, err := GenerateKey(testSeed(), p)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := GenerateKey(testSeed(), p)
	if err != nil {
		t.Fatal(err)
	}
	if !polyEqual(k1.Public.t, k2.Public.t) {
		t.Fatal("public key t differs for identical seed")
	}
	if !polyEqual(k1.Secret.s, k2.Secret.s) {
		t.Fatal("secret s differs for identical seed")
	}
	if !bytes.Equal(k1.Public.aSeed, k2.Public.aSeed) {
		t.Fatal("aSeed differs for identical seed")
	}
	// different seed -> different key (overwhelmingly likely)
	other, err := GenerateKey(bytes.Repeat([]byte{0x01}, 32), p)
	if err != nil {
		t.Fatal(err)
	}
	if polyEqual(k1.Public.t, other.Public.t) {
		t.Fatal("distinct seeds produced identical public keys")
	}
}

func TestDeterministicSign(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	msg := []byte("the quick brown fox")
	s1, err := Sign(kp.Secret, msg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		s2, err := Sign(kp.Secret, msg)
		if err != nil {
			t.Fatal(err)
		}
		if !polyEqual(s1.z, s2.z) || s1.ch != s2.ch {
			t.Fatalf("signature differs across repeated sign at iteration %d", i)
		}
		if err := Verify(kp.Public, msg, s2); err != nil {
			t.Fatalf("verify failed on repeat %d: %v", i, err)
		}
	}
	// different message -> (overwhelmingly) different signature
	other, err := Sign(kp.Secret, []byte("different message"))
	if err != nil {
		t.Fatal(err)
	}
	if polyEqual(s1.z, other.z) && s1.ch == other.ch {
		t.Fatal("different messages produced identical signatures")
	}
}

func TestKeySerializationRoundTrip(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)

	pubB, err := kp.Public.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	pub2, err := UnmarshalPublicKey(pubB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub2.aSeed, kp.Public.aSeed) || !polyEqual(pub2.t, kp.Public.t) {
		t.Fatal("public key round trip mismatch")
	}

	skB, err := kp.Secret.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	sk2, err := UnmarshalSecretKey(skB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sk2.seed, kp.Secret.seed) || !polyEqual(sk2.s, kp.Secret.s) {
		t.Fatal("secret key round trip mismatch")
	}

	// A restored secret key must still sign and verify.
	msg := []byte("after restart")
	sig, err := Sign(sk2, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub2, msg, sig); err != nil {
		t.Fatalf("verify with restored keys failed: %v", err)
	}
	// restored secret produces the same signature as the original
	sigOrig, _ := Sign(kp.Secret, msg)
	if !polyEqual(sig.z, sigOrig.z) || sig.ch != sigOrig.ch {
		t.Fatal("restored key did not reproduce signature")
	}
}

func TestSignatureSerializationRoundTrip(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	msg := []byte("serialize me")
	sig, _ := Sign(kp.Secret, msg)
	b, err := sig.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := UnmarshalSignature(b)
	if err != nil {
		t.Fatal(err)
	}
	if !polyEqual(sig.z, sig2.z) || sig.ch != sig2.ch {
		t.Fatal("signature round trip mismatch")
	}
	if err := Verify(kp.Public, msg, sig2); err != nil {
		t.Fatalf("verify after decode failed: %v", err)
	}
	if err := VerifyEncoded(kp.Public, msg, b); err != nil {
		t.Fatalf("VerifyEncoded failed: %v", err)
	}
}
