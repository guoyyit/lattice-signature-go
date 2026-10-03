package latticesig

import (
	"encoding/hex"
	"errors"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

// TestLegacyV0VectorsParse loads the three frozen v0 blobs and requires each
// to decode successfully against its own kind.
func TestLegacyV0VectorsParse(t *testing.T) {
	pubB := mustHex(t, legacyV0PublicKeyHex)
	skB := mustHex(t, legacyV0SecretKeyHex)
	sigB := mustHex(t, legacyV0SignatureHex)

	if pubB[5] != 0 {
		t.Fatalf("fixture is not v0: byte5=%d", pubB[5])
	}

	pk, err := UnmarshalPublicKey(pubB)
	if err != nil {
		t.Fatalf("legacy v0 public key rejected: %v", err)
	}
	sk, err := UnmarshalSecretKey(skB)
	if err != nil {
		t.Fatalf("legacy v0 secret key rejected: %v", err)
	}
	sig, err := UnmarshalSignature(sigB)
	if err != nil {
		t.Fatalf("legacy v0 signature rejected: %v", err)
	}
	if pk.Params().Name != Toy128.Name {
		t.Fatalf("params = %q, want toy128", pk.Params().Name)
	}
	if len(sig.z) != Toy128.N {
		t.Fatalf("z length = %d, want %d", len(sig.z), Toy128.N)
	}

	// The restored secret key must be cryptographically linked to the
	// restored public key: signing with it must verify against the restored
	// public key, and must match key generation from the embedded seed.
	live, err := GenerateKey(mustHex(t, legacyV0SeedHex), Toy128)
	if err != nil {
		t.Fatal(err)
	}
	if !polyEqual(live.Public.t, pk.t) {
		t.Fatal("legacy v0 public key t does not match key derived from seed")
	}
	if !polyEqual(live.Secret.s, sk.s) {
		t.Fatal("legacy v0 secret s does not match key derived from seed")
	}
}

// TestLegacyV0SignatureVerifiesAndRejectsTamper covers the historical
// signature: valid message accepted, altered message rejected.
func TestLegacyV0SignatureVerifiesAndRejectsTamper(t *testing.T) {
	pk, err := UnmarshalPublicKey(mustHex(t, legacyV0PublicKeyHex))
	if err != nil {
		t.Fatal(err)
	}
	sigB := mustHex(t, legacyV0SignatureHex)
	msg := mustHex(t, legacyV0MessageHex)
	tampered := mustHex(t, legacyV0TamperedMessageHex)

	if err := VerifyEncoded(pk, msg, sigB); err != nil {
		t.Fatalf("legacy v0 signature rejected for correct message: %v", err)
	}
	if err := VerifyEncoded(pk, tampered, sigB); err == nil {
		t.Fatal("legacy v0 signature accepted for tampered message")
	} else if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered message: expected ErrInvalidSignature, got %v", err)
	}

	// Same result through the decoded in-memory signature.
	sig, err := UnmarshalSignature(sigB)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pk, msg, sig); err != nil {
		t.Fatalf("decoded legacy signature verify: %v", err)
	}
	if err := Verify(pk, tampered, sig); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("decoded tamper: %v", err)
	}
}

// TestCrossVersionInterop proves full bidirectional interoperability:
//   - legacy v0 public key + current (v1) signature verifies;
//   - current (v1) public key + legacy v0 signature verifies;
//   - a key pair restored from the legacy v0 secret key signs fresh
//     signatures that verify under the legacy v0 public key.
func TestCrossVersionInterop(t *testing.T) {
	msg := mustHex(t, legacyV0MessageHex)

	legacyPub, err := UnmarshalPublicKey(mustHex(t, legacyV0PublicKeyHex))
	if err != nil {
		t.Fatal(err)
	}
	legacySig, err := UnmarshalSignature(mustHex(t, legacyV0SignatureHex))
	if err != nil {
		t.Fatal(err)
	}
	legacySK, err := UnmarshalSecretKey(mustHex(t, legacyV0SecretKeyHex))
	if err != nil {
		t.Fatal(err)
	}

	// Current (v1) public key is produced by the live writer for the same
	// key material, so v0/v1 blobs describe the same mathematical key.
	live, err := GenerateKey(mustHex(t, legacyV0SeedHex), Toy128)
	if err != nil {
		t.Fatal(err)
	}
	currentPubB, err := live.Public.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if currentPubB[5] != payloadVersion {
		t.Fatalf("current writer version = %d, want %d", currentPubB[5], payloadVersion)
	}
	currentPub, err := UnmarshalPublicKey(currentPubB)
	if err != nil {
		t.Fatal(err)
	}

	// v1 signature verified against v0 public key.
	currentSig, err := Sign(live.Secret, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(legacyPub, msg, currentSig); err != nil {
		t.Fatalf("v1 signature / v0 public key: %v", err)
	}

	// v0 signature verified against v1 public key (both encoded and decoded
	// verification paths).
	if err := Verify(currentPub, msg, legacySig); err != nil {
		t.Fatalf("v0 signature / v1 public key: %v", err)
	}
	legacySigB := mustHex(t, legacyV0SignatureHex)
	if err := VerifyEncoded(currentPub, msg, legacySigB); err != nil {
		t.Fatalf("v0 encoded signature / v1 public key: %v", err)
	}

	// A restored v0 secret key produces signatures that verify, and they are
	// identical to what the live deterministic signer produces.
	fresh, err := Sign(legacySK, msg)
	if err != nil {
		t.Fatalf("signing with restored v0 secret key: %v", err)
	}
	if !polyEqual(fresh.z, currentSig.z) || fresh.ch != currentSig.ch {
		t.Fatal("restored v0 secret key is not deterministic/canonical")
	}
	if err := Verify(legacyPub, msg, fresh); err != nil {
		t.Fatalf("restored-key signature rejected by legacy public key: %v", err)
	}
	if err := Verify(currentPub, msg, fresh); err != nil {
		t.Fatalf("restored-key signature rejected by current public key: %v", err)
	}
}

// TestLegacyV0LayoutDiffersFromV1 is a structural guard ensuring v0 is a real
// distinct format, not merely a different version byte on the v1 payload.
func TestLegacyV0LayoutDiffersFromV1(t *testing.T) {
	v0Pub := mustHex(t, legacyV0PublicKeyHex)
	v0Sig := mustHex(t, legacyV0SignatureHex)

	live, err := GenerateKey(mustHex(t, legacyV0SeedHex), Toy128)
	if err != nil {
		t.Fatal(err)
	}
	v1Pub, err := live.Public.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	currentSignature, err := Sign(live.Secret, mustHex(t, legacyV0MessageHex))
	if err != nil {
		t.Fatal(err)
	}
	v1Sig, err := currentSignature.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}

	v0PubPayload := v0Pub[headerLen : len(v0Pub)-checksumLen]
	v1PubPayload := v1Pub[headerLen : len(v1Pub)-checksumLen]
	// v0 public key: first 32 payload bytes are the un-prefixed seed, then
	// little-endian coefficients; v1 starts with a length prefix and uses
	// big-endian signed coefficients, so payloads must differ as well.
	if string(v0PubPayload[:legacyV0SeedLen]) != string(live.Public.aSeed) {
		t.Fatal("v0 public-key payload does not start with raw aSeed")
	}
	// v1 public key: payload starts with a uint16 length prefix.
	if be16(v1PubPayload) != uint16(len(live.Public.aSeed)) {
		t.Fatal("v1 public-key payload missing length prefix")
	}
	if equalIgnoringVersion(v0Pub, v1Pub) {
		t.Fatal("legacy v0 public-key bytes identical to v1 apart from version")
	}

	// v0 signature: z precedes ch; v1 signature: ch precedes z. The 32-byte
	// challenge seed therefore sits at different offsets.
	v0SigPayload := v0Sig[headerLen : len(v0Sig)-checksumLen]
	v1SigPayload := v1Sig[headerLen : len(v1Sig)-checksumLen]
	var ch [32]byte
	copy(ch[:], v1SigPayload[:32])
	if string(v0SigPayload[len(v0SigPayload)-32:]) != string(ch[:]) {
		t.Fatal("v0 signature payload does not place ch last")
	}
	if string(v1SigPayload[:32]) == string(v0SigPayload[:32]) {
		t.Fatal("signature layouts unexpectedly identical")
	}
}

// equalIgnoringVersion reports whether two blobs are byte-identical once the
// version byte is masked out.
func equalIgnoringVersion(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if i == 5 {
			continue
		}
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
