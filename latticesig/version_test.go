package latticesig

import (
	"crypto/sha256"
	"errors"
	"testing"
)

// fixChecksum rewrites the trailing 4 checksum bytes after a header/payload
// mutation (e.g. version bump).
func fixChecksum(b []byte) {
	plen := int(be32(b[8:]))
	sum := sha256.Sum256(b[:headerLen+plen])
	copy(b[headerLen+plen:], sum[:checksumLen])
}

func TestUnknownVersionRejected(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	sig, _ := Sign(kp.Secret, []byte("v"))
	b, _ := sig.MarshalBinary()

	corrupt := make([]byte, len(b))
	copy(corrupt, b)
	corrupt[5] = payloadVersion + 1
	fixChecksum(corrupt)
	if _, err := UnmarshalSignature(corrupt); !errors.Is(err, ErrNewerVersion) {
		t.Fatalf("expected ErrNewerVersion, got %v", err)
	}
	if _, err := UnmarshalSignature(corrupt); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("expected alias ErrUnknownVersion, got %v", err)
	}

	copy(corrupt, b)
	corrupt[5] = 0xFF // signed -1: older than the oldest supported version
	fixChecksum(corrupt)
	if _, err := UnmarshalSignature(corrupt); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion, got %v", err)
	}
}

func TestCurrentVersionAccepted(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	sig, _ := Sign(kp.Secret, []byte("v"))
	b, _ := sig.MarshalBinary()
	if b[5] != payloadVersion {
		t.Fatalf("unexpected payload version %d", b[5])
	}
	if err := VerifyEncoded(kp.Public, []byte("v"), b); err != nil {
		t.Fatalf("current version rejected: %v", err)
	}
}

func TestUnknownParamsRejected(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	sig, _ := Sign(kp.Secret, []byte("v"))
	b, _ := sig.MarshalBinary()
	corrupt := make([]byte, len(b))
	copy(corrupt, b)
	// point the param id at an unallocated value
	corrupt[6] = 0x7F
	corrupt[7] = 0xFF
	fixChecksum(corrupt)
	if _, err := UnmarshalSignature(corrupt); !errors.Is(err, ErrUnsupportedParams) {
		t.Fatalf("expected ErrUnsupportedParams, got %v", err)
	}
}

func TestWrongKindRejected(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	pubB, _ := kp.Public.MarshalBinary()
	if _, err := UnmarshalSignature(pubB); !errors.Is(err, ErrMalformedEncoding) {
		t.Fatalf("expected malformed for wrong kind, got %v", err)
	}
}

func TestTruncatedAndGarbage(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	msg := []byte("m")
	sig, _ := Sign(kp.Secret, msg)
	b, _ := sig.MarshalBinary()

	badMagic := make([]byte, len(b))
	copy(badMagic, b)
	badMagic[0] = 'X'

	cases := map[string][]byte{
		"nil":         nil,
		"empty":       {},
		"short":       b[:headerLen],
		"garbage":     []byte("this is definitely not a signature blob at all!!!"),
		"missing-crc": b[:len(b)-1],
		"bad-magic":   badMagic,
		"trailing":    append(append([]byte{}, b...), 0x00),
	}
	for name, bad := range cases {
		if _, err := UnmarshalSignature(bad); err == nil {
			t.Fatalf("%s: expected decode error", name)
		}
		if err := VerifyEncoded(kp.Public, msg, bad); err == nil {
			t.Fatalf("%s: expected verify error", name)
		}
	}
}

func TestOversizedMessageRejected(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	big := make([]byte, Toy128.MaxMsg+1)
	if _, err := Sign(kp.Secret, big); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("sign: expected ErrMessageTooLarge, got %v", err)
	}
	sig, err := Sign(kp.Secret, []byte("small"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(kp.Public, big, sig); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("verify: expected ErrMessageTooLarge, got %v", err)
	}
}

func TestBadSeedAndNilInputs(t *testing.T) {
	if _, err := GenerateKey(nil, Toy128); !errors.Is(err, ErrMalformedEncoding) {
		t.Fatalf("nil seed: %v", err)
	}
	if _, err := GenerateKey([]byte("short"), Toy128); !errors.Is(err, ErrMalformedEncoding) {
		t.Fatalf("short seed: %v", err)
	}
	if _, err := GenerateKey([]byte("1234567890123456"), nil); !errors.Is(err, ErrUnsupportedParams) {
		t.Fatalf("nil params: %v", err)
	}
	if err := Verify(nil, []byte("m"), &Signature{}); err == nil {
		t.Fatal("nil public key should fail")
	}
	if _, err := Sign(nil, []byte("m")); err == nil {
		t.Fatal("nil secret key should fail")
	}
}

// TestEmptyMessageIsValid ensures zero-length input is a legitimate message.
func TestEmptyMessageIsValid(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	sig, err := Sign(kp.Secret, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(kp.Public, nil, sig); err != nil {
		t.Fatalf("empty message verify: %v", err)
	}
}
