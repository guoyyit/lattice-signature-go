package latticesig

import (
	"errors"
	"testing"
)

// TestVersionBoundaries exhausts the five distinguished cases required for
// the version field:
//
//   - below the minimum supported version  -> ErrUnsupportedVersion
//   - lowest in-range legacy version (v0)   -> accepted
//   - current version (v1)                  -> accepted
//   - above the current version             -> ErrNewerVersion
//   - version byte tampered (checksum not   -> ErrMalformedEncoding
//     repaired)                             (detected before any version use)
//
// Every concrete version rejection must also match the generic
// ErrUnknownVersion family marker, while malformed/tampered bytes must not.
func TestVersionBoundaries(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	msg := []byte("boundary")
	sig, _ := Sign(kp.Secret, msg)
	current, _ := sig.MarshalBinary()

	mutate := func(ver byte, fixCRC bool) []byte {
		out := make([]byte, len(current))
		copy(out, current)
		out[5] = ver
		if fixCRC {
			fixChecksum(out)
		}
		return out
	}

	t.Run("below minimum rejected as obsolete", func(t *testing.T) {
		// 0xFF is -1 when the version byte is interpreted as signed.
		b := mutate(0xFF, true)
		_, err := UnmarshalSignature(b)
		if !errors.Is(err, ErrUnsupportedVersion) {
			t.Fatalf("want ErrUnsupportedVersion, got %v", err)
		}
		if !errors.Is(err, ErrUnknownVersion) {
			t.Fatalf("obsolete version should also match ErrUnknownVersion, got %v", err)
		}
	})

	t.Run("lowest supported legacy accepted", func(t *testing.T) {
		// A mere byte bump is not a valid v0 payload (different layout), so
		// use the real frozen v0 vector.
		b := mustHex(t, legacyV0SignatureHex)
		if b[5] != minAcceptedVer {
			t.Fatalf("fixture version %d != minimum %d", b[5], minAcceptedVer)
		}
		legacyPub, err := UnmarshalPublicKey(mustHex(t, legacyV0PublicKeyHex))
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyEncoded(legacyPub, mustHex(t, legacyV0MessageHex), b); err != nil {
			t.Fatalf("lowest supported version rejected: %v", err)
		}
	})

	t.Run("current accepted", func(t *testing.T) {
		b := mutate(payloadVersion, true)
		if err := VerifyEncoded(kp.Public, msg, b); err != nil {
			t.Fatalf("current version rejected: %v", err)
		}
	})

	t.Run("above current rejected as newer", func(t *testing.T) {
		b := mutate(payloadVersion+1, true)
		_, err := UnmarshalSignature(b)
		if !errors.Is(err, ErrNewerVersion) {
			t.Fatalf("want ErrNewerVersion, got %v", err)
		}
		if !errors.Is(err, ErrUnknownVersion) {
			t.Fatalf("newer version should also match ErrUnknownVersion, got %v", err)
		}
	})

	t.Run("tampered version byte rejected as malformed", func(t *testing.T) {
		// Flip the byte away from its original value without repairing the
		// checksum; integrity checking must win regardless of target version.
		for _, ver := range []byte{0x00, payloadVersion + 1, 0xFF} {
			b := mutate(ver, false) // leave checksum stale
			_, err := UnmarshalSignature(b)
			if !errors.Is(err, ErrMalformedEncoding) {
				t.Fatalf("ver %d: want ErrMalformedEncoding, got %v", ver, err)
			}
			if errors.Is(err, ErrUnknownVersion) {
				t.Fatalf("ver %d: checksum failure must not look like a version rejection", ver)
			}
		}
	})
}

// TestVersionReasonsAreDistinct ensures obsolete and newer rejections are not
// confused with each other, so callers can react differently.
func TestVersionReasonsAreDistinct(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	sig, _ := Sign(kp.Secret, []byte("distinct"))
	b, _ := sig.MarshalBinary()

	older := append([]byte(nil), b...)
	older[5] = 0xFE // -2 as signed
	fixChecksum(older)
	if _, err := UnmarshalSignature(older); errors.Is(err, ErrNewerVersion) {
		t.Fatalf("obsolete version matched ErrNewerVersion: %v", err)
	}

	newer := append([]byte(nil), b...)
	newer[5] = payloadVersion + 1
	fixChecksum(newer)
	if _, err := UnmarshalSignature(newer); errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("newer version matched ErrUnsupportedVersion: %v", err)
	}
}
