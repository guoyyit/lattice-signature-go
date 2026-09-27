package latticesig_test

import (
	"errors"
	"fmt"

	"github.com/guoyyit/lattice-signature-go/latticesig"
)

// A fixed seed keeps the example output reproducible. Real code should use
// crypto/rand for the seed.
func Example() {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	kp, err := latticesig.GenerateKey(seed, latticesig.Toy128)
	if err != nil {
		panic(err)
	}

	msg := []byte("pay Alice 5 coins")
	sig, err := latticesig.Sign(kp.Secret, msg)
	if err != nil {
		panic(err)
	}

	// Deterministic: signing again yields an identical signature.
	sig2, _ := latticesig.Sign(kp.Secret, msg)
	b1, _ := sig.MarshalBinary()
	b2, _ := sig2.MarshalBinary()
	fmt.Println("deterministic:", bytesEqual(b1, b2))

	// Verification passes on the unmodified tuple.
	fmt.Println("verify:", errName(latticesig.Verify(kp.Public, msg, sig)))

	// Tampering with the message is rejected with ErrInvalidSignature.
	fmt.Println("tampered:", errName(latticesig.Verify(kp.Public, []byte("pay Bob 500"), sig)))

	// Round-trip through serialized, versioned encoding.
	pk, _ := latticesig.UnmarshalPublicKey(must(kp.Public.MarshalBinary()))
	sigBlob, _ := sig.MarshalBinary()
	fmt.Println("encoded verify:", errName(latticesig.VerifyEncoded(pk, msg, sigBlob)))

	// Output:
	// deterministic: true
	// verify: <nil>
	// tampered: invalid signature
	// encoded verify: <nil>
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func errName(err error) string {
	switch {
	case err == nil:
		return "<nil>"
	case errors.Is(err, latticesig.ErrInvalidSignature):
		return "invalid signature"
	default:
		return err.Error()
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}
