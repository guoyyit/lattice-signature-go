package latticesig

import (
	"bytes"
	"testing"
)

func TestSmokeSignVerify(t *testing.T) {
	seed := bytes.Repeat([]byte{0xAB}, 32)
	for _, p := range []*Params{Toy128, Lite256} {
		kp, err := GenerateKey(seed, p)
		if err != nil {
			t.Fatalf("%s: keygen: %v", p.Name, err)
		}
		msg := []byte("hello lattice world")
		sig, err := Sign(kp.Secret, msg)
		if err != nil {
			t.Fatalf("%s: sign: %v", p.Name, err)
		}
		if err := Verify(kp.Public, msg, sig); err != nil {
			t.Fatalf("%s: verify: %v", p.Name, err)
		}
	}
}
