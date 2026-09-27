package lattice

import "testing"

func BenchmarkKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, _, err := KeyGenFromSeed([]byte("bench-seed"), nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignVerify(b *testing.B) {
	pk, sk, _ := KeyGenFromSeed([]byte("bench"), nil)
	msg := []byte("benchmark message")
	b.Run("sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := sign(sk, msg); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("verify", func(b *testing.B) {
		sig, _ := sign(sk, msg)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := verify(pk, msg, sig); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestSignatureSize(t *testing.T) {
	_, sk, _ := KeyGenFromSeed([]byte("size"), nil)
	sig, err := sign(sk, make([]byte, 100))
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := marshalSignature(sig)
	t.Logf("signature encoded size = %d bytes", len(enc))
	pk, _ := marshalPublicKey(sk.publicKey())
	esk, _ := marshalSecretKey(sk)
	t.Logf("public key size = %d bytes; secret key size = %d bytes", len(pk), len(esk))
}
