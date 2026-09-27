package lattice

import (
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	pk, sk, err := KeyGenFromSeed([]byte("deterministic-seed-0123456789abcdef"), nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello lattice world")
	sig, err := sign(sk, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := verify(pk, msg, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSignDeterministic(t *testing.T) {
	_, sk, _ := KeyGenFromSeed([]byte("seed-determinism"), nil)
	msg := make([]byte, 1000)
	for i := range msg {
		msg[i] = byte(i * 7)
	}
	s1, err := sign(sk, msg)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := sign(sk, msg)
	if err != nil {
		t.Fatal(err)
	}
	if s1.ch != s2.ch || s1.mu0 != s2.mu0 {
		t.Fatal("challenge/mu differ across repeated signing")
	}
	for j := range s1.z {
		for i := range s1.z[j] {
			if s1.z[j][i] != s2.z[j][i] {
				t.Fatalf("z differs at (%d,%d)", j, i)
			}
		}
	}
}

func TestWrongMessageRejected(t *testing.T) {
	pk, sk, _ := KeyGenFromSeed([]byte("seed-tamper"), nil)
	sig, err := sign(sk, []byte("original message"))
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(pk, []byte("original message."), sig); err == nil {
		t.Fatal("expected rejection for altered message")
	}
}

func TestTamperZRejected(t *testing.T) {
	pk, sk, _ := KeyGenFromSeed([]byte("seed-tamper2"), nil)
	sig, err := sign(sk, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	sig.z[0][0] = modQ(int64(sig.z[0][0]) + 1)
	if err := verify(pk, []byte("payload"), sig); err == nil {
		t.Fatal("expected rejection for tampered z")
	}
}

func TestTamperPubkeyRejected(t *testing.T) {
	pk, sk, _ := KeyGenFromSeed([]byte("seed-tamper3"), nil)
	sig, err := sign(sk, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	pk.t[0][0] = modQ(int64(pk.t[0][0]) + 1)
	if err := verify(pk, []byte("payload"), sig); err == nil {
		t.Fatal("expected rejection for tampered public key")
	}
}

func TestKeyGenDeterministic(t *testing.T) {
	pk1, sk1, _ := KeyGenFromSeed([]byte("same-seed"), nil)
	pk2, sk2, _ := KeyGenFromSeed([]byte("same-seed"), nil)
	if pk1.rho != pk2.rho {
		t.Fatal("rho mismatch")
	}
	for i := range pk1.t {
		for j := range pk1.t[i] {
			if pk1.t[i][j] != pk2.t[i][j] {
				t.Fatalf("pk t mismatch %d,%d", i, j)
			}
		}
	}
	if sk1.s1 != sk2.s1 {
		t.Fatal("sk s1 mismatch")
	}
	// 不同种子必须产生不同密钥
	pk3, _, _ := KeyGenFromSeed([]byte("different-seed"), nil)
	if pk3.rho == pk1.rho {
		t.Fatal("different seeds produced same rho")
	}
}
