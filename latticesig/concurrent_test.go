package latticesig

import (
	"fmt"
	"sync"
	"testing"
)

func TestConcurrentSignDifferentMessages(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	const n = 64

	var wg sync.WaitGroup
	res := make([][]byte, n) // encoded signatures
	errs := make([]error, n)
	start := make(chan struct{})
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			msg := []byte(fmt.Sprintf("concurrent-message-%d", i))
			sig, err := Sign(kp.Secret, msg)
			if err == nil {
				res[i], err = sig.MarshalBinary()
			}
			errs[i] = err
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("signer %d failed: %v", i, errs[i])
		}
		if err := VerifyEncoded(kp.Public, []byte(fmt.Sprintf("concurrent-message-%d", i)), res[i]); err != nil {
			t.Fatalf("verify %d failed: %v", i, err)
		}
	}

	// Distinct messages must yield distinct signatures (no mask reuse).
	seen := map[string]bool{}
	for i, b := range res {
		if seen[string(b)] {
			t.Fatalf("signature reused for distinct message at %d", i)
		}
		seen[string(b)] = true
	}
}

func TestConcurrentVerify(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	msg := []byte("shared message")
	sig, _ := Sign(kp.Secret, msg)
	var wg sync.WaitGroup
	start := make(chan struct{})
	const n = 128
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			if err := Verify(kp.Public, msg, sig); err != nil {
				t.Errorf("concurrent verify failed: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
}

func TestSignerRepeatedMessageStable(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	signer := NewSigner(kp.Secret)
	msg := []byte("same")
	a, err := signer.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := signer.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !polyEqual(a.z, b.z) || a.ch != b.ch {
		t.Fatal("stateful signer did not reproduce same message")
	}
}

func TestSignerConcurrentNoReuse(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	signer := NewSigner(kp.Secret)
	const n = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			if _, err := signer.Sign([]byte(fmt.Sprintf("m-%d", i))); err != nil {
				t.Errorf("signer %d: %v", i, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
}

func TestNonceReuseDetectorRejectsCrossMessage(t *testing.T) {
	g := newNonceGuard()
	var mask [32]byte
	mask[0] = 0xAA
	msg1 := h256(0x05, []byte("msg1"))
	msg2 := h256(0x05, []byte("msg2"))

	if !g.observe(mask, msg1) {
		t.Fatal("first use should be allowed")
	}
	if !g.observe(mask, msg1) {
		t.Fatal("same message reuse should be allowed")
	}
	if g.observe(mask, msg2) {
		t.Fatal("mask reuse across different messages must be rejected")
	}
}
