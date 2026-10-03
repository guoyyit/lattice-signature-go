package latticesig

import (
	"fmt"
	"sync"
	"testing"
)

// TestRestoredPublicKeyConcurrentVerify is the canonical first-use race: a
// public key recovered from its serialized bytes must be immediately usable by
// any number of goroutines without any warming call. Run with -race.
func TestRestoredPublicKeyConcurrentVerify(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	msg := []byte("first-use concurrency")
	sig, _ := Sign(kp.Secret, msg)

	blob, err := kp.Public.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := UnmarshalPublicKey(blob)
	if err != nil {
		t.Fatal(err)
	}

	const n = 128
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start // all goroutines release simultaneously: no warming call
			errs[i] = Verify(pk, msg, sig)
		}(i)
	}
	close(start)
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("concurrent verify %d failed: %v", i, errs[i])
		}
	}
}

// TestRestoredPublicKeyConcurrentVerifyDifferentMessages verifies many
// distinct messages concurrently on a freshly restored key.
func TestRestoredPublicKeyConcurrentVerifyDifferentMessages(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	const n = 64
	msgs := make([][]byte, n)
	sigs := make([]*Signature, n)
	for i := 0; i < n; i++ {
		msgs[i] = []byte(fmt.Sprintf("msg-%d", i))
		sigs[i], _ = Sign(kp.Secret, msgs[i])
	}

	blob, _ := kp.Public.MarshalBinary()
	pk, err := UnmarshalPublicKey(blob)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = Verify(pk, msgs[i], sigs[i])
		}(i)
	}
	close(start)
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("verify %d failed: %v", i, errs[i])
		}
	}
}

// TestMultipleRestoredInstancesConcurrentFirstVerify recovers several
// instances from serialized bytes and verifies on all of them concurrently.
func TestMultipleRestoredInstancesConcurrentFirstVerify(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	msg := []byte("shared")
	sig, _ := Sign(kp.Secret, msg)
	blob, _ := kp.Public.MarshalBinary()

	const instances = 8
	const perInstance = 16
	pks := make([]*PublicKey, instances)
	for i := 0; i < instances; i++ {
		pk, err := UnmarshalPublicKey(blob)
		if err != nil {
			t.Fatal(err)
		}
		pks[i] = pk
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, instances*perInstance)
	wg.Add(instances * perInstance)
	idx := 0
	for i := 0; i < instances; i++ {
		for j := 0; j < perInstance; j++ {
			go func(slot int, pk *PublicKey) {
				defer wg.Done()
				<-start
				errs[slot] = Verify(pk, msg, sig)
			}(idx, pks[i])
			idx++
		}
	}
	close(start)
	wg.Wait()
	for i := range errs {
		if errs[i] != nil {
			t.Fatalf("verify %d failed: %v", i, errs[i])
		}
	}
}

// TestVerifyEncodedConcurrentOnRestoredKey concurrently verifies serialized
// signature blobs directly (decode + verify) on a restored key.
func TestVerifyEncodedConcurrentOnRestoredKey(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	msg := []byte("encoded")
	sig, _ := Sign(kp.Secret, msg)
	sigBlob, _ := sig.MarshalBinary()
	pubBlob, _ := kp.Public.MarshalBinary()
	pk, err := UnmarshalPublicKey(pubBlob)
	if err != nil {
		t.Fatal(err)
	}

	const n = 64
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = VerifyEncoded(pk, msg, sigBlob)
		}(i)
	}
	close(start)
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("encoded verify %d failed: %v", i, errs[i])
		}
	}
}

// TestRestoredSecretKeySignAndVerifyConcurrent uses a restored secret key for
// signing concurrently with verification on the restored public key.
func TestRestoredSecretKeySignAndVerifyConcurrent(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	skBlob, _ := kp.Secret.MarshalBinary()
	pubBlob, _ := kp.Public.MarshalBinary()
	sk, err := UnmarshalSecretKey(skBlob)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := UnmarshalPublicKey(pubBlob)
	if err != nil {
		t.Fatal(err)
	}

	const n = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, 2*n)
	wg.Add(2 * n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			msg := []byte(fmt.Sprintf("mixed-%d", i))
			sig, err := Sign(sk, msg)
			if err != nil {
				errs[i] = err
				return
			}
			errs[i] = Verify(pk, msg, sig)
		}(i)
		go func(i int) {
			defer wg.Done()
			<-start
			msg := []byte(fmt.Sprintf("mixed-%d", i))
			// verify a signature produced by the original key pair
			sig, _ := Sign(kp.Secret, msg)
			errs[n+i] = Verify(pk, msg, sig)
		}(i)
	}
	close(start)
	wg.Wait()
	for i := range errs {
		if errs[i] != nil {
			t.Fatalf("mixed op %d failed: %v", i, errs[i])
		}
	}
}
