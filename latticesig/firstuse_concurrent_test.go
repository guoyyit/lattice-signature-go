package latticesig

import (
	"fmt"
	"sync"
	"testing"
)

func mustBytes(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

// Every test in this file restores keys/signatures directly from serialized
// bytes and immediately fans out concurrent goroutines. There is intentionally
// no warm-up call of any kind between unmarshalling and first use: these tests
// exist to exercise the *first* concurrent use, which used to lazily write to
// shared cached state. They are meaningful under `go test -race`.

const firstUseGoroutines = 64

func serialVerdict(t *testing.T, pk *PublicKey, msg []byte, sig *Signature) error {
	t.Helper()
	return Verify(pk, msg, sig)
}

// TestFirstUseConcurrentSameSignature verifies the same signature with the
// same freshly restored public key from many goroutines at once.
func TestFirstUseConcurrentSameSignature(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	msg := []byte("first-use same signature")
	sig, err := Sign(kp.Secret, msg)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := UnmarshalPublicKey(mustBytes(kp.Public.MarshalBinary()))
	if err != nil {
		t.Fatal(err)
	}

	want := serialVerdict(t, kp.Public, msg, sig) // reference: live key

	errs := make([]error, firstUseGoroutines)
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(firstUseGoroutines)
	for i := 0; i < firstUseGoroutines; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = Verify(pk, msg, sig)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, got := range errs {
		if (got == nil) != (want == nil) {
			t.Fatalf("goroutine %d verdict %v differs from serial %v", i, got, want)
		}
	}
}

// TestFirstUseConcurrentDifferentSignatures mixes valid signatures for
// different messages with one invalid pair, all verified against one freshly
// restored key with no prior call.
func TestFirstUseConcurrentDifferentSignatures(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)

	type job struct {
		msg []byte
		sig *Signature
		ok  bool
	}
	const jobs = firstUseGoroutines
	work := make([]job, jobs)
	for i := range work {
		msg := []byte(fmt.Sprintf("first-use distinct %d", i))
		sig, err := Sign(kp.Secret, msg)
		if err != nil {
			t.Fatal(err)
		}
		work[i] = job{msg: msg, sig: sig, ok: true}
	}
	// Inject an invalid (wrong-message) job at a fixed position.
	badSig, _ := Sign(kp.Secret, []byte("real message"))
	work[jobs-1] = job{msg: []byte("different message"), sig: badSig, ok: false}

	pk, err := UnmarshalPublicKey(mustBytes(kp.Public.MarshalBinary()))
	if err != nil {
		t.Fatal(err)
	}

	got := make([]bool, jobs)
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(jobs)
	for i := 0; i < jobs; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			got[i] = Verify(pk, work[i].msg, work[i].sig) == nil
		}(i)
	}
	close(start)
	wg.Wait()

	for i := range work {
		if got[i] != work[i].ok {
			t.Fatalf("job %d: got valid=%v want valid=%v", i, got[i], work[i].ok)
		}
	}
}

// TestFirstUseMultipleRestoredInstances restores several independent public
// keys (different key material) and lets goroutines race each instance's first
// verification simultaneously.
func TestFirstUseMultipleRestoredInstances(t *testing.T) {
	const instances = 8
	type fixture struct {
		pk  *PublicKey
		msg []byte
		sig *Signature
	}
	fixtures := make([]fixture, instances)
	for i := range fixtures {
		seed := make([]byte, 32)
		for b := range seed {
			seed[b] = byte(0x10*i + b)
		}
		kp, err := GenerateKey(seed, Toy128)
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte(fmt.Sprintf("instance %d message", i))
		sig, err := Sign(kp.Secret, msg)
		if err != nil {
			t.Fatal(err)
		}
		pk, err := UnmarshalPublicKey(mustBytes(kp.Public.MarshalBinary()))
		if err != nil {
			t.Fatal(err)
		}
		fixtures[i] = fixture{pk: pk, msg: msg, sig: sig}
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	errCh := make(chan error, instances*8)
	for _, f := range fixtures {
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func(f fixture) {
				defer wg.Done()
				<-start
				if err := Verify(f.pk, f.msg, f.sig); err != nil {
					errCh <- err
				}
			}(f)
		}
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("freshly restored instance rejected a valid signature: %v", err)
	}
}

// TestFirstUseConcurrentVerifyEncoded verifies fixed signature bytes directly
// (VerifyEncoded), so decoding and verification of the restored key all happen
// concurrently on first use.
func TestFirstUseConcurrentVerifyEncoded(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	msg := []byte("verify encoded on first use")
	sig, err := Sign(kp.Secret, msg)
	if err != nil {
		t.Fatal(err)
	}
	sigB, err := sig.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := UnmarshalPublicKey(mustBytes(kp.Public.MarshalBinary()))
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(firstUseGoroutines)
	for i := 0; i < firstUseGoroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			blob := make([]byte, len(sigB))
			copy(blob, sigB) // each goroutine owns its own slice copy
			if err := VerifyEncoded(pk, msg, blob); err != nil {
				t.Errorf("concurrent VerifyEncoded failed: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
}

// TestFirstUseConcurrentSignAndVerify restores a secret key from bytes and,
// with no prior call, concurrently signs new messages and verifies them with
// the key restored alongside it.
func TestFirstUseConcurrentSignAndVerify(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)
	sk, err := UnmarshalSecretKey(mustBytes(kp.Secret.MarshalBinary()))
	if err != nil {
		t.Fatal(err)
	}
	pk, err := UnmarshalPublicKey(mustBytes(kp.Public.MarshalBinary()))
	if err != nil {
		t.Fatal(err)
	}

	// A stable signature produced independently, to keep verification traffic
	// flowing while signers hit the restored secret key's first use.
	steadyMsg := []byte("steady background verification")
	steadySig, err := Sign(kp.Secret, steadyMsg)
	if err != nil {
		t.Fatal(err)
	}

	const signers = 24
	const verifiers = 40
	var wg sync.WaitGroup
	start := make(chan struct{})

	// Signers: restored SK first use happens concurrently with everything
	// else. Each distinct message is signed once; signing is deterministic and
	// uses only read-only key state.
	signErr := make([]error, signers)
	signed := make([][]byte, signers)
	for i := 0; i < signers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			msg := []byte(fmt.Sprintf("concurrent first-use sign %d", i))
			sig, err := Sign(sk, msg)
			if err == nil {
				signed[i], err = sig.MarshalBinary()
			}
			signErr[i] = err
		}(i)
	}

	// Verifiers on the freshly restored PK: half steady, half chase the
	// signatures produced by the signers once they land.
	wg.Add(verifiers)
	for i := 0; i < verifiers; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			if err := Verify(pk, steadyMsg, steadySig); err != nil {
				t.Errorf("steady verify failed: %v", err)
			}
		}(i)
	}

	close(start)
	wg.Wait()

	for i, err := range signErr {
		if err != nil {
			t.Fatalf("concurrent sign %d failed: %v", i, err)
		}
	}
	// Determinism: signatures produced under the concurrent first use must
	// equal the serial reference output for the same messages.
	for i := range signed {
		msg := []byte(fmt.Sprintf("concurrent first-use sign %d", i))
		ref, err := Sign(kp.Secret, msg)
		if err != nil {
			t.Fatal(err)
		}
		refB, _ := ref.MarshalBinary()
		if string(refB) != string(signed[i]) {
			t.Fatalf("concurrent signature %d differs from serial reference", i)
		}
		if err := VerifyEncoded(pk, msg, signed[i]); err != nil {
			t.Fatalf("concurrently produced signature %d does not verify: %v", i, err)
		}
	}
}

// TestFirstUseSerialAndConcurrentAgree runs the same workload serially and
// concurrently and requires identical pass/fail outcomes.
func TestFirstUseSerialAndConcurrentAgree(t *testing.T) {
	kp, _ := GenerateKey(testSeed(), Toy128)

	type check struct {
		msg []byte
		sig *Signature
		ok  bool
	}
	const n = 32
	mk := func() []check {
		out := make([]check, n)
		for i := range out {
			msg := []byte(fmt.Sprintf("agree %d", i))
			sig, _ := Sign(kp.Secret, msg)
			out[i] = check{msg: msg, sig: sig, ok: true}
		}
		bad, _ := Sign(kp.Secret, []byte("agree-bad"))
		out[7] = check{msg: []byte("agree other"), sig: bad, ok: false}
		return out
	}

	run := func(pk *PublicKey, work []check) []bool {
		results := make([]bool, len(work))
		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(len(work))
		for i := range work {
			go func(i int) {
				defer wg.Done()
				<-start
				results[i] = Verify(pk, work[i].msg, work[i].sig) == nil
			}(i)
		}
		close(start)
		wg.Wait()
		return results
	}

	pkSerial, err := UnmarshalPublicKey(mustBytes(kp.Public.MarshalBinary()))
	if err != nil {
		t.Fatal(err)
	}
	work := mk()
	var serial []bool
	for i := range work {
		serial = append(serial, Verify(pkSerial, work[i].msg, work[i].sig) == nil)
	}

	pkConcurrent, err := UnmarshalPublicKey(mustBytes(kp.Public.MarshalBinary()))
	if err != nil {
		t.Fatal(err)
	}
	concurrent := run(pkConcurrent, mk())

	for i := range serial {
		if serial[i] != concurrent[i] || serial[i] != work[i].ok {
			t.Fatalf("case %d: serial=%v concurrent=%v expected=%v", i, serial[i], concurrent[i], work[i].ok)
		}
	}
}
