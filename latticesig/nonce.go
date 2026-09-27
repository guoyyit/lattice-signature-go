package latticesig

import "sync"

// ErrNonceReuse indicates that a signing mask was derived for a message while
// the same mask had already been used for a different message. Reusing a
// Schnorr-like mask across distinct messages is the classical path to secret
// recovery; deterministic derivation removes it by construction, and the
// stateful Signer additionally detects any such collision at runtime.
var ErrNonceReuse = newNonceReuseErr()

type nonceReuseErr struct{}

func newNonceReuseErr() error { return &nonceReuseErr{} }
func (e *nonceReuseErr) Error() string {
	return "latticesig: signing nonce (mask) reuse detected across different messages"
}

// nonceGuard records which accepted masks have been seen and the message
// digest for which each one was used.
type nonceGuard struct {
	mu      sync.Mutex
	maskFor map[[32]byte][32]byte // mask digest -> message digest
}

func newNonceGuard() *nonceGuard {
	return &nonceGuard{maskFor: map[[32]byte][32]byte{}}
}

// observe returns ok=false only when the same mask digest was previously seen
// for a different message. Re-signing the identical message is allowed.
func (g *nonceGuard) observe(maskDigest, msgDigest [32]byte) (ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if prior, exists := g.maskFor[maskDigest]; exists && prior != msgDigest {
		return false
	}
	g.maskFor[maskDigest] = msgDigest
	return true
}

// Signer is an optional stateful, concurrency-safe signing handle. In addition
// to the determinism guarantee of the stateless API, it maintains a live
// nonce-reuse detector for defense in depth.
type Signer struct {
	sk    *SecretKey
	guard *nonceGuard
	mu    sync.Mutex
}

func NewSigner(sk *SecretKey) *Signer {
	return &Signer{sk: sk, guard: newNonceGuard()}
}

func (s *Signer) Sign(message []byte) (*Signature, error) {
	// Serialize signers using one handle: deterministic randomness makes
	// parallel calls safe, and the lock also guards the reuse table.
	s.mu.Lock()
	defer s.mu.Unlock()
	sig, usedMask, err := signWithMeta(s.sk, message)
	if err != nil {
		return nil, err
	}
	msgDigest := h256(0x05, message)
	if !s.guard.observe(usedMask, msgDigest) {
		return nil, &nonceReuseErr{}
	}
	return sig, nil
}
