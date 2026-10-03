package latticesig

import "sync"

// MinSeedLen is the minimum accepted master-seed length in bytes.
const MinSeedLen = 16

// PublicKey is the shareable half of a key pair.
type PublicKey struct {
	params *Params
	aSeed  []byte // seed expanding the public ring element a
	t      poly   // t = a*s in R_q

	aOnce  sync.Once // guards lazy expansion of aCache
	aCache poly      // lazily expanded a
}

// SecretKey is the private half. Retaining the master seed makes signing fully
// deterministic and reproducible across restarts.
type SecretKey struct {
	params *Params
	seed   []byte // master seed
	s      poly   // secret ring element
	pub    *PublicKey
}

// KeyPair bundles the two halves.
type KeyPair struct {
	Public *PublicKey
	Secret *SecretKey
}

func (k *PublicKey) Params() *Params { return k.params }
func (k *SecretKey) Params() *Params { return k.params }

func (k *SecretKey) Public() *PublicKey {
	if k == nil {
		return nil
	}
	return k.pub
}

// ringA returns the expanded public ring element, caching it. The first call
// expands a exactly once; concurrent callers block until the expansion is
// complete and then share the result. This makes a restored public key safe for
// immediate concurrent verification with no warming call.
func (k *PublicKey) ringA() poly {
	k.aOnce.Do(func() {
		if k.aCache == nil {
			k.aCache = expandA(k.params, k.aSeed)
		}
	})
	return k.aCache
}

// GenerateKey deterministically derives a key pair from a seed.
//
// The same seed and Params always produce an identical key pair. The seed
// must be at least MinSeedLen bytes of high-entropy material; callers should
// generate it with crypto/rand.
func GenerateKey(seed []byte, p *Params) (*KeyPair, error) {
	if p == nil {
		return nil, ErrUnsupportedParams
	}
	if len(seed) < MinSeedLen {
		return nil, ErrMalformedEncoding
	}
	aSeed := h256(labelA, seed, []byte(p.Name))
	s := sampleTernary(p, seed, labelSecret)
	a := expandA(p, aSeed[:])
	t := polyMulNTT(p, a, s)

	pub := &PublicKey{params: p, aSeed: append([]byte(nil), aSeed[:]...), t: t, aCache: a}
	sk := &SecretKey{
		params: p,
		seed:   append([]byte(nil), seed...),
		s:      s,
		pub:    pub,
	}
	return &KeyPair{Public: pub, Secret: sk}, nil
}
