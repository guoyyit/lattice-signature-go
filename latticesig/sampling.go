package latticesig

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// Deterministic randomness expansion.
//
// Every random quantity used in key generation and signing is the output of a
// keyed hash over a domain-separated label and the relevant inputs. This makes
// the whole scheme reproducible (same seed/params/msg => same result) and
// structurally removes the classic "reused nonce leaks the secret key" path:
// masks are a function of (secret seed, message, attempt counter), so two
// *different* messages always expand to independent masks, while signing the
// *same* message twice legitimately repeats and hence yields an identical
// signature.

const (
	labelSecret byte = 0x01
	labelA      byte = 0x02
	labelMask   byte = 0x03
)

// h256 is a domain-separated SHA-256 over length-prefixed parts. Length
// prefixing makes the encoding injective (no ambiguous concatenations).
func h256(domain byte, parts ...[]byte) [32]byte {
	h := sha256.New()
	var dom [1]byte
	dom[0] = domain
	h.Write(dom[:])
	var lb [4]byte
	for _, part := range parts {
		binary.BigEndian.PutUint32(lb[:], uint32(len(part)))
		h.Write(lb[:])
		h.Write(part)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// hmacStream is a deterministic byte stream: HMAC-SHA256(key, info || counter)
// concatenated over increasing 32-bit counters.
type hmacStream struct {
	key  [32]byte
	info []byte
	buf  []byte
	ctr  uint32
	pos  int
}

func newHMACStream(key [32]byte, info []byte) *hmacStream {
	return &hmacStream{key: key, info: info, ctr: 0, pos: 0}
}

func (s *hmacStream) refill() {
	mac := hmac.New(sha256.New, s.key[:])
	mac.Write(s.info)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], s.ctr)
	mac.Write(c[:])
	s.buf = mac.Sum(s.buf[:0])
	s.ctr++
	s.pos = 0
}

func (s *hmacStream) byte() byte {
	if s.pos >= len(s.buf) {
		s.refill()
	}
	v := s.buf[s.pos]
	s.pos++
	return v
}

// uniformB returns a uniform value in [0, bound) via rejection sampling.
// bound must be <= 65536.
func (s *hmacStream) uniformB(bound int) int {
	if bound <= 1 {
		return 0
	}
	// Use 16-bit draws so rejection is rare even for the largest bound.
	limit := 65536 - (65536 % bound)
	for {
		v := int(binary.BigEndian.Uint16([]byte{s.byte(), s.byte()}))
		if v < limit {
			return v % bound
		}
	}
}

// deriveMask derives y with coefficients uniform in [-Eta, Eta].
func deriveMask(p *Params, skSeed []byte, msg []byte, attempt uint64) poly {
	var info [1 + 8]byte
	info[0] = labelMask
	binary.BigEndian.PutUint64(info[1:], attempt)
	prk := h256(labelMask, skSeed, msg)
	st := newHMACStream(prk, info[:])
	out := make(poly, p.N)
	bound := 2*p.Eta + 1
	for i := range out {
		out[i] = int32(st.uniformB(bound) - p.Eta)
	}
	return out
}

// sampleTernary derives a uniform ternary polynomial (coeffs in {-1,0,1}).
func sampleTernary(p *Params, seed []byte, label byte) poly {
	prk := h256(label, seed)
	st := newHMACStream(prk, []byte{label, 't', 'e', 'r', 'n'})
	out := make(poly, p.N)
	for i := range out {
		switch st.uniformB(3) {
		case 0:
			out[i] = -1
		case 1:
			out[i] = 0
		default:
			out[i] = 1
		}
	}
	return out
}

// expandA deterministically expands the uniform public ring element a.
func expandA(p *Params, seed []byte) poly {
	prk := h256(labelA, seed)
	st := newHMACStream(prk, []byte{labelA, 'e', 'x', 'p'})
	out := make(poly, p.N)
	for i := range out {
		// Two big-endian bytes give a value in [0,65535]; reject >= bound.
		bound := 65536 - (65536 % p.Q)
		for {
			v := int(binary.BigEndian.Uint16([]byte{st.byte(), st.byte()}))
			if v < bound {
				out[i] = int32(v % p.Q)
				break
			}
		}
	}
	return out
}

// challengeSeed computes the 32-byte challenge seed ch = H(w || message).
// w is encoded canonically as signed int16 coefficients (all params fit).
func challengeSeed(p *Params, w poly, msg []byte) [32]byte {
	enc := make([]byte, 2*p.N)
	for i, v := range w {
		binary.BigEndian.PutUint16(enc[2*i:], uint16(int16(v)))
	}
	return h256(0x04, enc, msg)
}

// expandChallenge turns a challenge seed into a sparse polynomial with exactly
// Tau non-zero coefficients in {-1,+1}, at uniformly chosen distinct indices.
func expandChallenge(p *Params, seed [32]byte) poly {
	st := newHMACStream(seed, []byte{'c', 'h', 'a', 'l'})
	c := make(poly, p.N)
	// Fisher-Yates partial shuffle over indices [0,N).
	idx := make([]int, p.N)
	for i := range idx {
		idx[i] = i
	}
	for i := 0; i < p.Tau; i++ {
		j := i + st.uniformB(p.N-i)
		idx[i], idx[j] = idx[j], idx[i]
		if st.byte()&1 == 0 {
			c[idx[i]] = 1
		} else {
			c[idx[i]] = -1
		}
	}
	return c
}

// hashChallenge returns the sparse challenge c for (w, message).
func hashChallenge(p *Params, w poly, msg []byte) poly {
	return expandChallenge(p, challengeSeed(p, w, msg))
}
