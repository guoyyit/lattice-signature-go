package latticesig

// Signature is a compact (z, ch) pair: z is the response polynomial and ch the
// 32-byte challenge seed that regenerates the sparse challenge c.
type Signature struct {
	params *Params
	z      poly
	ch     [32]byte
}

func Sign(sk *SecretKey, message []byte) (*Signature, error) {
	sig, _, err := signWithMeta(sk, message)
	return sig, err
}

// signWithMeta additionally returns a digest of the accepted mask y. It lets a
// stateful Signer explicitly detect any reuse of a mask across different
// messages (a leak precondition). Deterministic design already prevents it.
func signWithMeta(sk *SecretKey, message []byte) (*Signature, [32]byte, error) {
	var zero [32]byte
	if sk == nil || sk.pub == nil || sk.params == nil {
		return nil, zero, ErrMalformedEncoding
	}
	p := sk.params
	if len(message) > p.MaxMsg {
		return nil, zero, ErrMessageTooLarge
	}

	// Bound the work: a pathological parameter choice must never loop
	// forever. Deterministic derivation retries with increasing counters.
	for attempt := uint64(0); attempt < uint64(p.MaxIters); attempt++ {
		y := deriveMask(p, sk.seed, message, attempt)
		w := polyMulNTT(p, sk.pub.ringA(), y)
		ch := challengeSeed(p, w, message)
		c := expandChallenge(p, ch)

		// z = y + s*c
		sc := polyMulNTT(p, sk.s, c)
		z := polyAdd(p, y, sc)

		// Rejection sampling: keep z only if it falls inside the acceptance
		// ball. Because y is uniform in a box slightly larger than that ball,
		// the accepted distribution of z is independent of s (no secret leak).
		if polyNormSq(p, z) > p.AcceptSq {
			continue
		}
		// Extra cheap per-coefficient bound for the verifier.
		if int64(maxCoeffAbs(z)) > int64(p.Eta) {
			continue
		}

		used := h256(labelMask, packInt16Vec(y))
		return &Signature{params: p, z: z, ch: ch}, used, nil
	}
	return nil, zero, ErrInvalidSignature
}
