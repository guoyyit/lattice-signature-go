package latticesig

// verify performs all checks and returns a VerifyError carrying a precise
// reason on failure. It is read-only on its inputs and safe for concurrent
// use. All branches are bounded; no input can trigger unbounded iteration.
func verify(pk *PublicKey, message []byte, sig *Signature) error {
	if pk == nil {
		return &VerifyError{Reason: ErrMalformedEncoding, Detail: "nil public key"}
	}
	if sig == nil {
		return &VerifyError{Reason: ErrInvalidSignature, Detail: "nil signature"}
	}
	p := pk.params
	if p == nil {
		return &VerifyError{Reason: ErrUnsupportedParams, Detail: "public key has no params"}
	}
	if sig.params != nil && sig.params.Name != p.Name {
		return &VerifyError{Reason: ErrUnsupportedParams, Detail: "signature/key parameter mismatch"}
	}
	if len(message) > p.MaxMsg {
		return &VerifyError{Reason: ErrMessageTooLarge, Detail: "message exceeds maximum length"}
	}
	if len(sig.z) != p.N {
		return &VerifyError{Reason: ErrInvalidSignature, Detail: "response polynomial length mismatch"}
	}
	// A public key is complete if both t and the expanded a have the ring
	// length. v0 keys embed a directly (aSeed=nil, aCache set); v1 keys carry
	// aSeed and expand a lazily via ringA().
	if len(pk.t) != p.N || len(pk.ringA()) != p.N {
		return &VerifyError{Reason: ErrMalformedEncoding, Detail: "public key incomplete"}
	}

	// Bounded-coefficient check (rejects grossly oversized z cheaply).
	if int64(maxCoeffAbs(sig.z)) > int64(p.Eta) {
		return &VerifyError{Reason: ErrInvalidSignature, Detail: "response coefficient out of bounds"}
	}
	// Norm check.
	if polyNormSq(p, sig.z) > p.AcceptSq {
		return &VerifyError{Reason: ErrInvalidSignature, Detail: "response norm out of bounds"}
	}

	// Regenerate sparse challenge from the committed seed.
	c := expandChallenge(p, sig.ch)

	// w' = a*z - t*c
	az := polyMulNTT(p, pk.ringA(), sig.z)
	tc := polyMulNTT(p, pk.t, c)
	wPrime := polySub(p, az, tc)

	recomputed := challengeSeed(p, wPrime, message)
	if recomputed != sig.ch {
		return &VerifyError{Reason: ErrInvalidSignature, Detail: "challenge mismatch (tampered signature or public key)"}
	}
	return nil
}

// Verify checks a signature against a message and public key. It is safe for
// concurrent use by multiple goroutines.
func Verify(pk *PublicKey, message []byte, sig *Signature) error {
	return verify(pk, message, sig)
}

// VerifyEncoded verifies an already-serialized signature blob.
func VerifyEncoded(pk *PublicKey, message []byte, encoded []byte) error {
	sig, err := UnmarshalSignature(encoded)
	if err != nil {
		return &VerifyError{Reason: err, Detail: "could not decode signature"}
	}
	return verify(pk, message, sig)
}
