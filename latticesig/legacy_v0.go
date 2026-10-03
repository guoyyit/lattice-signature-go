package latticesig

import "encoding/binary"

// Version 0 is the historical wire format, kept readable for backward
// compatibility. It is never produced by this build (the writer emits
// payloadVersion); only the decoder understands it.
//
// The v0 envelope is identical to v1 (magic/kind/version/param-id/plen/
// checksum, all big endian). Only the *payload* layout differs:
//
//   - Ring coefficients are encoded as LITTLE-endian unsigned 16-bit
//     canonical residues in [0, q), whereas v1 uses big-endian signed
//     16-bit values in [-(q-1)/2, (q-1)/2].
//   - Variable-length byte strings (aSeed, seed) are fixed 32-byte fields
//     with NO length prefix; v1 prefixes them with a uint16 length.
//   - The signature payload orders the response polynomial z BEFORE the
//     challenge seed; v1 puts the challenge seed first.
//   - The secret-key payload orders the embedded public key BEFORE the seed
//     and secret polynomial; v1 orders seed, s, then public key.
//
// Exact v0 payload layouts:
//
//	public key : aSeed[32] || leU16(t)[2*N]
//	secret key : pubkey_blob(rest of payload, exact) || seed[32] || leU16(s)[2*N]
//	signature  : leU16(z)[2*N] || ch[32]
//
// Converting between the two coefficient encodings is an exact bijection for
// every supported modulus, so parsing a v0 blob yields the exact same
// in-memory objects as parsing the equivalent v1 blob.

const (
	legacyV0Version      byte = 0
	legacyV0SeedLen           = 32
	legacyV0ChallengeLen      = 32
)

// unpackLEU16Vec decodes little-endian canonical residues in [0, q) into the
// symmetric coefficient range used internally.
func unpackLEU16Vec(p *Params, b []byte) (poly, bool) {
	if len(b) != 2*p.N {
		return nil, false
	}
	out := make(poly, p.N)
	for i := 0; i < p.N; i++ {
		r := binary.LittleEndian.Uint16(b[2*i:])
		if int(r) >= p.Q {
			return nil, false
		}
		out[i] = modSym(p.Q, int64(r))
	}
	return out, true
}

// ---- v0 public key ----

func unmarshalPublicKeyV0(p *Params, payload []byte) (*PublicKey, error) {
	if len(payload) != legacyV0SeedLen+2*p.N {
		return nil, ErrMalformedEncoding
	}
	aSeed := payload[:legacyV0SeedLen:legacyV0SeedLen]
	t, ok := unpackLEU16Vec(p, payload[legacyV0SeedLen:])
	if !ok {
		return nil, ErrMalformedEncoding
	}
	seed := append([]byte(nil), aSeed...)
	return &PublicKey{
		params: p,
		aSeed:  seed,
		t:      t,
		aCache: expandA(p, seed),
	}, nil
}

// ---- v0 signature ----

func unmarshalSignatureV0(p *Params, payload []byte) (*Signature, error) {
	if len(payload) != 2*p.N+legacyV0ChallengeLen {
		return nil, ErrMalformedEncoding
	}
	z, ok := unpackLEU16Vec(p, payload[:2*p.N])
	if !ok {
		return nil, ErrMalformedEncoding
	}
	var ch [32]byte
	copy(ch[:], payload[2*p.N:])
	return &Signature{params: p, z: z, ch: ch}, nil
}

// ---- v0 secret key ----

func unmarshalSecretKeyV0(p *Params, payload []byte) (*SecretKey, error) {
	// Embedded public-key blob first. Its length is implicit (the blob
	// terminates at the start of the trailing fixed-width fields).
	trailing := legacyV0SeedLen + 2*p.N
	if len(payload) <= trailing {
		return nil, ErrMalformedEncoding
	}
	pubBlob := payload[:len(payload)-trailing]
	pub, err := UnmarshalPublicKey(pubBlob)
	if err != nil {
		return nil, err
	}
	if pub.params.Name != p.Name {
		return nil, ErrUnsupportedParams
	}
	rest := payload[len(pubBlob):]
	seed := rest[:legacyV0SeedLen:legacyV0SeedLen]
	if len(seed) < MinSeedLen {
		return nil, ErrMalformedEncoding
	}
	s, ok := unpackLEU16Vec(p, rest[legacyV0SeedLen:])
	if !ok {
		return nil, ErrMalformedEncoding
	}
	return &SecretKey{
		params: p,
		seed:   append([]byte(nil), seed...),
		s:      s,
		pub:    pub,
	}, nil
}
