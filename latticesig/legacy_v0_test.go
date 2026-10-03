package latticesig

import (
	"crypto/sha256"
)

// Legacy v0 wire encoder. This is an independent writer for the retired v0
// payload format. It must NOT use MarshalBinary (the current v1 encoder): its
// purpose is to produce genuine v0 blobs with a different payload layout so
// that interop tests exercise the real v0 decoder, not a v1 blob with a bumped
// version byte.
//
// v0 layouts:
//   public key : 2*N int16 a (full ring element) || 2*N int16 t
//   secret key : 2*N int16 s || uint16 seedLen || seed || 4-byte pubLen || embedded v0 public key blob
//   signature  : 2*N int16 z || 32-byte challenge seed

func legacyEncodeBlobV0(kind byte, p *Params, payload []byte) []byte {
	total := headerLen + len(payload) + checksumLen
	buf := make([]byte, total)
	buf[0], buf[1], buf[2], buf[3] = magic0, magic1, magic2, magic3
	buf[4] = kind
	buf[5] = 0 // legacy version
	put16(buf[6:], paramID(p.Name))
	put32(buf[8:], uint32(len(payload)))
	copy(buf[headerLen:], payload)
	sum := sha256.Sum256(buf[:headerLen+len(payload)])
	copy(buf[headerLen+len(payload):], sum[:checksumLen])
	return buf
}

func legacyMarshalPublicKeyV0(p *Params, a, t poly) []byte {
	payload := make([]byte, 0, 2*len(a)+2*len(t))
	payload = append(payload, packInt16Vec(a)...)
	payload = append(payload, packInt16Vec(t)...)
	return legacyEncodeBlobV0(kindPublicKey, p, payload)
}

func legacyMarshalSecretKeyV0(p *Params, seed []byte, s poly, pubBlobV0 []byte) []byte {
	payload := make([]byte, 0, 2*p.N+2+len(seed)+4+len(pubBlobV0))
	payload = append(payload, packInt16Vec(s)...)
	var l [2]byte
	put16(l[:], uint16(len(seed)))
	payload = append(payload, l[:]...)
	payload = append(payload, seed...)
	var pl [4]byte
	put32(pl[:], uint32(len(pubBlobV0)))
	payload = append(payload, pl[:]...)
	payload = append(payload, pubBlobV0...)
	return legacyEncodeBlobV0(kindSecretKey, p, payload)
}

func legacyMarshalSignatureV0(p *Params, z poly, ch [32]byte) []byte {
	payload := make([]byte, 0, 2*len(z)+32)
	payload = append(payload, packInt16Vec(z)...)
	payload = append(payload, ch[:]...)
	return legacyEncodeBlobV0(kindSignature, p, payload)
}

// legacyV0KeyDerivation derives the same key material as GenerateKey but
// exposes the expanded a so the v0 public key can embed it directly.
func legacyV0KeyDerivation(seed []byte, p *Params) (a, t, s poly, aSeed []byte) {
	aSeedBytes := h256(labelA, seed, []byte(p.Name))
	aSeed = aSeedBytes[:]
	s = sampleTernary(p, seed, labelSecret)
	a = expandA(p, aSeed)
	t = polyMulNTT(p, a, s)
	return a, t, s, aSeed
}
