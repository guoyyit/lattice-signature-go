package latticesig

import (
	"crypto/sha256"
	"encoding/binary"
)

// Versioned, self-describing binary encoding.
//
// Wire layout (all integers big endian):
//
//	offset  size  field
//	0       4     magic "LSG1" (format family)
//	4       1     kind   (1=public key, 2=secret key, 3=signature)
//	5       1     ver    payload version
//	6       2     param  parameter-set id (length-prefixed name)
//	8       4     plen   payload length
//	12      plen  payload
//	12+plen 4     checksum = first 4 bytes SHA-256(bytes[0:12+plen])
//
// Payload version 1:
//
//	public key : uint16 aSeedLen || aSeed || 2*N int16 t
//	secret key : uint16 seedLen  || seed  || 2*N int16 s || embedded public key blob
//	signature  : 32-byte challenge seed || 2*N int16 z
//
// Older payload versions <= payloadVersion are accepted for verification;
// strictly newer ones yield ErrUnknownVersion.

const (
	magic0, magic1, magic2, magic3 = 'L', 'S', 'G', '1'
	headerLen                      = 12
	checksumLen                    = 4

	payloadVersion byte = 1
	minAcceptedVer byte = 1

	kindPublicKey byte = 1
	kindSecretKey byte = 2
	kindSignature byte = 3
)

func be16(b []byte) uint16     { return binary.BigEndian.Uint16(b) }
func put16(b []byte, v uint16) { binary.BigEndian.PutUint16(b, v) }
func put32(b []byte, v uint32) { binary.BigEndian.PutUint32(b, v) }

func encodeBlob(kind byte, version byte, p *Params, payload []byte) []byte {
	total := headerLen + len(payload) + checksumLen
	buf := make([]byte, total)
	buf[0], buf[1], buf[2], buf[3] = magic0, magic1, magic2, magic3
	buf[4] = kind
	buf[5] = version
	put16(buf[6:], paramID(p.Name))
	put32(buf[8:], uint32(len(payload)))
	copy(buf[headerLen:], payload)
	sum := sha256.Sum256(buf[:headerLen+len(payload)])
	copy(buf[headerLen+len(payload):], sum[:checksumLen])
	return buf
}

func decodeBlob(kind byte, blob []byte) (version byte, p *Params, payload []byte, err error) {
	if len(blob) < headerLen+checksumLen {
		return 0, nil, nil, ErrMalformedEncoding
	}
	if blob[0] != magic0 || blob[1] != magic1 || blob[2] != magic2 || blob[3] != magic3 {
		return 0, nil, nil, ErrMalformedEncoding
	}
	if blob[4] != kind {
		return 0, nil, nil, ErrMalformedEncoding
	}
	plen := be32(blob[8:])
	if headerLen+int(plen)+checksumLen != len(blob) {
		return 0, nil, nil, ErrMalformedEncoding
	}
	// Checksum before trusting any content.
	sum := sha256.Sum256(blob[:headerLen+int(plen)])
	for i := 0; i < checksumLen; i++ {
		if blob[headerLen+int(plen)+i] != sum[i] {
			return 0, nil, nil, ErrMalformedEncoding
		}
	}
	ver := blob[5]
	if ver < minAcceptedVer {
		return 0, nil, nil, ErrUnknownVersion
	}
	if ver > payloadVersion {
		return 0, nil, nil, ErrUnknownVersion
	}
	params, ok := lookupParams(paramName(be16(blob[6:])))
	if !ok {
		return 0, nil, nil, ErrUnsupportedParams
	}
	return ver, params, append([]byte(nil), blob[headerLen:headerLen+int(plen)]...), nil
}

func be32(b []byte) uint32 { return uint32(binary.BigEndian.Uint32(b)) }

// ----- coefficient (de)serialization -----

func packInt16Vec(v poly) []byte {
	out := make([]byte, 2*len(v))
	for i, c := range v {
		binary.BigEndian.PutUint16(out[2*i:], uint16(int16(c)))
	}
	return out
}

func unpackInt16Vec(p *Params, b []byte) (poly, bool) {
	if len(b) != 2*p.N {
		return nil, false
	}
	out := make(poly, p.N)
	for i := 0; i < p.N; i++ {
		out[i] = int32(int16(binary.BigEndian.Uint16(b[2*i:])))
	}
	return out, true
}

func readLenPrefixed(b []byte) (item, rest []byte, ok bool) {
	if len(b) < 2 {
		return nil, nil, false
	}
	n := int(be16(b))
	b = b[2:]
	if n < 0 || n > len(b) {
		return nil, nil, false
	}
	return b[:n:n], b[n:], true
}

// ----- public key -----

func (k *PublicKey) MarshalBinary() ([]byte, error) {
	if k == nil || k.params == nil {
		return nil, ErrMalformedEncoding
	}
	aLen := len(k.aSeed)
	payload := make([]byte, 2+aLen+2*k.params.N)
	put16(payload, uint16(aLen))
	copy(payload[2:], k.aSeed)
	copy(payload[2+aLen:], packInt16Vec(k.t))
	return encodeBlob(kindPublicKey, payloadVersion, k.params, payload), nil
}

func UnmarshalPublicKey(b []byte) (*PublicKey, error) {
	_, p, payload, err := decodeBlob(kindPublicKey, b)
	if err != nil {
		return nil, err
	}
	aSeed, rest, ok := readLenPrefixed(payload)
	if !ok {
		return nil, ErrMalformedEncoding
	}
	t, ok := unpackInt16Vec(p, rest)
	if !ok {
		return nil, ErrMalformedEncoding
	}
	if len(aSeed) == 0 {
		return nil, ErrMalformedEncoding
	}
	return &PublicKey{params: p, aSeed: append([]byte(nil), aSeed...), t: t}, nil
}

// ----- secret key -----

func (k *SecretKey) MarshalBinary() ([]byte, error) {
	if k == nil || k.params == nil || k.pub == nil {
		return nil, ErrMalformedEncoding
	}
	pubBlob, err := k.pub.MarshalBinary()
	if err != nil {
		return nil, err
	}
	sLen := len(k.seed)
	payload := make([]byte, 0, 2+sLen+2*k.params.N+4+len(pubBlob))
	var l [2]byte
	put16(l[:], uint16(sLen))
	payload = append(payload, l[:]...)
	payload = append(payload, k.seed...)
	payload = append(payload, packInt16Vec(k.s)...)
	var pl [4]byte
	put32(pl[:], uint32(len(pubBlob)))
	payload = append(payload, pl[:]...)
	payload = append(payload, pubBlob...)
	return encodeBlob(kindSecretKey, payloadVersion, k.params, payload), nil
}

func UnmarshalSecretKey(b []byte) (*SecretKey, error) {
	_, p, payload, err := decodeBlob(kindSecretKey, b)
	if err != nil {
		return nil, err
	}
	seed, rest, ok := readLenPrefixed(payload)
	if !ok || len(seed) < MinSeedLen {
		return nil, ErrMalformedEncoding
	}
	if len(rest) < 2*p.N+4 {
		return nil, ErrMalformedEncoding
	}
	s, ok := unpackInt16Vec(p, rest[:2*p.N])
	if !ok {
		return nil, ErrMalformedEncoding
	}
	rest = rest[2*p.N:]
	pubLen := int(binary.BigEndian.Uint32(rest[:4]))
	rest = rest[4:]
	if pubLen != len(rest) {
		return nil, ErrMalformedEncoding
	}
	pub, err := UnmarshalPublicKey(rest)
	if err != nil {
		return nil, err
	}
	if pub.params.Name != p.Name {
		return nil, ErrUnsupportedParams
	}
	return &SecretKey{
		params: p,
		seed:   append([]byte(nil), seed...),
		s:      s,
		pub:    pub,
	}, nil
}

// ----- signature -----

func (s *Signature) MarshalBinary() ([]byte, error) {
	if s == nil || s.params == nil {
		return nil, ErrMalformedEncoding
	}
	payload := make([]byte, 0, 32+2*s.params.N)
	payload = append(payload, s.ch[:]...)
	payload = append(payload, packInt16Vec(s.z)...)
	return encodeBlob(kindSignature, payloadVersion, s.params, payload), nil
}

func UnmarshalSignature(b []byte) (*Signature, error) {
	_, p, payload, err := decodeBlob(kindSignature, b)
	if err != nil {
		return nil, err
	}
	if len(payload) != 32+2*p.N {
		return nil, ErrMalformedEncoding
	}
	var ch [32]byte
	copy(ch[:], payload[:32])
	z, ok := unpackInt16Vec(p, payload[32:])
	if !ok {
		return nil, ErrMalformedEncoding
	}
	return &Signature{params: p, z: z, ch: ch}, nil
}
