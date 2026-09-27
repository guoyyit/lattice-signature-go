package lattice

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// 版本化编码格式（小端整数）：
//
//	magic   [4]byte = "LTTC"
//	version uint8
//	kind    uint8   （1=公钥 2=私钥 3=签名）
//	length  uint32  （载荷字节数）
//	payload []byte
//	check   [8]byte = SHA-256(header||payload) 的前 8 字节
//
// 同版本内向后兼容：未来仅在不改变载荷含义的前提下新增可接受版本号。
// 未知版本与损坏编码通过不同哨兵错误区分。
const (
	currentVersion uint8  = 1
	magic          uint32 = 0x4C545443 // "LTTC"

	kindPublicKey uint8 = 1
	kindSecretKey uint8 = 2
	kindSignature uint8 = 3

	headerLen = 10
	checkLen  = 8
)

// 可区分错误：未知版本 / 编码损坏 / 参数不支持等。
var (
	ErrUnknownVersion    = errors.New("lattice: unknown encoding version")
	ErrCorruptEncoding   = errors.New("lattice: corrupt or truncated encoding")
	ErrUnsupportedParams = errors.New("lattice: unsupported parameter set")
	ErrWrongObjectKind   = errors.New("lattice: encoded object kind mismatch")
)

// 签名/验证过程使用的错误。
var (
	ErrInvalidArgument   = errors.New("lattice: nil key or signature")
	ErrMessageTooLarge   = errors.New("lattice: message exceeds configured size limit")
	ErrSignFailed        = errors.New("lattice: signing failed after retry limit")
	ErrSignatureRejected = errors.New("lattice: signature rejected (tampered or invalid)")
)

// framePayload 添加头与校验和。
func framePayload(kind uint8, payload []byte) []byte {
	out := make([]byte, 0, headerLen+len(payload)+checkLen)
	var hdr [headerLen]byte
	binary.LittleEndian.PutUint32(hdr[0:4], magic)
	hdr[4] = currentVersion
	hdr[5] = kind
	binary.LittleEndian.PutUint32(hdr[6:10], uint32(len(payload)))
	out = append(out, hdr[:]...)
	out = append(out, payload...)

	sum := sha256.New()
	sum.Write(hdr[:])
	sum.Write(payload)
	var digest [sha256.Size]byte
	sum.Sum(digest[:0])
	out = append(out, digest[:checkLen]...)
	return out
}

// openFrame 校验魔数、版本、长度、校验和并返回 (version, payload)。
func openFrame(enc []byte, wantKind uint8) (uint8, []byte, error) {
	if len(enc) < headerLen+checkLen {
		return 0, nil, ErrCorruptEncoding
	}
	if binary.LittleEndian.Uint32(enc[0:4]) != magic {
		return 0, nil, ErrCorruptEncoding
	}
	ver := enc[4]
	kind := enc[5]
	// 版本兼容窗口：当前仅接受版本 1；未来版本在此处扩展。
	if ver != currentVersion {
		return ver, nil, ErrUnknownVersion
	}
	if kind != wantKind {
		return ver, nil, ErrWrongObjectKind
	}
	n := binary.LittleEndian.Uint32(enc[6:10])
	if uint64(n) != uint64(len(enc))-headerLen-checkLen {
		return ver, nil, ErrCorruptEncoding
	}
	payload := enc[headerLen : headerLen+n]

	h := sha256.New()
	h.Write(enc[:headerLen])
	h.Write(payload)
	var digest [sha256.Size]byte
	h.Sum(digest[:0])
	for i := 0; i < checkLen; i++ {
		if digest[i] != enc[headerLen+int(n)+i] {
			return ver, nil, ErrCorruptEncoding
		}
	}
	return ver, payload, nil
}

// ---- 读写助手 ----

type reader struct {
	b   []byte
	pos int
}

func (r *reader) read(n int) []byte {
	if r.pos+n > len(r.b) {
		return nil
	}
	out := r.b[r.pos : r.pos+n]
	r.pos += n
	return out
}

func (r *reader) u24() (int32, bool) {
	b := r.read(3)
	if b == nil {
		return 0, false
	}
	return int32(uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])), true
}

func appendU24(out []byte, v uint32) []byte {
	return append(out, byte(v>>16), byte(v>>8), byte(v))
}

// pack20 把每个元素（范围约 ±zBound < 2^18，有符号）按 20 位紧凑打包。
func pack20(values ...poly) []byte {
	total := nConst * len(values)
	out := make([]byte, (total*20+7)/8)
	var bit uint64 // 当前比特偏移
	for i := range values {
		for j := 0; j < nConst; j++ {
			// 偏移到无符号 [0,2^20)：原值大于 q/2 时先中心化。
			v := int64(values[i][j])
			if v > qConst/2 {
				v -= qConst
			}
			u := uint64(v + zBound)
			for b := 0; b < 20; b++ {
				if u&(1<<b) != 0 {
					out[(bit+uint64(b))/8] |= 1 << ((bit + uint64(b)) % 8)
				}
			}
			bit += 20
		}
	}
	return out
}

// unpack20 是 pack20 的逆操作，并校验范围。
func unpack20(buf []byte, values ...poly) bool {
	if len(buf) < (nConst*len(values)*20+7)/8 {
		return false
	}
	var bit uint64
	for i := range values {
		for j := 0; j < nConst; j++ {
			var u uint64
			for b := 0; b < 20; b++ {
				if buf[(bit+uint64(b))/8]&(1<<((bit+uint64(b))%8)) != 0 {
					u |= 1 << b
				}
			}
			bit += 20
			v := int64(u) - zBound
			if v < -zBound || v >= zBound {
				return false
			}
			values[i][j] = modQ(v)
		}
	}
	return true
}

// ---- 公钥 ----

func marshalPublicKey(pk *PublicKey) ([]byte, error) {
	if pk == nil {
		return nil, ErrInvalidArgument
	}
	p := make([]byte, 0, 32+kConst*nConst*3)
	p = append(p, pk.rho[:]...)
	for i := 0; i < kConst; i++ {
		for j := 0; j < nConst; j++ {
			v := pk.t[i][j]
			if v < 0 || v >= qConst {
				return nil, ErrCorruptEncoding
			}
			p = appendU24(p, uint32(v))
		}
	}
	return framePayload(kindPublicKey, p), nil
}

func unmarshalPublicKey(enc []byte) (*PublicKey, error) {
	_, p, err := openFrame(enc, kindPublicKey)
	if err != nil {
		return nil, err
	}
	r := reader{b: p}
	pk := &PublicKey{version: currentVersion, params: ToyParams256}
	if b := r.read(32); b == nil {
		return nil, ErrCorruptEncoding
	} else {
		copy(pk.rho[:], b)
	}
	for i := 0; i < kConst; i++ {
		for j := 0; j < nConst; j++ {
			v, ok := r.u24()
			if !ok || v < 0 || v >= qConst {
				return nil, ErrCorruptEncoding
			}
			pk.t[i][j] = v
		}
	}
	if r.pos != len(p) {
		return nil, ErrCorruptEncoding
	}
	return pk, nil
}

// ---- 私钥 ----

func marshalSecretKey(sk *SecretKey) ([]byte, error) {
	if sk == nil {
		return nil, ErrInvalidArgument
	}
	p := make([]byte, 0, 32+ellConst*nConst+kConst*nConst*3)
	p = append(p, sk.rho[:]...)
	// s1 系数在 [-eta, eta]，用单个有符号字节存储。
	for i := 0; i < ellConst; i++ {
		for j := 0; j < nConst; j++ {
			v := int64(sk.s1[i][j])
			if v > qConst/2 {
				v -= qConst
			}
			if v < -etaConst || v > etaConst {
				return nil, ErrCorruptEncoding
			}
			p = append(p, byte(v))
		}
	}
	for i := 0; i < kConst; i++ {
		for j := 0; j < nConst; j++ {
			v := sk.t[i][j]
			if v < 0 || v >= qConst {
				return nil, ErrCorruptEncoding
			}
			p = appendU24(p, uint32(v))
		}
	}
	return framePayload(kindSecretKey, p), nil
}

func unmarshalSecretKey(enc []byte) (*SecretKey, error) {
	_, p, err := openFrame(enc, kindSecretKey)
	if err != nil {
		return nil, err
	}
	r := reader{b: p}
	sk := &SecretKey{version: currentVersion, params: ToyParams256}
	if b := r.read(32); b == nil {
		return nil, ErrCorruptEncoding
	} else {
		copy(sk.rho[:], b)
	}
	for i := 0; i < ellConst; i++ {
		for j := 0; j < nConst; j++ {
			b := r.read(1)
			if b == nil {
				return nil, ErrCorruptEncoding
			}
			v := int8(b[0])
			if int(v) < -etaConst || int(v) > etaConst {
				return nil, ErrCorruptEncoding
			}
			sk.s1[i][j] = modQ(int64(v))
		}
	}
	for i := 0; i < kConst; i++ {
		for j := 0; j < nConst; j++ {
			v, ok := r.u24()
			if !ok || v < 0 || v >= qConst {
				return nil, ErrCorruptEncoding
			}
			sk.t[i][j] = v
		}
	}
	if r.pos != len(p) {
		return nil, ErrCorruptEncoding
	}
	return sk, nil
}

// ---- 签名 ----

func marshalSignature(sig *Signature) ([]byte, error) {
	if sig == nil {
		return nil, ErrInvalidArgument
	}
	// 归一化前先校验 z 必须是短向量。
	for i := 0; i < ellConst; i++ {
		for j := 0; j < nConst; j++ {
			v := int64(sig.z[i][j])
			if v > qConst/2 {
				v -= qConst
			}
			if v < -zBound || v >= zBound {
				return nil, ErrSignatureRejected
			}
		}
	}
	p := make([]byte, 0, 64+(ellConst*nConst*20+7)/8)
	p = append(p, sig.mu0[:]...)
	p = append(p, sig.ch[:]...)
	p = append(p, pack20(sig.z[:]...)...)
	return framePayload(kindSignature, p), nil
}

func unmarshalSignature(enc []byte) (*Signature, error) {
	_, p, err := openFrame(enc, kindSignature)
	if err != nil {
		return nil, err
	}
	r := reader{b: p}
	sig := &Signature{version: currentVersion}
	if b := r.read(32); b == nil {
		return nil, ErrCorruptEncoding
	} else {
		copy(sig.mu0[:], b)
	}
	if b := r.read(32); b == nil {
		return nil, ErrCorruptEncoding
	} else {
		copy(sig.ch[:], b)
	}
	zLen := (ellConst * nConst * 20) / 8
	zBuf := r.read(zLen)
	if zBuf == nil {
		return nil, ErrCorruptEncoding
	}
	if !unpack20(zBuf, sig.z[:]...) {
		return nil, ErrCorruptEncoding
	}
	if r.pos != len(p) {
		return nil, ErrCorruptEncoding
	}
	return sig, nil
}
