package lattice

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// streamPRG 是从 (种子, 域分隔标签) 确定性派生的字节流，
// 仅使用标准库（SHA-256 / HMAC），内部不调用任何 OS 随机源。
//
// 为每条用途（密钥生成、每一次签名尝试等）传入互不相同的 domain，
// 从而在设计上保证随机数绝不会跨用途复用。
type streamPRG struct {
	key [32]byte
}

// newPRG 从 32 字节种子与域分隔标签派生一个字节流。
// 若种子长度不是 32 字节，将先做一次 SHA-256 压缩。
func newPRG(seed, domain []byte) *streamPRG {
	h := sha256.New()
	h.Write([]byte("lattice-prg-v1"))
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(domain)))
	h.Write(l[:])
	h.Write(domain)
	h.Write([]byte{0})
	h.Write(seed)
	g := &streamPRG{}
	h.Sum(g.key[:0])
	return g
}

// bytes 将确定性字节流写入 dst（长度任意）。
func (g *streamPRG) bytes(dst []byte) {
	var block [32 + 4]byte
	mac := hmac.New(sha256.New, g.key[:])
	for off := 0; off < len(dst); off += 32 {
		mac.Reset()
		binary.BigEndian.PutUint32(block[32:], uint32(off/32))
		mac.Write(block[:])
		b := mac.Sum(nil)
		copy(dst[off:], b)
	}
}

// u32 从字节流读取一个大端 32 位整数（拒绝采样的辅助函数）。
func (g *streamPRG) u32(buf *[4]byte) uint32 {
	g.bytes(buf[:])
	return binary.BigEndian.Uint32(buf[:])
}
