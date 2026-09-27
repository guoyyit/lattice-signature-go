package lattice

import "crypto/sha256"

// sha256NewHasher 返回带域前缀约定的新 SHA-256 哈希器（调用方写长度受限数据）。
func sha256NewHasher() interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
} {
	return sha256.New()
}

func writeUint24(h interface{ Write([]byte) (int, error) }, v uint32) {
	h.Write([]byte{byte(v >> 16), byte(v >> 8), byte(v)})
}

// sha256New 是带域分隔标签的 SHA-256 助手。
func sha256New(domain, data []byte) []byte {
	h := sha256.New()
	h.Write(domain)
	h.Write(data)
	return h.Sum(nil)
}
