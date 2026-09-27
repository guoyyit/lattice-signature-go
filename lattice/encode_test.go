package lattice

import (
	"bytes"
	"errors"
	"testing"
)

func TestKeySerializationRoundTrip(t *testing.T) {
	pk, sk, _ := KeyGenFromSeed([]byte("enc-seed"), nil)

	epk, err := marshalPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	epsk, err := marshalSecretKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	pk2, err := unmarshalPublicKey(epk)
	if err != nil {
		t.Fatalf("unmarshal pk: %v", err)
	}
	sk2, err := unmarshalSecretKey(epsk)
	if err != nil {
		t.Fatalf("unmarshal sk: %v", err)
	}
	if pk2.rho != pk.rho || pk2.t != pk.t {
		t.Fatal("public key round-trip mismatch")
	}
	if sk2.rho != sk.rho || sk2.s1 != sk.s1 || sk2.t != sk.t {
		t.Fatal("secret key round-trip mismatch")
	}
	// 用恢复后的密钥重新签名并验证（模拟重启）
	sig, err := sign(sk2, []byte("after-restart"))
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(pk2, []byte("after-restart"), sig); err != nil {
		t.Fatalf("verify after restart: %v", err)
	}
}

func TestSignatureSerializationRoundTrip(t *testing.T) {
	pk, sk, _ := KeyGenFromSeed([]byte("enc-sig-seed"), nil)
	sig, _ := sign(sk, []byte("message"))
	enc, err := marshalSignature(sig)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := unmarshalSignature(enc)
	if err != nil {
		t.Fatal(err)
	}
	if sig2.mu0 != sig.mu0 || sig2.ch != sig.ch || sig2.z != sig.z {
		t.Fatal("signature round-trip mismatch")
	}
	if err := verify(pk, []byte("message"), sig2); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownVersionDistinctError(t *testing.T) {
	pk, _, _ := KeyGenFromSeed([]byte("enc-ver"), nil)
	enc, _ := marshalPublicKey(pk)
	enc[4] = 99 // 未知版本
	_, err := unmarshalPublicKey(enc)
	if !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("want ErrUnknownVersion, got %v", err)
	}
}

func TestCorruptEncodingDistinctError(t *testing.T) {
	pk, _, _ := KeyGenFromSeed([]byte("enc-corrupt"), nil)
	enc, _ := marshalPublicKey(pk)
	enc[len(enc)-1] ^= 0xFF // 破坏校验和
	_, err := unmarshalPublicKey(enc)
	if !errors.Is(err, ErrCorruptEncoding) {
		t.Fatalf("want ErrCorruptEncoding, got %v", err)
	}

	// 截断
	if _, err := unmarshalPublicKey(enc[:5]); !errors.Is(err, ErrCorruptEncoding) {
		t.Fatalf("truncated: want ErrCorruptEncoding, got %v", err)
	}
	// 魔数错误
	bad := bytes.Clone(enc)
	bad[0] ^= 0xFF
	// 魔数错误后校验和也不匹配，但魔数检查先于校验和
	if _, err := unmarshalPublicKey(bad); !errors.Is(err, ErrCorruptEncoding) {
		t.Fatalf("bad magic: want ErrCorruptEncoding, got %v", err)
	}
}

func TestKindMismatch(t *testing.T) {
	pk, _, _ := KeyGenFromSeed([]byte("kind"), nil)
	enc, _ := marshalPublicKey(pk)
	if _, err := unmarshalSignature(enc); !errors.Is(err, ErrWrongObjectKind) {
		t.Fatalf("want ErrWrongObjectKind, got %v", err)
	}
}
