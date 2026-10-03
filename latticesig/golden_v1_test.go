package latticesig

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Frozen current-version (v1) wire bytes. They pin the exact encoding
// produced by this build for fixed inputs, guaranteeing that concurrency and
// compatibility fixes never change current-version output and that existing
// serialized data keeps working without migration. The vectors were verified
// byte-for-byte against the pre-fix implementation.

func goldenSeed() []byte {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 0x42 ^ byte(i)
	}
	return seed
}

var goldenV1Message = []byte("golden v1 lock message")

const goldenV1PublicKeyHex = "4c53473101010001000001220020ef4a4ac3a2cd2ddcae37bae8903db14fa59d576c0c998cc5161c190ebf12600202e5fce7fba003bf006a025c05c405b0fa81fbacfdc3fc4f01a1006effa503f8fb4605cf0583015404b90099fc3efe17fa2bfd33fa3ffb2103e4fa9ffa5a022bfa9a04ec0229fc1aff4f02defcbf03f4fd530129fee70488fe6cff0c01cb034f058efe47fea0fff0fe87fe860670fbd0fc19065fff9f04abf9d70662fc8002e601e4fa4b05cc03bf038efd48fcce022dfcbbff0a00b2fff101c7ff37fd150484fd41faa00118fb8201440648fd80040bff74fb3aff28fb0c01f5049101a0fa2efe920611066d066c0642f9e3ff52fcdc0160fb8bfe9bfabcff3600d6fb860251fcc6fa04fde6feae03520482fe3e0349fef2003b0668065903090142ffd20246ba7cf5cb"

const goldenV1SecretKeyHex = "4c5347310201000100000258002042434041464744454a4b48494e4f4c4d52535051565754555a5b58595e5f5c5d000000000001000100000000000100010001ffffffffffffffff0000000100010001ffff000100000000ffffffff0001ffff000000000001000100000000ffffffffffffffffffffffffffff0001000100010000ffffffff0000000000010001ffff00000000ffffffff0000ffffffffffff00000000000000010000ffff0001ffff00000000ffff0001ffff0000ffffffffffff00000000000100010001ffff0000ffff0000ffff0001ffffffffffff00010000ffffffff0000000000000000ffff0000ffff00010001ffffffffffffffff000000010001000100000001ffff0001ffffffff00000001000100000000ffffffff00010000ffff000100000001000001324c53473101010001000001220020ef4a4ac3a2cd2ddcae37bae8903db14fa59d576c0c998cc5161c190ebf12600202e5fce7fba003bf006a025c05c405b0fa81fbacfdc3fc4f01a1006effa503f8fb4605cf0583015404b90099fc3efe17fa2bfd33fa3ffb2103e4fa9ffa5a022bfa9a04ec0229fc1aff4f02defcbf03f4fd530129fee70488fe6cff0c01cb034f058efe47fea0fff0fe87fe860670fbd0fc19065fff9f04abf9d70662fc8002e601e4fa4b05cc03bf038efd48fcce022dfcbbff0a00b2fff101c7ff37fd150484fd41faa00118fb8201440648fd80040bff74fb3aff28fb0c01f5049101a0fa2efe920611066d066c0642f9e3ff52fcdc0160fb8bfe9bfabcff3600d6fb860251fcc6fa04fde6feae03520482fe3e0349fef2003b0668065903090142ffd20246ba7cf5cbfe3dc2f1"

const goldenV1SignatureHex = "4c53473103010001000001208745e0aa8e633c1342ac85dbb42549cd11b68f072a789f8fd3fb4e5bb49f6532ffc3ffca000a0000ffc1ffc5ffd800000022001e003dffc30015ffebffc40020fff10028ffc0000bffd3ffd8ffc2ffcf000c0002001d0014fffc00170039ffdefff10027001500000039fffe000a0033003700030005001600280003ffc3ffdf0036002b001dffde0000ffc00012003affe6002affccfffa0034ffdeffc5ffc50034002b002affe9003b0036fff8ffc9003a0012003000160001ffe5002b0008001ffff60028fff200290021ffdf000affd1001c002700100032ffdeffd8003e0037ffc40005002fffd4000cffe00037000afff5ffd2ffdcffe2ffc2003dffc6001dffd7ffe8ffc2ffcdffcf0008002dffde00330015fff2fff6ffc8ffcb002e8cbdc5c2"

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGoldenV1EncodingIsStable(t *testing.T) {
	kp, err := GenerateKey(goldenSeed(), Toy128)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(kp.Secret, goldenV1Message)
	if err != nil {
		t.Fatal(err)
	}
	pubB, _ := kp.Public.MarshalBinary()
	skB, _ := kp.Secret.MarshalBinary()
	sigB, _ := sig.MarshalBinary()

	cases := []struct {
		name string
		got  []byte
		want string
	}{
		{"public key", pubB, goldenV1PublicKeyHex},
		{"secret key", skB, goldenV1SecretKeyHex},
		{"signature", sigB, goldenV1SignatureHex},
	}
	for _, c := range cases {
		want := decodeHex(t, c.want)
		if !bytes.Equal(c.got, want) {
			t.Fatalf("%s encoding drifted: got %x... want %x... (len %d vs %d)",
				c.name, c.got[:16], want[:16], len(c.got), len(want))
		}
		if c.got[5] != payloadVersion {
			t.Fatalf("%s version byte = %d, want current %d", c.name, c.got[5], payloadVersion)
		}
	}

	// Deterministic key derivation/signing is locked too: re-derive and
	// compare once more.
	kp2, err := GenerateKey(goldenSeed(), Toy128)
	if err != nil {
		t.Fatal(err)
	}
	sig2, _ := Sign(kp2.Secret, goldenV1Message)
	sig2B, _ := sig2.MarshalBinary()
	if !bytes.Equal(sig2B, decodeHex(t, goldenV1SignatureHex)) {
		t.Fatal("deterministic signing output drifted")
	}

	// The golden blobs must themselves remain verifiable end to end.
	pk, err := UnmarshalPublicKey(decodeHex(t, goldenV1PublicKeyHex))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEncoded(pk, goldenV1Message, decodeHex(t, goldenV1SignatureHex)); err != nil {
		t.Fatalf("golden v1 signature no longer verifies: %v", err)
	}
}
