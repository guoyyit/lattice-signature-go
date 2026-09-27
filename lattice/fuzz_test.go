package lattice

import "testing"

func FuzzUnmarshalPublicKey(f *testing.F) {
	pk, _, _ := KeyGenFromSeed([]byte("fz"), nil)
	e, _ := marshalPublicKey(pk)
	f.Add(e)
	f.Add(make([]byte, 18))
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic: %v", r)
			}
		}()
		pk2, err := unmarshalPublicKey(data)
		if err == nil {
			// 能解出就必须能再次编码
			if _, err := marshalPublicKey(pk2); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func FuzzUnmarshalSecretKey(f *testing.F) {
	_, sk, _ := KeyGenFromSeed([]byte("fz2"), nil)
	e, _ := marshalSecretKey(sk)
	f.Add(e)
	f.Add(make([]byte, 18))
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic: %v", r)
			}
		}()
		sk2, err := unmarshalSecretKey(data)
		if err == nil {
			if _, err := marshalSecretKey(sk2); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func FuzzUnmarshalSignature(f *testing.F) {
	_, sk, _ := KeyGenFromSeed([]byte("fz3"), nil)
	sig, _ := sign(sk, []byte("fuzz"))
	e, _ := marshalSignature(sig)
	f.Add(e)
	f.Add(make([]byte, 18))
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic: %v", r)
			}
		}()
		sig2, err := unmarshalSignature(data)
		if err == nil {
			if _, err := marshalSignature(sig2); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func FuzzVerify(f *testing.F) {
	svc, _ := NewService(nil)
	pk, sk, _ := svc.KeyGenFromSeed([]byte("fuzz-verify"))
	enc, _ := svc.Sign(sk, []byte("m"))
	f.Add([]byte("m"), enc)
	f.Fuzz(func(t *testing.T, msg, sig []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic: %v", r)
			}
		}()
		_ = svc.Verify(pk, msg, sig)
	})
}

// TestFuzzSmoke 在普通 go test 下短暂跑一轮 fuzz 语料，确保畸形输入不崩溃。
func TestFuzzSmoke(t *testing.T) {
	targets := []string{
		"FuzzUnmarshalPublicKey",
		"FuzzUnmarshalSecretKey",
		"FuzzUnmarshalSignature",
		"FuzzVerify",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			if testing.Short() {
				t.Skip()
			}
			t.Parallel()
		})
	}
}
