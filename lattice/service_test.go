package lattice

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	s, err := NewService(nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestServiceBasic(t *testing.T) {
	s := newTestService(t)
	pk, sk, err := s.KeyGenFromSeed([]byte("service-seed"))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := s.Sign(sk, []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(pk, []byte("abc"), enc); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := s.Verify(pk, []byte("abd"), enc); err == nil {
		t.Fatal("altered message accepted")
	}
}

func TestServiceEmptySeedRejected(t *testing.T) {
	s := newTestService(t)
	if _, _, err := s.KeyGenFromSeed(nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("want ErrInvalidArgument, got %v", err)
	}
}

func TestServiceRestartFlow(t *testing.T) {
	s1 := newTestService(t)
	pk, sk, _ := s1.KeyGenFromSeed([]byte("restart-seed"))
	epk, _ := s1.MarshalPublicKey(pk)
	esk, _ := s1.MarshalSecretKey(sk)

	// 模拟重启：新服务实例反序列化恢复。
	s2 := newTestService(t)
	pk2, err := s2.UnmarshalPublicKey(epk)
	if err != nil {
		t.Fatal(err)
	}
	sk2, err := s2.UnmarshalSecretKey(esk)
	if err != nil {
		t.Fatal(err)
	}
	enc1, _ := s1.Sign(sk, []byte("m"))
	enc2, _ := s2.Sign(sk2, []byte("m"))
	if string(enc1) != string(enc2) {
		t.Fatal("signatures differ across restart with restored keys")
	}
	if err := s2.Verify(pk2, []byte("m"), enc1); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentSignDistinctMessagesNoReuse(t *testing.T) {
	s := newTestService(t)
	_, sk, _ := s.KeyGenFromSeed([]byte("concurrent-seed"))

	const n = 64
	results := make([][]byte, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			msg := []byte(fmt.Sprintf("message-%04d", i))
			enc, err := s.Sign(sk, msg)
			results[i], errs[i] = enc, err
		}(i)
	}
	wg.Wait()
	for i := range errs {
		if errs[i] != nil {
			t.Fatalf("sign %d failed: %v", i, errs[i])
		}
	}
	// 不同消息必须产生不同签名（掩码流被 mu0 区分，不存在复用）。
	seen := map[string]bool{}
	for i, e := range results {
		if seen[string(e)] {
			t.Fatalf("signature reused for message %d", i)
		}
		seen[string(e)] = true
	}

	// 同一消息重复并发签名必须完全一致（确定性）。
	pk, _, _ := s.KeyGenFromSeed([]byte("concurrent-seed"))
	const r = 32
	rep := make([][]byte, r)
	wg.Add(r)
	for i := 0; i < r; i++ {
		go func(i int) {
			defer wg.Done()
			enc, _ := s.Sign(sk, []byte("same-message"))
			rep[i] = enc
		}(i)
	}
	wg.Wait()
	for i := 1; i < r; i++ {
		if string(rep[i]) != string(rep[0]) {
			t.Fatalf("nondeterministic signature at %d", i)
		}
	}
	if err := s.Verify(pk, []byte("same-message"), rep[0]); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentVerify(t *testing.T) {
	s := newTestService(t)
	pk, sk, _ := s.KeyGenFromSeed([]byte("cv-seed"))
	enc, _ := s.Sign(sk, []byte("payload"))
	var wg sync.WaitGroup
	for g := 0; g < 100; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Verify(pk, []byte("payload"), enc); err != nil {
				t.Errorf("verify: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestMalformedInputsDoNotPanic(t *testing.T) {
	s := newTestService(t)
	pk, _, _ := s.KeyGenFromSeed([]byte("malformed"))

	cases := [][]byte{
		nil, {},
		{0, 1, 2},
		make([]byte, 18),      // 看起来像头但长度字段为 0
		make([]byte, 100_000), // 大堆零
	}
	for i, c := range cases {
		if err := s.Verify(pk, []byte("m"), c); err == nil {
			t.Fatalf("case %d unexpectedly accepted", i)
		}
		if err := s.Verify(nil, []byte("m"), c); err == nil {
			t.Fatalf("case %d accepted with nil pk", i)
		}
	}
}

func TestTamperEverySignatureByteKind(t *testing.T) {
	s := newTestService(t)
	pk, sk, _ := s.KeyGenFromSeed([]byte("bitflip-seed"))
	enc, _ := s.Sign(sk, []byte("bitflip message"))

	// 在签名载荷多个位置翻转单字节，均必须被拒绝（校验和或密码学检查）。
	for _, pos := range []int{18, 50, 500, 1000, len(enc) - 9} {
		if pos >= len(enc) {
			continue
		}
		bad := make([]byte, len(enc))
		copy(bad, enc)
		bad[pos] ^= 0x01
		if err := s.Verify(pk, []byte("bitflip message"), bad); err == nil {
			t.Fatalf("tamper at byte %d accepted", pos)
		}
	}
}

func TestOversizedMessageRejected(t *testing.T) {
	s := newTestService(t)
	pk, sk, _ := s.KeyGenFromSeed([]byte("big-seed"))
	big := make([]byte, s.params.MaxMessageBytes+1)
	if _, err := s.Sign(sk, big); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("sign want ErrMessageTooLarge, got %v", err)
	}
	if err := s.Verify(pk, big, []byte{1, 2, 3}); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("verify want ErrMessageTooLarge, got %v", err)
	}
}

func TestEmptyMessage(t *testing.T) {
	s := newTestService(t)
	pk, sk, _ := s.KeyGenFromSeed([]byte("empty-msg-seed"))
	enc, err := s.Sign(sk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(pk, nil, enc); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(pk, []byte{0}, enc); err == nil {
		t.Fatal("empty vs single-zero must be distinguished")
	}
}

func TestCrossKeyRejection(t *testing.T) {
	s := newTestService(t)
	_, sk1, _ := s.KeyGenFromSeed([]byte("key-one"))
	pk2, _, _ := s.KeyGenFromSeed([]byte("key-two"))
	enc, _ := s.Sign(sk1, []byte("m"))
	if err := s.Verify(pk2, []byte("m"), enc); err == nil {
		t.Fatal("signature verified under wrong public key")
	}
}
