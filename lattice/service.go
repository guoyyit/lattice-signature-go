package lattice

// Service 是本地短签名服务，仅暴露进程内函数接口；无网络、无外部依赖。
//
// Service 本身不持有任何可变状态：密钥从种子生成，签名确定性派生，
// 因此所有方法天然可被多个 goroutine 并发调用。
type Service struct {
	params *Params
}

// NewService 创建使用指定参数集的服务；nil 表示使用默认参数集。
func NewService(p *Params) (*Service, error) {
	cp, err := checkParams(p)
	if err != nil {
		return nil, err
	}
	return &Service{params: cp}, nil
}

// KeyGenFromSeed 从种子确定性生成密钥对（公钥、私钥均可序列化恢复）。
func (s *Service) KeyGenFromSeed(seed []byte) (*PublicKey, *SecretKey, error) {
	return safeCall3(func() (*PublicKey, *SecretKey, error) {
		if len(seed) == 0 {
			return nil, nil, ErrInvalidArgument
		}
		return KeyGenFromSeed(seed, s.params)
	})
}

// Sign 返回版本化编码后的签名字节。同一 (私钥, 消息) 恒返回相同结果。
func (s *Service) Sign(sk *SecretKey, message []byte) (sig []byte, err error) {
	return safeCall2(func() ([]byte, error) {
		if sk == nil || !paramsEqual(sk.params, s.params) {
			return nil, ErrInvalidArgument
		}
		if len(message) > s.params.MaxMessageBytes {
			return nil, ErrMessageTooLarge
		}
		signed, err := sign(sk, message)
		if err != nil {
			return nil, err
		}
		return marshalSignature(signed)
	})
}

// Verify 校验版本化编码签名。恶意/超大输入只返回明确的拒绝错误，不会 panic。
func (s *Service) Verify(pk *PublicKey, message, encoded []byte) (err error) {
	return safeCall1(func() error {
		if pk == nil || !paramsEqual(pk.params, s.params) {
			return ErrInvalidArgument
		}
		if len(message) > s.params.MaxMessageBytes {
			return ErrMessageTooLarge
		}
		sig, err := unmarshalSignature(encoded)
		if err != nil {
			return err
		}
		return verify(pk, message, sig)
	})
}

// MarshalPublicKey / MarshalSecretKey / Unmarshal* 提供重启恢复能力。
func (s *Service) MarshalPublicKey(pk *PublicKey) ([]byte, error) {
	return safeCall2(func() ([]byte, error) {
		if pk == nil || !paramsEqual(pk.params, s.params) {
			return nil, ErrInvalidArgument
		}
		return marshalPublicKey(pk)
	})
}

func (s *Service) UnmarshalPublicKey(enc []byte) (pk *PublicKey, err error) {
	return safeCall1ptr(func() (*PublicKey, error) {
		pk, err := unmarshalPublicKey(enc)
		if err != nil {
			return nil, err
		}
		if !paramsEqual(pk.params, s.params) {
			return nil, ErrUnsupportedParams
		}
		return pk, nil
	})
}

func (s *Service) MarshalSecretKey(sk *SecretKey) ([]byte, error) {
	return safeCall2(func() ([]byte, error) {
		if sk == nil || !paramsEqual(sk.params, s.params) {
			return nil, ErrInvalidArgument
		}
		return marshalSecretKey(sk)
	})
}

func (s *Service) UnmarshalSecretKey(enc []byte) (sk *SecretKey, err error) {
	return safeCall1ptr(func() (*SecretKey, error) {
		sk, err := unmarshalSecretKey(enc)
		if err != nil {
			return nil, err
		}
		if !paramsEqual(sk.params, s.params) {
			return nil, ErrUnsupportedParams
		}
		return sk, nil
	})
}

func paramsEqual(a, b *Params) bool {
	if a == nil || b == nil {
		return false
	}
	return a == b || *a == *b
}
