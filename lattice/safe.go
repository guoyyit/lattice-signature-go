package lattice

// safeCall* 把内部 panic（例如畸形输入触发的越界）统一转成错误，
// 保证服务 API 在恶意输入下不会让调用进程崩溃。
func safeCall1(f func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = ErrCorruptEncoding
		}
	}()
	return f()
}

func safeCall2(f func() ([]byte, error)) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, ErrCorruptEncoding
		}
	}()
	return f()
}

func safeCall3(f func() (*PublicKey, *SecretKey, error)) (pk *PublicKey, sk *SecretKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			pk, sk, err = nil, nil, ErrCorruptEncoding
		}
	}()
	return f()
}

func safeCall1ptr[T any](f func() (*T, error)) (out *T, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, ErrCorruptEncoding
		}
	}()
	return f()
}
