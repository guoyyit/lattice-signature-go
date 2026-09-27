package lattice

// Signature 是一次确定性签名的结构化表示。
//
//	mu0 绑定 (公钥, 消息)：H("mu-v1" || rho || t || message)
//	ch  是 Fiat-Shamir 挑战承诺：H(mu0 || w1)
//	z   是小的掩码+挑战响应向量（自然域）
type Signature struct {
	version uint8
	mu0     [32]byte
	ch      [32]byte
	z       vecL
}

const (
	// beta = tau*eta：c*s1 的无穷范数上界。
	beta = tauConst * etaConst
	// zBound = gamma1 - beta：响应 z 的合法性界。
	zBound = gamma1Const - beta
	// maxSignAttempts 为确定性重试上限。
	maxSignAttempts = 256
)

// highBits 返回 a 相对 gamma2=(q-1)/32 的“高位”索引（Dilithium 风格）。
// 当两个输入的差的中心表示落在 (-gamma2, gamma2] 内时，高位索引相同。
func highBits(a int32) int32 {
	const gamma2 = (qConst - 1) / 32
	r := a
	if r > qConst/2 {
		r -= qConst
	}
	return (r + gamma2) / (2 * gamma2)
}

func polyHighBits(a *poly) poly {
	var r poly
	for i := 0; i < nConst; i++ {
		r[i] = highBits(a[i])
	}
	return r
}

// addShifted 将 ±a 旋转 shift 位并累加到 r（利用 X^n = -1 折回）。
func addShifted(r, a *poly, shift int, neg bool) {
	for j := 0; j < nConst; j++ {
		aj := int64(a[j])
		if neg {
			aj = -aj
		}
		if shift+j < nConst {
			r[shift+j] = modQ(int64(r[shift+j]) + aj)
		} else {
			r[shift+j-nConst] = modQ(int64(r[shift+j-nConst]) - aj)
		}
	}
}

// polyMulSparse 计算 a*c，其中 c 仅含 tau 个 ±1（移位相加，避免全卷积）。
func polyMulSparse(a, c *poly) poly {
	var r poly
	for i := 0; i < nConst; i++ {
		switch c[i] {
		case 1:
			addShifted(&r, a, i, false)
		case qConst - 1:
			addShifted(&r, a, i, true)
		}
	}
	return r
}

// commitMu0 计算绑定公钥与消息的摘要。
func commitMu0(pk *PublicKey, message []byte) [32]byte {
	h := sha256NewHasher()
	h.Write([]byte("lattice-mu-v1"))
	for i := 0; i < kConst; i++ {
		for j := 0; j < nConst; j++ {
			writeUint24(h, uint32(pk.t[i][j]))
		}
	}
	h.Write(pk.rho[:])
	h.Write(message)
	var mu [32]byte
	h.Sum(mu[:0])
	return mu
}

// hashW1 计算 Fiat-Shamir 挑战承诺 H(mu0 || w1)。
func hashW1(mu0 []byte, w1 []poly) [32]byte {
	h := sha256NewHasher()
	h.Write([]byte("lattice-w1-v1"))
	h.Write(mu0)
	for i := range w1 {
		for j := 0; j < nConst; j++ {
			// 高位索引范围约 [-8,8]，一个字节足够。
			v := w1[i][j]
			h.Write([]byte{byte(v), byte(v >> 8)})
		}
	}
	var ch [32]byte
	h.Sum(ch[:0])
	return ch
}

// makeAttemptDomain 构造第 attempt 次签名尝试的掩码派生域，
// 绑定 mu0（即绑定公钥与消息），从设计上隔离不同消息/尝试的随机数。
func makeAttemptDomain(mu0 []byte, attempt int) []byte {
	d := make([]byte, 0, len("sign-y-v1")+32+4)
	d = append(d, []byte("sign-y-v1")...)
	d = append(d, mu0...)
	d = append(d, byte(attempt>>24), byte(attempt>>16), byte(attempt>>8), byte(attempt))
	return d
}

// sign 对消息生成确定性签名。
//
// 掩码 y 由 (rho, mu0, attempt) 确定性派生：不同消息 mu0 必不同，
// 因而不同消息之间在设计上不可能复用掩码；每次失败尝试也使用独立域。
// 签名过程不持有可变随机状态，不存在随机数复用泄露私钥的路径。
func sign(sk *SecretKey, message []byte) (*Signature, error) {
	if len(message) > sk.params.MaxMessageBytes {
		return nil, ErrMessageTooLarge
	}
	pk := sk.publicKey()
	mu0 := commitMu0(pk, message)

	A := expandA(&sk.rho)

	for attempt := 0; attempt < maxSignAttempts; attempt++ {
		g := newPRG(sk.rho[:], makeAttemptDomain(mu0[:], attempt))
		var y, yHat vecL
		for j := 0; j < ellConst; j++ {
			y[j] = sampleMask(g)
			yHat[j] = polyNTT(&y[j])
		}

		var w1 [kConst]poly
		for i := 0; i < kConst; i++ {
			var acc poly
			for j := 0; j < ellConst; j++ {
				prod := polyPointwise(&A[i][j], &yHat[j])
				acc = polyAdd(&acc, &prod)
			}
			wNat := polyInvNTT(&acc)
			w1[i] = polyHighBits(&wNat)
		}

		ch := hashW1(mu0[:], w1[:])
		c := challengeFromMu(ch[:])

		var z vecL
		ok := true
		for j := 0; j < ellConst; j++ {
			cs1 := polyMulSparse(&sk.s1[j], &c)
			z[j] = polyAdd(&y[j], &cs1)
			if polyNormInf(&z[j]) >= zBound {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		return &Signature{version: currentVersion, mu0: mu0, ch: ch, z: z}, nil
	}
	return nil, ErrSignFailed
}

// verify 校验签名。消息/公钥/签名任一处被篡改都会使承诺或范数检查失败。
func verify(pk *PublicKey, message []byte, sig *Signature) error {
	if pk == nil || sig == nil {
		return ErrInvalidArgument
	}
	if len(message) > pk.params.MaxMessageBytes {
		return ErrMessageTooLarge
	}
	if sig.version != currentVersion {
		return ErrUnknownVersion
	}
	for j := 0; j < ellConst; j++ {
		if polyNormInf(&sig.z[j]) >= zBound {
			return ErrSignatureRejected
		}
	}

	mu0 := commitMu0(pk, message)
	if mu0 != sig.mu0 {
		return ErrSignatureRejected
	}
	c := challengeFromMu(sig.ch[:])
	cHat := polyNTT(&c)

	A := expandA(&pk.rho)
	var w1 [kConst]poly
	for i := 0; i < kConst; i++ {
		var az poly
		for j := 0; j < ellConst; j++ {
			zHat := polyNTT(&sig.z[j])
			prod := polyPointwise(&A[i][j], &zHat)
			az = polyAdd(&az, &prod)
		}
		cT := polyPointwise(&cHat, &pk.t[i])
		diff := polySub(&az, &cT)
		wPrime := polyInvNTT(&diff)
		w1[i] = polyHighBits(&wPrime)
	}
	if hashW1(mu0[:], w1[:]) != sig.ch {
		return ErrSignatureRejected
	}
	return nil
}
