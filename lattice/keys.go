package lattice

// PublicKey 是验证公钥（rho 展开公开矩阵 A，t 以 NTT 表示存储）。
type PublicKey struct {
	version uint8
	params  *Params
	rho     [32]byte
	t       vecK
}

// SecretKey 是签名私钥。s1 为自然域小向量；t 以 NTT 表示存储。
//
// 本实现采用无噪声的 Module-SIS 风格构造：t = A·s1（模 q）。
// 这是教学化简化：伪造签名等价于求解 Module-SIS，
// 但不提供基于 Module-LWE 密钥的全部安全性质，禁止用于生产。
type SecretKey struct {
	version uint8
	params  *Params
	rho     [32]byte
	s1      vecL
	t       vecK
}

// checkParams 校验参数与本实现的固定维度一致（本版本只支持单一参数集）。
func checkParams(p *Params) (*Params, error) {
	if p == nil {
		return ToyParams256, nil
	}
	if p.N != nConst || p.Q != qConst || p.K != kConst || p.L != ellConst ||
		p.Eta != etaConst || p.Gamma1 != gamma1Const || p.Tau != tauConst ||
		p.MaxMessageBytes <= 0 {
		return nil, ErrUnsupportedParams
	}
	return p, nil
}

// KeyGenFromSeed 从种子与安全参数确定性地生成密钥对。
// 同一 (种子, 参数) 始终得到同一密钥对；过程不调用任何外部随机源。
func KeyGenFromSeed(seed []byte, p *Params) (*PublicKey, *SecretKey, error) {
	p, err := checkParams(p)
	if err != nil {
		return nil, nil, err
	}

	var rho [32]byte
	copy(rho[:], sha256New([]byte("lattice-keygen-rho-v1"), seed))

	// 域分隔：不同材料使用不同 PRG 域，杜绝随机数跨用途复用。
	gS1 := newPRG(rho[:], []byte("keygen-s1-v1"))

	sk := &SecretKey{version: currentVersion, params: p, rho: rho}
	pk := &PublicKey{version: currentVersion, params: p, rho: rho}

	for i := 0; i < ellConst; i++ {
		sk.s1[i] = sampleCentered(gS1, p.Eta)
	}

	A := expandA(&rho)
	for i := 0; i < kConst; i++ {
		var acc poly
		for j := 0; j < ellConst; j++ {
			s1hat := polyNTT(&sk.s1[j])
			prod := polyPointwise(&A[i][j], &s1hat)
			acc = polyAdd(&acc, &prod)
		}
		sk.t[i] = acc // t 直接以 NTT 表示存储
	}
	pk.t = sk.t
	return pk, sk, nil
}

// expandA 从 rho 确定性展开公开矩阵 A（元素直接以 NTT 表示输出）。
func expandA(rho *[32]byte) matA {
	var A matA
	for i := 0; i < kConst; i++ {
		for j := 0; j < ellConst; j++ {
			d := []byte{'A', byte(i), byte(j)}
			g := newPRG(rho[:], d)
			nat := sampleUniformQ(g)
			A[i][j] = polyNTT(&nat)
		}
	}
	return A
}

// publicKey 从私钥材料重建公钥视图。
func (sk *SecretKey) publicKey() *PublicKey {
	return &PublicKey{version: sk.version, params: sk.params, rho: sk.rho, t: sk.t}
}
