package lattice

// sampleUniformQ 通过拒绝采样输出 R_q 上的均匀系数多项式。
func sampleUniformQ(g *streamPRG) poly {
	var r poly
	var b [4]byte
	limit := uint32(uint64(1)<<32 - (uint64(1)<<32)%qConst)
	for i := 0; i < nConst; i++ {
		for {
			u := g.u32(&b)
			if u < limit {
				r[i] = int32(u % qConst)
				break
			}
		}
	}
	return r
}

// sampleCentered 输出系数均匀取自 [-eta, eta] 的多项式（标准模表示存储）。
func sampleCentered(g *streamPRG, eta int) poly {
	var r poly
	m := uint32(2*eta + 1)
	limit := uint32(uint64(1)<<32 - (uint64(1)<<32)%uint64(m))
	var b [4]byte
	for i := 0; i < nConst; i++ {
		var u uint32
		for {
			u = g.u32(&b)
			if u < limit {
				break
			}
		}
		v := int32(u%m) - int32(eta)
		r[i] = modQ(int64(v))
	}
	return r
}

// sampleMask 输出掩码多项式，系数均匀取自 [-gamma1, gamma1)。
func sampleMask(g *streamPRG) poly {
	var r poly
	span := uint32(2 * gamma1Const) // = 2^18，整除 2^32，无需拒绝
	var b [4]byte
	for i := 0; i < nConst; i++ {
		u := g.u32(&b) % span
		r[i] = modQ(int64(int64(u) - gamma1Const))
	}
	return r
}

// challengeFromMu 从 32 字节承诺确定性派生含 tau 个 ±1 的稀疏挑战多项式。
// 使用部分洗牌选取互不重复的位置，保证终止性（不依赖拒绝采样）。
func challengeFromMu(mu []byte) poly {
	var r poly
	g := newPRG(mu, []byte("challenge-poly-v1"))
	idx := make([]uint16, nConst)
	for i := range idx {
		idx[i] = uint16(i)
	}
	var b [4]byte
	for i := 0; i < tauConst; i++ {
		j := i + int(g.u32(&b)%uint32(nConst-i))
		idx[i], idx[j] = idx[j], idx[i]
		sign := int32(1)
		if g.u32(&b)&1 == 1 {
			sign = modQ(-1)
		}
		r[idx[i]] = sign
	}
	return r
}
