package lattice

// 多项式环 R_q = Z_q[X]/(X^n+1)，n=256, q=8380417（Dilithium 同款 NTT 素数）。
// rootOfUnity 是模 q 下的本原 2n(=512) 次单位根，用于负循环 NTT。
const rootOfUnity = 1753

// poly 是 R_q 中的元素，系数约定为标准表示 [0,q)。
type poly [nConst]int32

type vecL [ellConst]poly
type vecK [kConst]poly
type matA [kConst]vecL

// modQ 将任意 int64 规约到 [0,q)。
func modQ(x int64) int32 {
	r := x % qConst
	if r < 0 {
		r += qConst
	}
	return int32(r)
}

// centred 返回 a 到 0 的中心距离（无穷范数用）。
func centred(a int32) int32 {
	if a > qConst/2 {
		return qConst - a
	}
	return a
}

func polyAdd(a, b *poly) poly {
	var r poly
	for i := 0; i < nConst; i++ {
		r[i] = modQ(int64(a[i]) + int64(b[i]))
	}
	return r
}

func polySub(a, b *poly) poly {
	var r poly
	for i := 0; i < nConst; i++ {
		r[i] = modQ(int64(a[i]) - int64(b[i]))
	}
	return r
}

func polyScale(a *poly, f int64) poly {
	var r poly
	for i := 0; i < nConst; i++ {
		r[i] = modQ(int64(a[i]) * f)
	}
	return r
}

func polyNormInf(a *poly) int {
	m := int32(0)
	for i := 0; i < nConst; i++ {
		if c := centred(a[i]); c > m {
			m = c
		}
	}
	return int(m)
}

// nttZetas[k] = root^bitrev8(k) mod q，k=1..n-1（Dilithium 风格蝶形顺序）。
var nttZetas [nConst]int32

func init() {
	// 计算 8 位比特反转并逐个幂。直接从 1 出发按顺序递推 root^e 不便于
	// 按反转顺序取值，这里直接做幂运算（仅初始化一次）。
	for k := 1; k < nConst; k++ {
		nttZetas[k] = modQ(powMod(rootOfUnity, int64(bitRev8(k))))
	}
}

func bitRev8(x int) int {
	x = (x&0x0F)<<4 | (x>>4)&0x0F
	x = (x&0x33)<<2 | (x>>2)&0x33
	x = (x&0x55)<<1 | (x>>1)&0x55
	return x
}

func powMod(base, exp int64) int64 {
	r := int64(1)
	b := base % qConst
	for exp > 0 {
		if exp&1 == 1 {
			r = r * b % qConst
		}
		b = b * b % qConst
		exp >>= 1
	}
	return r
}

// polyNTT 是前向负循环 NTT（Cooley–Tukey，输入自然顺序）。
func polyNTT(a *poly) poly {
	r := *a
	k := 0
	for length := nConst / 2; length > 0; length >>= 1 {
		for start := 0; start < nConst; start += 2 * length {
			k++
			zeta := int64(nttZetas[k])
			for j := start; j < start+length; j++ {
				t := modQ(zeta * int64(r[j+length]))
				r[j+length] = modQ(int64(r[j]) - int64(t))
				r[j] = modQ(int64(r[j]) + int64(t))
			}
		}
	}
	return r
}

// polyInvNTT 是 polyNTT 的逆变换（Gentleman–Sande 蝶形 + 1/n 缩放）。
func polyInvNTT(a *poly) poly {
	r := *a
	k := nConst
	for length := 1; length < nConst; length <<= 1 {
		for start := 0; start < nConst; start += 2 * length {
			k--
			zeta := modQ(-int64(nttZetas[k]))
			for j := start; j < start+length; j++ {
				u := r[j]
				v := r[j+length]
				r[j] = modQ(int64(u) + int64(v))
				r[j+length] = modQ(int64(zeta) * int64(modQ(int64(u)-int64(v))))
			}
		}
	}
	invN := modQ(powMod(nConst, qConst-2))
	for i := 0; i < nConst; i++ {
		r[i] = modQ(int64(r[i]) * int64(invN))
	}
	return r
}

// polyPointwise 在 NTT 域逐点相乘（对应自然域的负循环卷积）。
func polyPointwise(a, b *poly) poly {
	var r poly
	for i := 0; i < nConst; i++ {
		r[i] = modQ(int64(a[i]) * int64(b[i]))
	}
	return r
}

// polyMulSchoolbook 是仅供测试的负循环卷积朴素实现。
func polyMulSchoolbook(a, b *poly) poly {
	var r poly
	for i := 0; i < nConst; i++ {
		for j := 0; j < nConst; j++ {
			ai := int64(a[i])
			if ai > qConst/2 {
				ai -= qConst
			}
			bj := int64(b[j])
			if bj > qConst/2 {
				bj -= qConst
			}
			if i+j < nConst {
				r[(i+j)%nConst] = modQ(int64(r[(i+j)%nConst]) + ai*bj)
			} else {
				r[(i+j)%nConst] = modQ(int64(r[(i+j)%nConst]) - ai*bj)
			}
		}
	}
	return r
}
