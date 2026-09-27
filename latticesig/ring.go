package latticesig

// Ring arithmetic over R_q = Z_q[x]/(x^N + 1), with N a power of two and q
// an odd positive integer.
//
// Multiplication uses straightforward negacyclic schoolbook convolution.
// It is O(N^2); the shipped parameter sets cap N at 256, where this is
// comfortably fast while staying simple and easy to audit.

// modQ reduces v into the symmetric range [-(q-1)/2, (q-1)/2].
func modSym(q int, v int64) int32 {
	q64 := int64(q)
	r := v % q64
	if r < 0 {
		r += q64
	}
	half := q64 / 2
	if r > half {
		r -= q64
	}
	return int32(r)
}

// modCanon reduces v into [0, q-1].
func modCanon(q int, v int64) int32 {
	q64 := int64(q)
	r := v % q64
	if r < 0 {
		r += q64
	}
	return int32(r)
}

func polyAdd(p *Params, a, b poly) poly {
	out := make(poly, p.N)
	for i := 0; i < p.N; i++ {
		out[i] = modSym(p.Q, int64(a[i])+int64(b[i]))
	}
	return out
}

func polySub(p *Params, a, b poly) poly {
	out := make(poly, p.N)
	for i := 0; i < p.N; i++ {
		out[i] = modSym(p.Q, int64(a[i])-int64(b[i]))
	}
	return out
}

func polyNeg(p *Params, a poly) poly {
	out := make(poly, p.N)
	for i := 0; i < p.N; i++ {
		out[i] = modSym(p.Q, -int64(a[i]))
	}
	return out
}

// polyMulNTT computes a*b in R_q. Despite the legacy name it performs exact
// negacyclic convolution (independent of whether q is NTT-friendly).
func polyMulNTT(p *Params, a, b poly) poly {
	n := p.N
	acc := make([]int64, n)
	for i := 0; i < n; i++ {
		ai := int64(a[i])
		if ai == 0 {
			continue
		}
		for j := 0; j < n; j++ {
			bj := int64(b[j])
			if bj == 0 {
				continue
			}
			prod := ai * bj
			k := i + j
			if k < n {
				acc[k] += prod
			} else {
				// x^(i+j) = -x^(i+j-n) modulo x^n + 1
				acc[k-n] -= prod
			}
		}
	}
	out := make(poly, n)
	for i := 0; i < n; i++ {
		out[i] = modSym(p.Q, acc[i])
	}
	return out
}

// polyNormSq returns the squared Euclidean norm of the coefficient vector.
func polyNormSq(p *Params, a poly) int64 {
	var sum int64
	for _, v := range a {
		sum += int64(v) * int64(v)
	}
	return sum
}

// maxCoeffAbs returns max_i |a_i|.
func maxCoeffAbs(a poly) int32 {
	var m int32
	for _, v := range a {
		if v < 0 {
			v = -v
		}
		if v > m {
			m = v
		}
	}
	return m
}

func polyEqual(a, b poly) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
