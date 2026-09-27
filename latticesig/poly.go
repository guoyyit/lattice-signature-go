package latticesig

// poly is a coefficient vector of length N in the ring Z_q[x]/(x^N+1).
type poly []int32

func newPoly(n int) poly { return make(poly, n) }

func (a poly) clone() poly {
	out := make(poly, len(a))
	copy(out, a)
	return out
}
