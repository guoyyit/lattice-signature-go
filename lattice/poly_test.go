package lattice

import "testing"

func TestNTTRoundTrip(t *testing.T) {
	g := newPRG([]byte("test-seed-for-ntt-roundtrip"), []byte("poly"))
	a := sampleUniformQ(g)
	fa := polyNTT(&a)
	back := polyInvNTT(&fa)
	for i := range a {
		if back[i] != a[i] {
			t.Fatalf("NTT round-trip mismatch at %d: %d != %d", i, back[i], a[i])
		}
	}
}

func TestNTTConvolution(t *testing.T) {
	g1 := newPRG([]byte("conv-a"), []byte("a"))
	g2 := newPRG([]byte("conv-b"), []byte("b"))
	a := sampleUniformQ(g1)
	b := sampleUniformQ(g2)
	fa := polyNTT(&a)
	fb := polyNTT(&b)
	pc := polyPointwise(&fa, &fb)
	got := polyInvNTT(&pc)
	want := polyMulSchoolbook(&a, &b)
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("convolution mismatch at %d: %d != %d", i, got[i], want[i])
		}
	}
}
