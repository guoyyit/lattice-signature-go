package latticesig

// Concrete parameter sets are registered here.
var (
	// Toy128 is a fast parameter set for unit tests and demos.
	Toy128 *Params
	// Lite256 is a larger, slower set intended for basic interoperability
	// experiments.
	Lite256 *Params
)

func init() {
	Toy128 = registerParams(&Params{
		Name:     "toy128",
		N:        128,
		Q:        3329,
		Eta:      64,
		Tau:      16,
		AcceptSq: 80 * 80 * 128,
		MaxIters: 4096,
		MaxMsg:   16 * 1024 * 1024,
	})
	Lite256 = registerParams(&Params{
		Name:     "lite256",
		N:        256,
		Q:        7681,
		Eta:      64,
		Tau:      24,
		AcceptSq: 110 * 110 * 256,
		MaxIters: 4096,
		MaxMsg:   16 * 1024 * 1024,
	})
}
