package latticesig

// Params holds the public constants of a ring-SIS based signature instance.
//
// Security caveat: the concrete constants shipped here are sized for tests
// and demonstrations, not for production security claims. See SECURITY.md.
type Params struct {
	Name     string
	N        int   // ring degree; modulus polynomial is x^N + 1, N power of two
	Q        int   // ciphertext modulus (prime)
	Eta      int   // coefficients of masks y lie in [-Eta, Eta]
	Tau      int   // exact number of non-zero challenge coefficients
	AcceptSq int64 // squared Euclidean acceptance radius for rejection sampling
	MaxIters int   // maximum signing attempts before giving up
	MaxMsg   int   // maximum message length in bytes accepted by Verify
}

func (p *Params) id() string { return p.Name }

// parameter catalog populated by register in a later file
var paramCatalog = map[string]*Params{}

// stable 2-byte wire identifiers for parameter sets (independent of display
// name). Adding a parameter set allocates a fresh id; ids are never reused.
var (
	paramIDByName        = map[string]uint16{}
	paramNameByID        = map[uint16]string{}
	nextParamID   uint16 = 0x0001
)

func registerParams(p *Params) *Params {
	paramCatalog[p.Name] = p
	id, exists := paramIDByName[p.Name]
	if !exists {
		id = nextParamID
		nextParamID++
		paramIDByName[p.Name] = id
		paramNameByID[id] = p.Name
	}
	return p
}

func lookupParams(name string) (*Params, bool) {
	p, ok := paramCatalog[name]
	return p, ok
}

func paramID(name string) uint16 { return paramIDByName[name] }

func paramName(id uint16) string {
	name, ok := paramNameByID[id]
	if !ok {
		return ""
	}
	return name
}
