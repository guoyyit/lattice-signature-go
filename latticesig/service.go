package latticesig

// Service is the local-only entry point. It performs no network or external
// service I/O; every operation is a pure function of its inputs.
type Service struct {
	defaultParams *Params
}

// NewService builds a service with a default parameter set.
func NewService(p *Params) *Service { return &Service{defaultParams: p} }

// DefaultService uses the Toy128 parameter set.
func DefaultService() *Service { return NewService(Toy128) }

// ParamsByName returns a registered parameter set.
func ParamsByName(name string) (*Params, bool) { return lookupParams(name) }

func (s *Service) DefaultParams() *Params { return s.defaultParams }

func (s *Service) GenerateKey(seed []byte) (*KeyPair, error) {
	return GenerateKey(seed, s.defaultParams)
}

func (s *Service) Sign(sk *SecretKey, message []byte) (*Signature, error) {
	return Sign(sk, message)
}

// NewSigner returns a concurrency-safe signing handle with live nonce-reuse
// detection.
func (s *Service) NewSigner(sk *SecretKey) *Signer { return NewSigner(sk) }

func (s *Service) Verify(pk *PublicKey, message []byte, sig *Signature) error {
	return Verify(pk, message, sig)
}

func (s *Service) VerifyEncoded(pk *PublicKey, message, encoded []byte) error {
	return VerifyEncoded(pk, message, encoded)
}
