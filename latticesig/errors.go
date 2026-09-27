package latticesig

import "errors"

// Sentinel errors for versioned encoding failures.
var (
	// ErrUnknownVersion is returned when an encoded blob carries a version
	// that this build does not understand.
	ErrUnknownVersion = errors.New("latticesig: unknown encoding version")

	// ErrMalformedEncoding is returned when an encoded blob is structurally
	// invalid (bad length, truncation, checksum mismatch, ...).
	ErrMalformedEncoding = errors.New("latticesig: malformed encoding")

	// ErrUnsupportedParams is returned when a parameter set identifier is
	// unknown to this build.
	ErrUnsupportedParams = errors.New("latticesig: unsupported parameter set")

	// ErrMessageTooLarge is returned when a message exceeds the configured
	// maximum accepted length.
	ErrMessageTooLarge = errors.New("latticesig: message too large")

	// ErrInvalidSignature is returned when a signature fails verification.
	ErrInvalidSignature = errors.New("latticesig: invalid signature")

	// ErrUnimplemented is used by skeleton builds and must never leak from
	// finished code paths.
	ErrUnimplemented = errors.New("latticesig: not implemented")
)

// VerifyError wraps a concrete rejection reason for a failed verification.
type VerifyError struct {
	Reason error
	Detail string
}

func (e *VerifyError) Error() string {
	if e.Detail == "" {
		return "latticesig: verification rejected: " + safeErr(e.Reason)
	}
	return "latticesig: verification rejected: " + safeErr(e.Reason) + ": " + e.Detail
}

func (e *VerifyError) Unwrap() error { return e.Reason }

func safeErr(err error) string {
	if err == nil {
		return "(none)"
	}
	return err.Error()
}
