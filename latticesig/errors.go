package latticesig

import "errors"

// Sentinel errors for versioned encoding failures.
var (
	// ErrUnsupportedVersion is returned when an encoded blob carries a
	// version older than the oldest version this build is able to parse.
	ErrUnsupportedVersion error = &versionErr{msg: "latticesig: unsupported (obsolete) encoding version"}

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

// versionErr is a sentinel error that also reports membership in the
// version-mismatch family (ErrUnknownVersion).
type versionErr struct {
	msg string
}

func (e *versionErr) Error() string { return e.msg }

func (e *versionErr) Is(target error) bool { return target == ErrUnknownVersion }

// ErrNewerVersion is returned when an encoded blob carries a version newer
// than the version produced by this build. The blob may be valid but requires
// a newer implementation.
var ErrNewerVersion error = &versionErr{msg: "latticesig: encoding version newer than this build"}

// ErrUnknownVersion is the generic version-mismatch marker. Every concrete
// version rejection (obsolete or newer) matches it via errors.Is, allowing
// callers to treat any version mismatch uniformly when they do not need the
// precise reason.
var ErrUnknownVersion = errors.New("latticesig: unknown encoding version")

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
