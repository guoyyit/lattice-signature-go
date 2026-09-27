// Package latticesig provides a local-only, deterministic short-signature
// service built on a ring-lattice (Ring-SIS) hardness assumption.
//
// All capabilities are exposed through in-process functions; the package never
// opens network connections or calls external services.
//
// WARNING: the shipped parameter sets are sized for tests and documentation.
// They are NOT audited and MUST NOT be used to protect real-world assets.
package latticesig
