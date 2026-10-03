// Package latticesig provides a local-only, deterministic short-signature
// service built on a ring-lattice (Ring-SIS) hardness assumption.
//
// All capabilities are exposed through in-process functions; the package never
// opens network connections or calls external services.
//
// Keys and signatures restored from their versioned byte encodings are ready
// for immediate concurrent use without any warm-up call: verification never
// mutates a public key, and decoding completes all derived-state expansion up
// front. Historical payload version 0 remains readable alongside the current
// version 1; see README "编码格式与版本兼容".
//
// WARNING: the shipped parameter sets are sized for tests and documentation.
// They are NOT audited and MUST NOT be used to protect real-world assets.
package latticesig
