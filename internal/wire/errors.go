package wire

import "fmt"

// FailureKind identifies a generation failure independently of its wording.
type FailureKind uint8

const (
	FailureFileEmpty FailureKind = iota + 1
	FailureFileInvalid
	FailureArchitectureMismatch
	FailureMixedAssembly
	FailureDLLExport
	FailurePayloadTypeMismatch
	FailureDotNetEntryPoint
	FailureInvalidConfiguration
	FailureCompression
	FailureRandom
)

// Failure carries a stable category across the wire serialization boundary.
type Failure struct {
	Kind FailureKind
	Err  error
}

func (e *Failure) Error() string { return e.Err.Error() }
func (e *Failure) Unwrap() error { return e.Err }

func fail(kind FailureKind, format string, args ...any) error {
	return &Failure{Kind: kind, Err: fmt.Errorf(format, args...)}
}
