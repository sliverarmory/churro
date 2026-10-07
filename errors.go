package churro

import (
	"errors"
	"fmt"
)

// ErrClosed is returned by Generator.Generate after Generator.Close.
var ErrClosed = errors.New("churro: generator is closed")

// ValidationError reports an invalid generation request.
type ValidationError struct {
	Field   string
	Problem string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("churro: invalid %s: %s", e.Field, e.Problem)
}

// ErrorCode is a stable domain code for a failure during generation. Values
// match Fritter's generation codes for callers migrating from its Go API.
type ErrorCode uint32

const (
	ErrorFileNotFound         ErrorCode = 1
	ErrorFileEmpty            ErrorCode = 2
	ErrorFileAccess           ErrorCode = 3
	ErrorFileInvalid          ErrorCode = 4
	ErrorDotNetEntryPoint     ErrorCode = 5
	ErrorOutOfMemory          ErrorCode = 6
	ErrorInvalidArchitecture  ErrorCode = 7
	ErrorInvalidURL           ErrorCode = 8
	ErrorURLTooLong           ErrorCode = 9
	ErrorInvalidConfiguration ErrorCode = 10
	ErrorRandom               ErrorCode = 11
	ErrorDLLExport            ErrorCode = 12
	ErrorArchitectureMismatch ErrorCode = 13
	ErrorDLLInvocation        ErrorCode = 14
	ErrorInvalidFormat        ErrorCode = 16
	ErrorCompressionEngine    ErrorCode = 17
	ErrorCompression          ErrorCode = 18
	ErrorInvalidEntropy       ErrorCode = 19
	ErrorMixedAssembly        ErrorCode = 20
	ErrorInvalidHeaders       ErrorCode = 21
	ErrorInvalidDecoy         ErrorCode = 22
	ErrorPayloadTypeMismatch  ErrorCode = 23
)

// String returns the description of a Fritter-compatible generation code.
func (c ErrorCode) String() string {
	switch c {
	case ErrorFileNotFound:
		return "file not found"
	case ErrorFileEmpty:
		return "file is empty"
	case ErrorFileAccess:
		return "cannot access file"
	case ErrorFileInvalid:
		return "file is invalid"
	case ErrorDotNetEntryPoint:
		return ".NET DLL requires a class and method"
	case ErrorOutOfMemory:
		return "memory allocation failed"
	case ErrorInvalidArchitecture:
		return "invalid architecture"
	case ErrorInvalidURL:
		return "invalid URL"
	case ErrorURLTooLong:
		return "URL is too long"
	case ErrorInvalidConfiguration:
		return "invalid generation configuration"
	case ErrorRandom:
		return "random generation failed"
	case ErrorDLLExport:
		return "DLL export was not found"
	case ErrorArchitectureMismatch:
		return "payload architecture is not supported"
	case ErrorDLLInvocation:
		return "invalid native DLL invocation"
	case ErrorInvalidFormat:
		return "invalid output format"
	case ErrorCompressionEngine:
		return "invalid compression engine"
	case ErrorCompression:
		return "compression failed"
	case ErrorInvalidEntropy:
		return "invalid entropy"
	case ErrorMixedAssembly:
		return "mixed native and managed assemblies are unsupported"
	case ErrorInvalidHeaders:
		return "invalid PE header option"
	case ErrorInvalidDecoy:
		return "invalid decoy module path"
	case ErrorPayloadTypeMismatch:
		return "payload bytes do not match the requested payload type"
	default:
		return fmt.Sprintf("unknown error code %d", c)
	}
}

// GenerationError reports a domain failure from the Go generator. Cause
// retains the underlying PE, wire, or loader error for diagnostics.
type GenerationError struct {
	Code  ErrorCode
	Cause error
}

func (e *GenerationError) Error() string {
	if e.Cause == nil {
		return fmt.Sprintf("churro: generation failed: %s", e.Code)
	}
	return fmt.Sprintf("churro: generation failed: %s: %v", e.Code, e.Cause)
}

func (e *GenerationError) Unwrap() error { return e.Cause }
