package churro

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/sliverarmory/churro/internal/wire"
)

// Generator builds Windows x64 loaders from payload bytes. Calls may run
// concurrently. It retains no payload bytes between calls.
type Generator struct {
	mu     sync.RWMutex
	closed bool
	bundle *LoaderBundle
}

// NewGenerator returns a reusable generator. Generation does not require a
// sidecar, C compiler, CGO or WebAssembly runtime.
func NewGenerator() *Generator { return &Generator{} }

// New returns a reusable generator, matching Fritter's one-time setup shape.
// The context is checked here; generation itself accepts a separate context.
func New(ctx context.Context) (*Generator, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return NewGenerator(), nil
}

// NewWithLoader creates a generator from caller-supplied x64 loader images and
// matching cipher/API metadata. The bundle is copied before this call returns.
func NewWithLoader(ctx context.Context, bundle LoaderBundle) (*Generator, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := bundle.validate(); err != nil {
		return nil, fmt.Errorf("invalid loader bundle: %w", err)
	}
	copy := bundle.clone()
	return &Generator{bundle: &copy}, nil
}

// Generate is the one-shot API for a single request.
func Generate(ctx context.Context, request Request) (Result, error) {
	return NewGenerator().Generate(ctx, request)
}

// Generate builds one loader with an embedded payload or an HTTP staging
// module. The returned byte slices are owned by the caller.
func (g *Generator) Generate(ctx context.Context, request Request) (Result, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.closed {
		return Result{}, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	n, err := normalizeGeneration(request)
	if err != nil {
		return Result{}, classifyValidationFailure(err)
	}
	config := wire.Config{
		Payload:     n.payload,
		ModuleType:  int(n.expectedType),
		Runtime:     n.runtime,
		Domain:      n.domain,
		Class:       n.class,
		Method:      n.method,
		Arguments:   n.args,
		Unicode:     n.unicode,
		Entropy:     int(n.entropy),
		Exit:        int(n.exit),
		Compression: int(n.compression),
		Headers:     int(n.headers),
		Thread:      n.thread != 0,
		OEP:         n.forkRVA,
		Decoy:       n.decoy,
		StagingURL:  n.server,
		ModuleName:  n.module,
		UTF8:        true,
	}
	if g.bundle != nil {
		config.Poly, config.APIImports = g.bundle.wireMetadata()
	}
	instance, staged, moduleName, err := wire.Build(config)
	if err != nil {
		return Result{}, classifyWireFailure(err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	raw, err := buildLoaderWithImages(instance, rand.Reader, g.bundle)
	if err != nil {
		return Result{}, &GenerationError{Code: ErrorInvalidConfiguration, Cause: err}
	}
	loader, err := formatLoader(raw, request.Format)
	if err != nil {
		return Result{}, &GenerationError{Code: ErrorInvalidFormat, Cause: err}
	}
	result := Result{Loader: loader}
	if staged != nil {
		moduleURL := *n.moduleURL
		if moduleName != n.module {
			parsedURL, parseErr := url.Parse(n.server + moduleName)
			if parseErr != nil {
				return Result{}, parseErr
			}
			moduleURL = *parsedURL
		}
		result.StagedModule = &StagedModule{Name: moduleName, URL: moduleURL, Data: staged}
	}
	return result, ctx.Err()
}

func classifyValidationFailure(err error) error {
	var validation *ValidationError
	if !errors.As(err, &validation) {
		return &GenerationError{Code: ErrorRandom, Cause: err}
	}
	code := ErrorInvalidConfiguration
	switch validation.Field {
	case "format":
		code = ErrorInvalidFormat
	case "loader.entropy":
		code = ErrorInvalidEntropy
	case "loader.compression":
		code = ErrorCompressionEngine
	case "payload":
		if validation.Problem == "is empty" || validation.Problem == "is required" || validation.Problem == "is nil" {
			code = ErrorFileEmpty
		}
	case "payload.export.name", "payload.export.arguments":
		code = ErrorDLLInvocation
	case "payload.entryPoint.typeName", "payload.entryPoint.methodName":
		code = ErrorDotNetEntryPoint
	case "payload.pe.headers":
		code = ErrorInvalidHeaders
	case "payload.pe.decoyModulePath":
		code = ErrorInvalidDecoy
	case "staging.baseURL":
		code = ErrorInvalidURL
		if strings.HasPrefix(validation.Problem, "exceeds ") {
			code = ErrorURLTooLong
		}
	case "staging.moduleName":
		code = ErrorInvalidURL
	}
	return &GenerationError{Code: code, Cause: err}
}

func classifyWireFailure(err error) error {
	code := ErrorInvalidConfiguration
	var failure *wire.Failure
	if errors.As(err, &failure) {
		switch failure.Kind {
		case wire.FailureFileEmpty:
			code = ErrorFileEmpty
		case wire.FailureFileInvalid:
			code = ErrorFileInvalid
		case wire.FailureArchitectureMismatch:
			code = ErrorArchitectureMismatch
		case wire.FailureMixedAssembly:
			code = ErrorMixedAssembly
		case wire.FailureDLLExport:
			code = ErrorDLLExport
		case wire.FailurePayloadTypeMismatch:
			code = ErrorPayloadTypeMismatch
		case wire.FailureDotNetEntryPoint:
			code = ErrorDotNetEntryPoint
		case wire.FailureCompression:
			code = ErrorCompression
		case wire.FailureRandom:
			code = ErrorRandom
		}
	}
	return &GenerationError{Code: code, Cause: err}
}

// Close prevents later generation calls. Active calls finish first.
func (g *Generator) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	return nil
}
