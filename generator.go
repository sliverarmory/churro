package churro

import (
	"context"
	"crypto/rand"
	"net/url"
	"sync"

	"github.com/sliverarmory/churro/internal/wire"
)

// Generator builds Windows x64 loaders from payload bytes. Calls may run
// concurrently. It retains no payload bytes between calls.
type Generator struct {
	mu     sync.RWMutex
	closed bool
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
		return Result{}, err
	}
	instance, staged, moduleName, err := wire.Build(wire.Config{
		Payload:    n.payload,
		ModuleType: int(n.expectedType),
		Runtime:    n.runtime,
		Domain:     n.domain,
		Class:      n.class,
		Method:     n.method,
		Entropy:    int(n.entropy),
		Exit:       int(n.exit),
		Headers:    int(n.headers),
		Thread:     n.thread != 0,
		OEP:        n.forkRVA,
		Decoy:      n.decoy,
		StagingURL: n.server,
		ModuleName: n.module,
		UTF8:       true,
	})
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	raw, err := buildLoader(instance, rand.Reader)
	if err != nil {
		return Result{}, err
	}
	loader, err := formatLoader(raw, request.Format)
	if err != nil {
		return Result{}, err
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

// Close prevents later generation calls. Active calls finish first.
func (g *Generator) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	return nil
}
