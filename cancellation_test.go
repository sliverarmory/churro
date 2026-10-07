package churro

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sliverarmory/churro/internal/assets"
)

// pausedContext lets a test stop generation at a checkpoint after CPU work has
// begun. Cancellation happens while the generating goroutine is paused there.
type pausedContext struct {
	context.Context
	pauseAt int32
	checks  atomic.Int32
	reached chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func newPausedContext(parent context.Context, pauseAt int32) *pausedContext {
	return &pausedContext{
		Context: parent,
		pauseAt: pauseAt,
		reached: make(chan struct{}),
		resume:  make(chan struct{}),
	}
}

func (c *pausedContext) Err() error {
	if c.checks.Add(1) == c.pauseAt {
		close(c.reached)
		<-c.resume
	}
	return c.Context.Err()
}

func (c *pausedContext) unpause() { c.once.Do(func() { close(c.resume) }) }

func waitForCancellationTest(t *testing.T, ready <-chan struct{}) {
	t.Helper()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("generation did not reach a mid-flight cancellation checkpoint")
	}
}

func TestGeneratorCancellationDuringCompressionAllowsClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	probe := newPausedContext(ctx, 12)
	defer func() {
		cancel()
		probe.unpause()
	}()
	g := NewGenerator()
	type outcome struct {
		result Result
		err    error
	}
	generated := make(chan outcome, 1)
	go func() {
		result, err := g.Generate(probe, Request{
			Payload: JScript{Source: bytes.Repeat([]byte("ABCD"), 1<<19)},
			Loader:  LoaderConfig{Compression: CompressionAPLib},
		})
		generated <- outcome{result, err}
	}()
	waitForCancellationTest(t, probe.reached)
	if got := probe.checks.Load(); got < 12 {
		t.Fatalf("only %d context checks before cancellation", got)
	}
	closed := make(chan error, 1)
	closeStarted := make(chan struct{})
	go func() {
		close(closeStarted)
		closed <- g.Close()
	}()
	<-closeStarted
	select {
	case err := <-closed:
		t.Fatalf("Close returned while Generate was active: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	probe.unpause()
	select {
	case got := <-generated:
		if !errors.Is(got.err, context.Canceled) || len(got.result.Loader) != 0 || got.result.StagedModule != nil {
			t.Fatalf("canceled Generate = %+v, %v", got.result, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Generate did not stop after cancellation")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not finish after cancellation")
	}
	if _, err := g.Generate(context.Background(), Request{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Generate after Close = %v, want ErrClosed", err)
	}
}

func TestLoaderCancellationDuringByteTransform(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	probe := newPausedContext(ctx, 12)
	defer func() {
		cancel()
		probe.unpause()
	}()
	done := make(chan error, 1)
	go func() {
		_, err := prepareCombinedContext(probe, bytes.Repeat([]byte{0x90}, 1<<20), assets.DispatchShim, repeatByte(0xa5))
		done <- err
	}()
	waitForCancellationTest(t, probe.reached)
	cancel()
	probe.unpause()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("prepareCombinedContext = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("loader byte transform did not stop after cancellation")
	}
}

func TestFormatCancellationDuringTextRendering(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	probe := newPausedContext(ctx, 12)
	defer func() {
		cancel()
		probe.unpause()
	}()
	done := make(chan error, 1)
	go func() {
		_, err := formatLoaderContext(probe, bytes.Repeat([]byte{0xab}, 1<<20), FormatHex)
		done <- err
	}()
	waitForCancellationTest(t, probe.reached)
	cancel()
	probe.unpause()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("formatLoaderContext = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("text rendering did not stop after cancellation")
	}
}
