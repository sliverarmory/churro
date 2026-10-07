package churro

import (
	"context"
	"errors"
	"testing"
)

func TestGeneratorClosedError(t *testing.T) {
	generator := NewGenerator()
	if err := generator.Close(); err != nil {
		t.Fatal(err)
	}
	if err := generator.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	_, err := generator.Generate(context.Background(), Request{})
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("Generate after Close = %v, want ErrClosed", err)
	}
}

func TestGenerateRequestValidationError(t *testing.T) {
	_, err := Generate(context.Background(), Request{})
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("empty request error = %v, want *ValidationError", err)
	}
	if validation.Field != "payload" {
		t.Fatalf("validation field = %q, want payload", validation.Field)
	}
}

func TestGeneratorContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("New with canceled context = %v", err)
	}
	if _, err := NewGenerator().Generate(ctx, Request{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Generate with canceled context = %v", err)
	}
}
