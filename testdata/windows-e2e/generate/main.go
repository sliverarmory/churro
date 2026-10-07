package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sliverarmory/churro"
)

func main() {
	dll := flag.String("dll", "", "path to a native x64 Windows DLL")
	export := flag.String("export", "", "parameterless export to invoke")
	out := flag.String("out", "", "path for raw shellcode")
	flag.Parse()
	if *dll == "" || *export == "" || *out == "" {
		fatalf("-dll, -export, and -out are required")
	}
	image, err := os.ReadFile(*dll)
	if err != nil {
		fatalf("read DLL: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, err := churro.Generate(ctx, churro.Request{
		Payload: churro.NativeDLL{
			Image:  image,
			Export: &churro.NativeDLLExport{Name: *export},
		},
	})
	if err != nil {
		fatalf("generate loader: %v", err)
	}
	if len(result.Loader) == 0 {
		fatalf("generator returned an empty loader")
	}
	if err := os.WriteFile(*out, result.Loader, 0o600); err != nil {
		fatalf("write loader: %v", err)
	}
	fmt.Printf("generated %s (%d bytes)\n", *out, len(result.Loader))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
