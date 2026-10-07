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
	headers := flag.String("headers", "overwrite", "PE header handling: overwrite or preserve")
	hostRVA := flag.Uint("host-rva", 0, "host continuation RVA (zero disables continuation)")
	flag.Parse()
	if *dll == "" || *export == "" || *out == "" {
		fatalf("-dll, -export, and -out are required")
	}
	var peHeaders churro.PEHeaders
	switch *headers {
	case "overwrite":
		peHeaders = churro.PEHeadersOverwrite
	case "preserve":
		peHeaders = churro.PEHeadersPreserve
	default:
		fatalf("invalid -headers value %q", *headers)
	}
	image, err := os.ReadFile(*dll)
	if err != nil {
		fatalf("read DLL: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var continuation *churro.HostImageContinuation
	if *hostRVA != 0 {
		if *hostRVA > 0xffffffff {
			fatalf("-host-rva exceeds 32 bits")
		}
		continuation = &churro.HostImageContinuation{EntryPointRVA: uint32(*hostRVA)}
	}
	result, err := churro.Generate(ctx, churro.Request{
		Payload: churro.NativeDLL{
			Image:  image,
			Export: &churro.NativeDLLExport{Name: *export},
			PE:     churro.NativePEConfig{Headers: peHeaders},
		},
		Loader: churro.LoaderConfig{HostContinuation: continuation},
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
