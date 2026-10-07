package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sliverarmory/churro"
)

func TestReadBundleDirChecksImagesAndManifest(t *testing.T) {
	dir := t.TempDir()
	bundle := churro.EmbeddedLoaderBundle()
	manifest := bundleManifest{
		Schema: 1, Poly: bundle.Poly, APIImports: bundle.APIImports,
		PEB1Meta: bundle.PEB1Meta, PEB2Meta: bundle.PEB2Meta,
	}
	images := []struct {
		name string
		data []byte
		hash *string
	}{
		{"loader_peb1_exe_x64.bin", bundle.PEB1, &manifest.SHA256.PEB1},
		{"loader_peb2_exe_x64.bin", bundle.PEB2, &manifest.SHA256.PEB2},
		{"dispatch_shim_exe_x64.bin", bundle.DispatchShim, &manifest.SHA256.DispatchShim},
	}
	for _, image := range images {
		if err := os.WriteFile(filepath.Join(dir, image.name), image.data, 0o600); err != nil {
			t.Fatal(err)
		}
		*image.hash = fmt.Sprintf("%x", sha256.Sum256(image.data))
	}
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(manifestPath, manifestData, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := readBundleDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := churro.NewWithLoader(context.Background(), loaded); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, images[0].name), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBundleDir(dir); err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("changed image result = %v", err)
	}
	unsafeManifest := append(append([]byte(nil), manifestData[:len(manifestData)-1]...), []byte(`,"path":"../escape"}`)...)
	if err := os.WriteFile(manifestPath, unsafeManifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBundleDir(dir); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unsafe manifest field result = %v", err)
	}
	if err := os.WriteFile(manifestPath, manifestData, 0o600); err != nil {
		t.Fatal(err)
	}
	imagePath := filepath.Join(dir, images[0].name)
	if err := os.Remove(imagePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, images[1].name), imagePath); err == nil {
		if _, err := readBundleDir(dir); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("symlinked image result = %v", err)
		}
	}
}
