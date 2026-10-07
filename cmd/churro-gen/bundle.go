package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sliverarmory/churro"
)

const maxBundleImageBytes = 16 << 20
const maxBundleManifestBytes = 256 << 10

type bundleManifest struct {
	Schema     int                   `json:"schema"`
	Poly       churro.PolyConfig     `json:"poly"`
	APIImports []churro.APIImport    `json:"api_imports"`
	PEB1Meta   churro.LoaderMetadata `json:"peb1_metadata"`
	PEB2Meta   churro.LoaderMetadata `json:"peb2_metadata"`
	SHA256     struct {
		PEB1         string `json:"peb1"`
		PEB2         string `json:"peb2"`
		DispatchShim string `json:"dispatch_shim"`
	} `json:"sha256"`
}

func readBundleDir(dir string) (churro.LoaderBundle, error) {
	manifestData, err := readRegularBundleFile(dir, "bundle.json", maxBundleManifestBytes)
	if err != nil {
		return churro.LoaderBundle{}, err
	}
	var manifest bundleManifest
	decoder := json.NewDecoder(bytes.NewReader(manifestData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return churro.LoaderBundle{}, fmt.Errorf("parse loader bundle manifest: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return churro.LoaderBundle{}, errors.New("loader bundle manifest must contain exactly one JSON object")
	}
	if manifest.Schema != 1 {
		return churro.LoaderBundle{}, fmt.Errorf("unsupported loader bundle schema %d", manifest.Schema)
	}
	images := []struct {
		name string
		hash string
		dest *[]byte
	}{
		{name: "loader_peb1_exe_x64.bin", hash: manifest.SHA256.PEB1},
		{name: "loader_peb2_exe_x64.bin", hash: manifest.SHA256.PEB2},
		{name: "dispatch_shim_exe_x64.bin", hash: manifest.SHA256.DispatchShim},
	}
	bundle := churro.LoaderBundle{
		Poly: manifest.Poly, APIImports: manifest.APIImports,
		PEB1Meta: manifest.PEB1Meta, PEB2Meta: manifest.PEB2Meta,
	}
	images[0].dest = &bundle.PEB1
	images[1].dest = &bundle.PEB2
	images[2].dest = &bundle.DispatchShim
	for _, image := range images {
		if len(image.hash) != 64 || strings.ToLower(image.hash) != image.hash {
			return churro.LoaderBundle{}, fmt.Errorf("invalid SHA-256 for %s", image.name)
		}
		data, err := readRegularBundleFile(dir, image.name, maxBundleImageBytes)
		if err != nil {
			return churro.LoaderBundle{}, err
		}
		actual := fmt.Sprintf("%x", sha256.Sum256(data))
		if actual != image.hash {
			return churro.LoaderBundle{}, fmt.Errorf("SHA-256 mismatch for %s", image.name)
		}
		*image.dest = data
	}
	return bundle, nil
}

func readRegularBundleFile(dir, name string, maxBytes int64) ([]byte, error) {
	if filepath.Base(name) != name || name == "." || name == ".." {
		return nil, errors.New("unsafe loader bundle filename")
	}
	path := filepath.Join(dir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxBytes {
		return nil, fmt.Errorf("%s must be a regular file of at most %d bytes", path, maxBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, maxBytes)
	}
	return data, nil
}
