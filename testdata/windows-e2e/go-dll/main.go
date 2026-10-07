package main

import "C"

import (
	"os"
)

//export HelloWorld
func HelloWorld() {
	prefix := os.Getenv("CHURRO_E2E_PREFIX")
	if prefix == "" {
		return
	}
	_ = os.WriteFile(prefix+".go", []byte("hello from Go DLL"), 0o600)
}

func main() {}
