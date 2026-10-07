package churro

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPEPackerReferences(t *testing.T) {
	zig, err := exec.LookPath("zig")
	if err != nil {
		t.Skip("Zig is unavailable for the native PE packer fixture")
	}
	exe := filepath.Join(t.TempDir(), "pack-test")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	build := exec.Command(zig, "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
		"-I", filepath.Join("internal", "loader", "exe2h"),
		filepath.Join("internal", "loader", "exe2h", "pack_test.c"),
		"-o", exe)
	build.Env = append(build.Environ(),
		"ZIG_GLOBAL_CACHE_DIR="+filepath.Join(t.TempDir(), "zig-global-cache"),
		"ZIG_LOCAL_CACHE_DIR="+filepath.Join(t.TempDir(), "zig-local-cache"))
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build native packer fixture: %v\n%s", err, out)
	}
	run := exec.Command(exe)
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("run native packer fixture: %v\n%s", err, out)
	}
}
