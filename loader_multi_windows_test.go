//go:build windows && amd64

package churro

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/sliverarmory/churro/internal/assets"
)

const (
	hashStressChildEnv     = "CHURRO_HASH_DISPATCH_CHILD"
	hashStressFirstResult  = 0x11
	hashStressSecondResult = 0x22
	hashStressWaitOK       = 0
	hashStressWaitTimeout  = 0x102
)

var (
	hashStressKernel32              = syscall.NewLazyDLL("kernel32.dll")
	hashStressVirtualAlloc          = hashStressKernel32.NewProc("VirtualAlloc")
	hashStressVirtualProtect        = hashStressKernel32.NewProc("VirtualProtect")
	hashStressVirtualFree           = hashStressKernel32.NewProc("VirtualFree")
	hashStressFlushInstructionCache = hashStressKernel32.NewProc("FlushInstructionCache")
	hashStressGetCurrentProcess     = hashStressKernel32.NewProc("GetCurrentProcess")
	hashStressReadProcessMemory     = hashStressKernel32.NewProc("ReadProcessMemory")
	hashStressWriteProcessMemory    = hashStressKernel32.NewProc("WriteProcessMemory")
	hashStressCreateThread          = hashStressKernel32.NewProc("CreateThread")
	hashStressWaitForSingleObject   = hashStressKernel32.NewProc("WaitForSingleObject")
	hashStressGetExitCodeThread     = hashStressKernel32.NewProc("GetExitCodeThread")
	hashStressCloseHandle           = hashStressKernel32.NewProc("CloseHandle")
)

// TestWindowsProtectedHashConcurrent runs native instructions in a child
// process. A broken dispatcher can fault or spin, so the parent always gets a
// bounded result and a useful Windows process exit code.
func TestWindowsProtectedHashConcurrent(t *testing.T) {
	if os.Getenv(hashStressChildEnv) == "1" {
		for _, seed := range []byte{0xa5, 0x5a} {
			if err := runProtectedHashContention(seed); err != nil {
				t.Fatalf("seed 0x%02x: %v", seed, err)
			}
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWindowsProtectedHashConcurrent$", "-test.v")
	cmd.Env = append(os.Environ(), hashStressChildEnv+"=1")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("native hash contention child exceeded 15 seconds: %v; output:\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("native hash contention child failed: %v; output:\n%s", err, output)
	}
	t.Logf("native hash contention child passed:\n%s", output)
}

func runProtectedHashContention(seed byte) error {
	// .text is a resident wrapper with Win64 shadow space around its call
	// into .hash_ch. The target assigns each call an arrival number, then
	// waits on a separate release word. Both calls use one image and table.
	const hashOffset = 4096
	hashBody := []byte{
		0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
		0xf0, 0x0f, 0xc1, 0x01, // lock xadd dword ptr [rcx], eax
		0x85, 0xc0, // test old entry count in eax
		0x75, 0x0d, // jnz second caller
		0x8b, 0x41, 0x04, // first: mov eax, [rcx+4]
		0x85, 0xc0, // test eax, eax
		0x74, 0xf9, // jz first
		0xb8, 0x11, 0x00, 0x00, 0x00, // mov eax, hashStressFirstResult
		0xc3,             // ret
		0x8b, 0x41, 0x08, // second: mov eax, [rcx+8]
		0x85, 0xc0, // test eax, eax
		0x74, 0xf9, // jz second
		0xb8, 0x22, 0x00, 0x00, 0x00, // mov eax, hashStressSecondResult
		0xc3, // ret
	}
	image := make([]byte, hashOffset+len(hashBody))
	copy(image, []byte{0x48, 0x83, 0xec, 0x28, 0xe8}) // sub rsp, 40; call
	binary.LittleEndian.PutUint32(image[5:9], hashOffset-9)
	copy(image[9:], []byte{0x48, 0x83, 0xc4, 0x28, 0xc3}) // add rsp, 40; ret
	copy(image[hashOffset:], hashBody)
	meta := LoaderMetadata{
		Functions: []LoaderFunction{
			{Offset: 0, Size: 14, SinglePage: true, Name: ".text"},
			{Offset: hashOffset, Size: uint32(len(hashBody)), SinglePage: true, Name: ".hash_ch"},
		},
		References: []LoaderReference{{SrcBlobOff: 4, InstLength: 5, DispOffset: 1, SrcFn: 0, TargetFn: 1}},
	}
	combined, err := prepareCombinedWithMetadata(image, assets.DispatchShim, meta, repeatByte(seed))
	if err != nil {
		return fmt.Errorf("prepare actual protected dispatcher: %w", err)
	}
	const shimPadded = 4096
	if len(assets.DispatchShim) > shimPadded {
		return fmt.Errorf("test requires a one-page dispatch shim")
	}
	marker := []byte{0xb1, 0x7a, 0x7e, 0xf1, 0xb1, 0x7a, 0x7e, 0xf1}
	ft := bytes.Index(assets.DispatchShim, marker)
	if ft < 0 {
		return fmt.Errorf("dispatch shim function table marker is missing")
	}
	// FN_ENTRY is 12 bytes; its aligned final word contains key and flags
	// followed by the reserved 16-bit transition-lock/active-count state.
	stateWordOffset := ft + 16 + 12 + 8
	if stateWordOffset%4 != 0 {
		return fmt.Errorf("dispatcher state word is unaligned")
	}
	if combined[stateWordOffset+1] != 0 || binary.LittleEndian.Uint16(combined[stateWordOffset+2:]) != 0 {
		return fmt.Errorf("protected section did not start with an empty dispatch state")
	}
	wantCiphertext := bytes.Clone(combined[shimPadded+hashOffset : shimPadded+hashOffset+len(hashBody)])
	if bytes.Equal(wantCiphertext, hashBody) {
		return fmt.Errorf("synthetic hash section was not encrypted")
	}

	const memCommitReserve = 0x3000
	const pageReadWrite = 0x04
	const pageExecuteReadWrite = 0x40
	code, _, callErr := hashStressVirtualAlloc.Call(0, uintptr(len(combined)), memCommitReserve, pageReadWrite)
	if code == 0 {
		return fmt.Errorf("VirtualAlloc code: %v", callErr)
	}
	// The child owns these mappings until exit if an assertion fails while a
	// native thread is running. Successful runs release them after both joins.
	shared, _, callErr := hashStressVirtualAlloc.Call(0, 12, memCommitReserve, pageReadWrite)
	if shared == 0 {
		return fmt.Errorf("VirtualAlloc shared counters: %v", callErr)
	}
	if err := hashStressWriteMemory(code, combined); err != nil {
		return fmt.Errorf("copy dispatcher image: %w", err)
	}
	var oldProtect uint32
	ok, _, callErr := hashStressVirtualProtect.Call(code, uintptr(len(combined)), pageExecuteReadWrite, uintptr(unsafe.Pointer(&oldProtect)))
	if ok == 0 {
		return fmt.Errorf("VirtualProtect code: %v", callErr)
	}
	process, _, _ := hashStressGetCurrentProcess.Call()
	ok, _, callErr = hashStressFlushInstructionCache.Call(process, code, uintptr(len(combined)))
	if ok == 0 {
		return fmt.Errorf("FlushInstructionCache: %v", callErr)
	}
	readEntered := func() (uint32, error) { return hashStressReadUint32(shared) }
	readState := func() (uint16, error) {
		word, err := hashStressReadUint32(code + uintptr(stateWordOffset))
		return uint16(word >> 16), err
	}
	first, _, callErr := hashStressCreateThread.Call(0, 0, code+shimPadded, shared, 0, 0)
	if first == 0 {
		return fmt.Errorf("CreateThread first: %v", callErr)
	}
	if err := waitForHashState("first", readEntered, readState, 1, 1); err != nil {
		return err
	}
	if got, err := hashStressReadMemory(code+shimPadded+hashOffset, len(hashBody)); err != nil || !bytes.Equal(got, hashBody) {
		return fmt.Errorf("first active call did not leave the hash section decrypted")
	}
	second, _, callErr := hashStressCreateThread.Call(0, 0, code+shimPadded, shared, 0, 0)
	if second == 0 {
		return fmt.Errorf("CreateThread second: %v", callErr)
	}
	// The first target cannot return until its release is set. Observing
	// count 2 while both releases are 0 proves a second thread entered this same
	// protected section while the first call remained active.
	if err := waitForHashState("second", readEntered, readState, 2, 2); err != nil {
		return err
	}
	firstRelease, firstErr := hashStressReadUint32(shared + 4)
	secondRelease, secondErr := hashStressReadUint32(shared + 8)
	if firstErr != nil || secondErr != nil || firstRelease != 0 || secondRelease != 0 {
		return fmt.Errorf("release changed before overlap was observed")
	}
	if got, err := hashStressReadMemory(code+shimPadded+hashOffset, len(hashBody)); err != nil || !bytes.Equal(got, hashBody) {
		return fmt.Errorf("concurrent calls corrupted the decrypted hash section")
	}
	if err := hashStressWriteUint32(shared+8, 1); err != nil {
		return fmt.Errorf("release second caller: %w", err)
	}
	if err := joinHashThread("second", second, hashStressSecondResult); err != nil {
		return err
	}
	if err := waitForHashState("first still active", readEntered, readState, 2, 1); err != nil {
		return err
	}
	if wait, _, _ := hashStressWaitForSingleObject.Call(first, 0); wait != hashStressWaitTimeout {
		return fmt.Errorf("first caller did not remain active while second returned: wait=0x%x", wait)
	}
	if got, err := hashStressReadMemory(code+shimPadded+hashOffset, len(hashBody)); err != nil || !bytes.Equal(got, hashBody) {
		return fmt.Errorf("second return encrypted code still used by first caller")
	}
	if err := hashStressWriteUint32(shared+4, 1); err != nil {
		return fmt.Errorf("release first caller: %w", err)
	}
	if err := joinHashThread("first", first, hashStressFirstResult); err != nil {
		return err
	}
	if err := waitForHashState("completed", readEntered, readState, 2, 0); err != nil {
		return err
	}
	if got, err := hashStressReadMemory(code+shimPadded+hashOffset, len(hashBody)); err != nil || !bytes.Equal(got, wantCiphertext) {
		return fmt.Errorf("hash section did not return to its original ciphertext")
	}
	hashStressCloseHandle.Call(first)
	hashStressCloseHandle.Call(second)
	hashStressVirtualFree.Call(shared, 0, 0x8000)
	hashStressVirtualFree.Call(code, 0, 0x8000)
	fmt.Printf("PASS protected hash dispatch seed=0x%02x overlapping=2 returns=0x%x,0x%x state=0 ciphertext=restored\n", seed, hashStressFirstResult, hashStressSecondResult)
	return nil
}

func waitForHashState(label string, entered func() (uint32, error), state func() (uint16, error), wantEntered uint32, wantState uint16) error {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		count, err := entered()
		if err != nil {
			return fmt.Errorf("%s read entry count: %w", label, err)
		}
		active, err := state()
		if err != nil {
			return fmt.Errorf("%s read dispatch state: %w", label, err)
		}
		if count == wantEntered && active == wantState {
			return nil
		}
		time.Sleep(time.Millisecond)
	}
	count, _ := entered()
	active, _ := state()
	return fmt.Errorf("%s overlap timed out: entered=%d state=0x%04x, want entered=%d state=%d",
		label, count, active, wantEntered, wantState)
}

func hashStressReadMemory(address uintptr, size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("invalid read size %d", size)
	}
	data := make([]byte, size)
	process, _, _ := hashStressGetCurrentProcess.Call()
	var read uintptr
	ok, _, callErr := hashStressReadProcessMemory.Call(process, address,
		uintptr(unsafe.Pointer(&data[0])), uintptr(size), uintptr(unsafe.Pointer(&read)))
	if ok == 0 || read != uintptr(size) {
		return nil, fmt.Errorf("ReadProcessMemory at 0x%x: bytes=%d: %v", address, read, callErr)
	}
	return data, nil
}

func hashStressReadUint32(address uintptr) (uint32, error) {
	data, err := hashStressReadMemory(address, 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(data), nil
}

func hashStressWriteMemory(address uintptr, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty write")
	}
	process, _, _ := hashStressGetCurrentProcess.Call()
	var written uintptr
	ok, _, callErr := hashStressWriteProcessMemory.Call(process, address,
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&written)))
	if ok == 0 || written != uintptr(len(data)) {
		return fmt.Errorf("WriteProcessMemory at 0x%x: bytes=%d: %v", address, written, callErr)
	}
	return nil
}

func hashStressWriteUint32(address uintptr, value uint32) error {
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], value)
	return hashStressWriteMemory(address, data[:])
}

func joinHashThread(label string, thread uintptr, want uint32) error {
	wait, _, callErr := hashStressWaitForSingleObject.Call(thread, 3000)
	if wait != hashStressWaitOK {
		return fmt.Errorf("%s WaitForSingleObject=0x%x: %v", label, wait, callErr)
	}
	var exitCode uint32
	ok, _, callErr := hashStressGetExitCodeThread.Call(thread, uintptr(unsafe.Pointer(&exitCode)))
	if ok == 0 {
		return fmt.Errorf("%s GetExitCodeThread: %v", label, callErr)
	}
	if exitCode != want {
		return fmt.Errorf("%s returned 0x%x, want 0x%x", label, exitCode, want)
	}
	return nil
}
