//go:build windows

package main

import (
	"bytes"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"
)

func TestWindowsClipboardCFTextReadback(t *testing.T) {
	if os.Getenv("CHURRO_TEST_CLIPBOARD") != "1" {
		t.Skip("set CHURRO_TEST_CLIPBOARD=1 to allow this test to replace the interactive clipboard")
	}
	want := []byte("Q2h1cnJvIGNsaXBib2FyZCB0ZXN0")
	var copyErr error
	for attempt := 0; attempt < 10; attempt++ {
		copyErr = copyBase64ToClipboard(want)
		if copyErr == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if copyErr != nil {
		t.Fatalf("CF_TEXT clipboard write unavailable after bounded retries: %v", copyErr)
	}

	sequence, _, _ := clipboardUser32.NewProc("GetClipboardSequenceNumber").Call()
	var opened uintptr
	var err error
	for attempt := 0; attempt < 10; attempt++ {
		opened, _, err = procOpenClipboard.Call(0)
		if opened != 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if opened == 0 {
		t.Fatalf("clipboard readback unavailable after bounded retries: OpenClipboard: %v", err)
	}
	defer procCloseClipboard.Call()
	if current, _, _ := clipboardUser32.NewProc("GetClipboardSequenceNumber").Call(); sequence != 0 && current != sequence {
		t.Fatal("clipboard changed between write and readback")
	}

	handle, _, err := clipboardUser32.NewProc("GetClipboardData").Call(clipboardCFText)
	if handle == 0 {
		t.Fatalf("GetClipboardData(CF_TEXT): %v", err)
	}
	size, _, err := clipboardKernel32.NewProc("GlobalSize").Call(handle)
	if size < uintptr(len(want)+1) {
		t.Fatalf("GlobalSize = %d, want at least %d: %v", size, len(want)+1, err)
	}
	ptr, _, err := procGlobalLock.Call(handle)
	if ptr == 0 {
		t.Fatalf("GlobalLock: %v", err)
	}
	defer procGlobalUnlock.Call(handle)
	got := make([]byte, len(want)+1)
	procRtlMoveMemory.Call(uintptr(unsafe.Pointer(&got[0])), ptr, uintptr(len(got)))
	runtime.KeepAlive(got)
	if !bytes.Equal(got[:len(want)], want) || got[len(want)] != 0 {
		t.Fatalf("CF_TEXT readback did not match the written NUL-terminated Base64 text")
	}
}
