//go:build windows

package main

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

var errClipboardUnavailable = errors.New("interactive clipboard unavailable")

const (
	clipboardCFText       = 1
	clipboardGMEMMoveable = 0x0002
	clipboardGMEMZeroInit = 0x0040
	clipboardWSPopup      = 0x80000000
)

var (
	clipboardUser32      = syscall.NewLazyDLL("user32.dll")
	clipboardKernel32    = syscall.NewLazyDLL("kernel32.dll")
	clipboardNtdll       = syscall.NewLazyDLL("ntdll.dll")
	procCreateWindowExW  = clipboardUser32.NewProc("CreateWindowExW")
	procDestroyWindow    = clipboardUser32.NewProc("DestroyWindow")
	procOpenClipboard    = clipboardUser32.NewProc("OpenClipboard")
	procCloseClipboard   = clipboardUser32.NewProc("CloseClipboard")
	procEmptyClipboard   = clipboardUser32.NewProc("EmptyClipboard")
	procSetClipboardData = clipboardUser32.NewProc("SetClipboardData")
	procGetModuleHandleW = clipboardKernel32.NewProc("GetModuleHandleW")
	procGlobalAlloc      = clipboardKernel32.NewProc("GlobalAlloc")
	procGlobalLock       = clipboardKernel32.NewProc("GlobalLock")
	procGlobalUnlock     = clipboardKernel32.NewProc("GlobalUnlock")
	procGlobalFree       = clipboardKernel32.NewProc("GlobalFree")
	procRtlMoveMemory    = clipboardNtdll.NewProc("RtlMoveMemory")
)

// copyBase64ToClipboard uses CF_TEXT because Base64 is ASCII and Fritter uses
// the same format. The caller treats all failures as a best-effort miss.
func copyBase64ToClipboard(data []byte) error {
	// Clipboard ownership transfers only after SetClipboardData succeeds.
	if len(data) != 0 {
		if err := procRtlMoveMemory.Find(); err != nil {
			return fmt.Errorf("RtlMoveMemory: %w", err)
		}
	}
	// Zero-initialization supplies the NUL terminator required by CF_TEXT.
	handle, _, err := procGlobalAlloc.Call(clipboardGMEMMoveable|clipboardGMEMZeroInit, uintptr(len(data)+1))
	if handle == 0 {
		return fmt.Errorf("GlobalAlloc: %w", err)
	}
	transferred := false
	defer func() {
		if !transferred {
			procGlobalFree.Call(handle)
		}
	}()

	ptr, _, err := procGlobalLock.Call(handle)
	if ptr == 0 {
		return fmt.Errorf("GlobalLock: %w", err)
	}
	if len(data) != 0 {
		procRtlMoveMemory.Call(ptr, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)))
		runtime.KeepAlive(data)
	}
	procGlobalUnlock.Call(handle)

	// EmptyClipboard requires a real owner window before SetClipboardData.
	// Create and destroy this hidden window on the same OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	instance, _, err := procGetModuleHandleW.Call(0)
	if instance == 0 {
		return fmt.Errorf("GetModuleHandleW: %w", err)
	}
	className, err := syscall.UTF16PtrFromString("STATIC")
	if err != nil {
		return err
	}
	window, _, callErr := procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(className)), 0, clipboardWSPopup,
		0, 0, 0, 0, 0, 0, instance, 0,
	)
	runtime.KeepAlive(className)
	if window == 0 {
		if errors.Is(callErr, syscall.ERROR_ACCESS_DENIED) {
			return fmt.Errorf("%w: CreateWindowExW: %v", errClipboardUnavailable, callErr)
		}
		return fmt.Errorf("CreateWindowExW: %w", callErr)
	}
	defer procDestroyWindow.Call(window)

	opened, _, err := procOpenClipboard.Call(window)
	if opened == 0 {
		if errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
			return fmt.Errorf("%w: OpenClipboard: %v", errClipboardUnavailable, err)
		}
		return fmt.Errorf("OpenClipboard: %w", err)
	}
	defer procCloseClipboard.Call()
	cleared, _, err := procEmptyClipboard.Call()
	if cleared == 0 {
		return fmt.Errorf("EmptyClipboard: %w", err)
	}
	set, _, err := procSetClipboardData.Call(clipboardCFText, handle)
	if set == 0 {
		return fmt.Errorf("SetClipboardData: %w", err)
	}
	transferred = true
	return nil
}
