//go:build !windows

package main

func copyBase64ToClipboard([]byte) error {
	return nil
}
