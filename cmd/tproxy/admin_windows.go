//go:build windows

package main

import "syscall"

var (
	modShell32        = syscall.NewLazyDLL("shell32.dll")
	procIsUserAnAdmin = modShell32.NewProc("IsUserAnAdmin")
)

// isAdmin checks if the current process is running with elevated Administrator privileges on Windows.
func isAdmin() bool {
	r, _, _ := procIsUserAnAdmin.Call()
	return r != 0
}

func cleanupPlatformRules() error {
	return nil
}
