//go:build linux

package main

import (
	"os"

	"transport_proxy/internal/interceptor"
)

// isAdmin checks if the current process is running with root privileges on Linux.
func isAdmin() bool {
	return os.Geteuid() == 0
}

func cleanupPlatformRules() error {
	return interceptor.CleanupIPTables()
}
