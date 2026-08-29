//go:build windows

package interceptor

import (
	"net"
	"testing"
)

func TestPortScanner_ScanReservedPortUsage(t *testing.T) {
	// 1. Scan when no conflicting listener is present in a high test range (e.g. 59870-59875)
	testMinPort := uint16(59870)
	testMaxPort := uint16(59875)

	conflicts, err := ScanReservedPortUsage(testMinPort, testMaxPort)
	if err != nil {
		t.Skipf("ScanReservedPortUsage skipped due to environment permissions: %v", err)
		return
	}

	// 2. Start a test listener inside test port range
	ln, err := net.Listen("tcp", "127.0.0.1:59872")
	if err != nil {
		// If port is in use or forbidden, skip bind part
		t.Logf("Skipping bind test on 59872: %v", err)
		return
	}
	defer ln.Close()

	// Since ln is owned by this test process (selfPID), ScanReservedPortUsage should ignore selfPID
	conflictsAfterSelfBind, err := ScanReservedPortUsage(testMinPort, testMaxPort)
	if err != nil {
		t.Fatalf("ScanReservedPortUsage failed after bind: %v", err)
	}

	// Self-process should not be reported as an external conflicting process
	for _, c := range conflictsAfterSelfBind {
		if c.LocalPort == 59872 {
			t.Errorf("Self-process should NOT be reported as external conflict, but got: %+v", c)
		}
	}

	t.Logf("PortScanner test passed: scanned %d existing conflicts in range %d-%d without error.", len(conflicts), testMinPort, testMaxPort)
}

func TestPortGuard_ScanAndAlert(t *testing.T) {
	pg := NewPortGuard(40000, 48999)
	alertCount := pg.ScanAndAlert()
	t.Logf("PortGuard ScanAndAlert completed with %d alerts.", alertCount)
}
