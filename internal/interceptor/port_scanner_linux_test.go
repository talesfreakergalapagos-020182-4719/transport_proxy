package interceptor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanProcNetFile(t *testing.T) {
	tempDir := t.TempDir()
	mockProcNetTCP := filepath.Join(tempDir, "tcp")

	// Dummy /proc/net/tcp format
	data := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:46D2 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 100 0 0 10 0
   2: 00000000:9C40 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99999 1 0000000000000000 100 0 0 10 0
`
	if err := os.WriteFile(mockProcNetTCP, []byte(data), 0644); err != nil {
		t.Fatalf("failed to write mock tcp file: %v", err)
	}

	result := make(map[string]uint16)
	// port 0050 = 80 (outside range)
	// port 46D2 = 18130 (outside range)
	// port 9C40 = 40000 (inside range 40000-48999)

	scanProcNetFile(mockProcNetTCP, 40000, 48999, result)

	if len(result) != 1 {
		t.Errorf("expected 1 result, got %d", len(result))
	}
	if port, ok := result["99999"]; !ok || port != 40000 {
		t.Errorf("expected inode 99999 to map to port 40000, got %d", port)
	}
}
