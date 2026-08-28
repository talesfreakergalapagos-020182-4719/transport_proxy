package dns

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"transport_proxy/internal/config"
)

type mockFilter struct {
	blockedHosts map[string]bool
}

func (m *mockFilter) ShouldBlock(hostOrIP string) bool {
	return m.blockedHosts[hostOrIP]
}

func createTestQuery(id uint16, qname string, qtype uint16) []byte {
	var buf []byte
	// Header (12 bytes)
	h := make([]byte, 12)
	h[0] = byte(id >> 8)
	h[1] = byte(id & 0xFF)
	h[2] = 0x01 // RD = 1
	h[3] = 0x00
	h[4] = 0x00 // QDCOUNT = 1
	h[5] = 0x01
	buf = append(buf, h...)

	// QNAME
	parts := splitDomain(qname)
	for _, p := range parts {
		buf = append(buf, byte(len(p)))
		buf = append(buf, []byte(p)...)
	}
	buf = append(buf, 0x00)

	// QTYPE + QCLASS
	buf = append(buf, byte(qtype>>8), byte(qtype&0xFF))
	buf = append(buf, 0x00, 0x01) // Class IN

	return buf
}

func splitDomain(d string) []string {
	var res []string
	start := 0
	for i := 0; i < len(d); i++ {
		if d[i] == '.' {
			if i > start {
				res = append(res, d[start:i])
			}
			start = i + 1
		}
	}
	if start < len(d) {
		res = append(res, d[start:])
	}
	return res
}

func TestParseQuery(t *testing.T) {
	q := createTestQuery(0x1234, "github.com", TypeA)
	msg, err := ParseQuery(q)
	if err != nil {
		t.Fatalf("ParseQuery failed: %v", err)
	}

	if msg.Header.ID != 0x1234 {
		t.Errorf("Expected ID 0x1234, got 0x%x", msg.Header.ID)
	}
	if len(msg.Questions) != 1 {
		t.Fatalf("Expected 1 question, got %d", len(msg.Questions))
	}
	if msg.Questions[0].Name != "github.com" {
		t.Errorf("Expected qname 'github.com', got %q", msg.Questions[0].Name)
	}
	if msg.Questions[0].Type != TypeA {
		t.Errorf("Expected qtype %d, got %d", TypeA, msg.Questions[0].Type)
	}
}

func TestBuildErrorResponse(t *testing.T) {
	q := createTestQuery(0xABCD, "blocked.com", TypeA)
	resp := BuildErrorResponse(q, RCodeNXDomain)

	if len(resp) < 12 {
		t.Fatalf("Response too short: %d bytes", len(resp))
	}
	// Verify ID
	if resp[0] != 0xAB || resp[1] != 0xCD {
		t.Errorf("Expected ID 0xABCD, got 0x%02x%02x", resp[0], resp[1])
	}
	// Verify QR=1
	if resp[2]&0x80 == 0 {
		t.Errorf("Expected QR=1 in response")
	}
	// Verify RCODE=3 (NXDOMAIN)
	if resp[3]&0x0F != RCodeNXDomain {
		t.Errorf("Expected RCODE 3, got %d", resp[3]&0x0F)
	}
}

func TestDNSCache(t *testing.T) {
	cache := NewCache(10 * time.Second)
	dstIP := net.ParseIP("1.1.1.2")

	// Store dummy response with ID 0x1111
	dummyResp := createTestQuery(0x1111, "example.com", TypeA)
	dummyResp[2] = 0x81 // Mark as response
	cache.Set(dstIP, "example.com", TypeA, dummyResp)

	// Lookup with new client ID 0x2222
	retResp, hit := cache.Get(dstIP, "example.com", TypeA, 0x2222)
	if !hit {
		t.Fatalf("Expected cache hit")
	}
	if retResp[0] != 0x22 || retResp[1] != 0x22 {
		t.Errorf("Expected rewritten ID 0x2222, got 0x%02x%02x", retResp[0], retResp[1])
	}

	// Lookup different domain -> miss
	_, hit = cache.Get(dstIP, "other.com", TypeA, 0x3333)
	if hit {
		t.Errorf("Expected cache miss for other.com")
	}
}

func TestProbeManager_PrivateIP(t *testing.T) {
	client := NewDoHClient(1*time.Second, nil)
	pm := NewProbeManager(client, 1*time.Hour)

	privateIPs := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.5.1",
		"127.0.0.1",
		"fe80::1",
	}

	for _, ipStr := range privateIPs {
		ip := net.ParseIP(ipStr)
		if !pm.IsPrivateIP(ip) {
			t.Errorf("Expected %s to be recognized as private IP", ipStr)
		}
		if pm.CheckOrProbe(context.Background(), ip) {
			t.Errorf("Expected private IP %s to return false (unsupported/passthrough)", ipStr)
		}
	}

	publicIP := net.ParseIP("1.1.1.2")
	if pm.IsPrivateIP(publicIP) {
		t.Errorf("Public IP %s was incorrectly marked as private", publicIP)
	}
}

func TestEngine_PolicyBlock(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	_ = os.WriteFile(configPath, []byte(`{"doh_enabled": true}`), 0644)
	mgr, err := config.NewManager(configPath)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Stop()

	filter := &mockFilter{
		blockedHosts: map[string]bool{
			"malware.com": true,
		},
	}

	eng := NewEngine(mgr, filter, nil)

	clientAddr, _ := net.ResolveUDPAddr("udp", "192.168.1.50:54321")
	dstIP := net.ParseIP("8.8.8.8")
	query := createTestQuery(0x5555, "malware.com", TypeA)

	resp, passthrough := eng.ProcessDNSQuery(context.Background(), clientAddr, dstIP, query)
	if passthrough {
		t.Errorf("Expected passthrough to be false for blocked domain")
	}
	if len(resp) < 12 {
		t.Fatalf("Expected valid error response, got %d bytes", len(resp))
	}
	if resp[3]&0x0F != RCodeNXDomain {
		t.Errorf("Expected NXDOMAIN (3), got %d", resp[3]&0x0F)
	}
}

func BenchmarkDNSCache_Get(b *testing.B) {
	cache := NewCache(10 * time.Minute)
	dstIP := net.ParseIP("1.1.1.2")
	dummyResp := createTestQuery(0x1111, "github.com", TypeA)
	dummyResp[2] = 0x81
	cache.Set(dstIP, "github.com", TypeA, dummyResp)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cache.Get(dstIP, "github.com", TypeA, uint16(i))
	}
}
