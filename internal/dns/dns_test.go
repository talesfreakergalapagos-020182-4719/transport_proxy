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

func TestProbeManager_Cache(t *testing.T) {
	client := NewDoHClient(1*time.Second, nil)
	pm := NewProbeManager(client, 1*time.Hour)

	ip := net.ParseIP("192.168.1.1")
	if status := pm.GetStatus(ip); status != StatusUnknown {
		t.Errorf("Expected initial status to be StatusUnknown, got %v", status)
	}

	// Probing non-responsive IP should result in unsupported (or false)
	supported := pm.CheckOrProbe(context.Background(), ip)
	if supported {
		t.Errorf("Expected probe to unresolvable IP to return false")
	}

	if status := pm.GetStatus(ip); status != StatusUnsupported {
		t.Errorf("Expected cached status to be StatusUnsupported, got %v", status)
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

func TestEngine_UpdateConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	_ = os.WriteFile(configPath, []byte(`{
		"doh_enabled": true,
		"doh_timeout_sec": 3,
		"dns_cache_enabled": true,
		"dns_cache_ttl_sec": 300
	}`), 0644)

	mgr, err := config.NewManager(configPath)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Stop()

	eng := NewEngine(mgr, nil, nil)

	// Populate cache with an entry
	dstIP := net.ParseIP("1.1.1.2")
	dummyResp := createTestQuery(0x1111, "example.com", TypeA)
	dummyResp[2] = 0x81
	eng.cache.Set(dstIP, "example.com", TypeA, dummyResp)

	// Verify cache hit
	if _, hit := eng.cache.Get(dstIP, "example.com", TypeA, 0x1111); !hit {
		t.Fatalf("Expected cache hit before update")
	}

	// UpdateConfig with dns_cache_enabled: false (should purge cache) and doh_timeout_sec: 7
	newCfg := &config.Config{
		DohEnabled:      true,
		DohTimeoutSec:   7,
		DNSCacheEnabled: false,
		DNSCacheTTLSec:  60,
	}
	eng.UpdateConfig(newCfg)

	if eng.dohClient.timeout != 7*time.Second {
		t.Errorf("Expected DoH client timeout 7s, got %v", eng.dohClient.timeout)
	}

	// Verify cache was purged
	if _, hit := eng.cache.Get(dstIP, "example.com", TypeA, 0x1111); hit {
		t.Errorf("Expected cache to be purged when DNSCacheEnabled is false")
	}

	// UpdateConfig again enabling cache with new TTL
	newCfg2 := &config.Config{
		DohEnabled:      true,
		DohTimeoutSec:   5,
		DNSCacheEnabled: true,
		DNSCacheTTLSec:  120,
	}
	eng.UpdateConfig(newCfg2)
	if eng.cache.maxTTL != 120*time.Second {
		t.Errorf("Expected cache maxTTL 120s, got %v", eng.cache.maxTTL)
	}
}

func TestDoHClient_SetTimeout(t *testing.T) {
	client := NewDoHClient(3*time.Second, nil)
	client.SetTimeout(8 * time.Second)
	if client.timeout != 8*time.Second {
		t.Errorf("Expected timeout 8s, got %v", client.timeout)
	}
	if client.client.Timeout != 8*time.Second {
		t.Errorf("Expected http.Client timeout 8s, got %v", client.client.Timeout)
	}

	// Zero or negative should fallback to 3s default
	client.SetTimeout(0)
	if client.timeout != 3*time.Second {
		t.Errorf("Expected default timeout 3s, got %v", client.timeout)
	}
}

func TestCache_SetMaxTTL(t *testing.T) {
	cache := NewCache(300 * time.Second)
	cache.SetMaxTTL(60 * time.Second)
	if cache.maxTTL != 60*time.Second {
		t.Errorf("Expected maxTTL 60s, got %v", cache.maxTTL)
	}

	// Zero or negative should fallback to 300s default
	cache.SetMaxTTL(-1)
	if cache.maxTTL != 300*time.Second {
		t.Errorf("Expected default maxTTL 300s, got %v", cache.maxTTL)
	}
}

func TestProbeManager_LoopbackRejection(t *testing.T) {
	client := NewDoHClient(1*time.Second, nil)
	pm := NewProbeManager(client, 1*time.Hour)

	loopbacks := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("127.0.0.53"),
		net.ParseIP("::1"),
		net.ParseIP("0.0.0.0"),
		nil,
	}

	for _, ip := range loopbacks {
		if status := pm.GetStatus(ip); status != StatusUnsupported {
			t.Errorf("Expected GetStatus(%v) to be StatusUnsupported, got %v", ip, status)
		}
		if pm.CheckOrProbe(context.Background(), ip) {
			t.Errorf("Expected CheckOrProbe(%v) to return false for loopback/unspecified IP", ip)
		}
	}
}

func TestProbeManager_PreSeededDoH(t *testing.T) {
	client := NewDoHClient(1*time.Second, nil)
	pm := NewProbeManager(client, 1*time.Hour)

	if status := pm.GetStatus(net.ParseIP("1.1.1.2")); status != StatusSupported {
		t.Errorf("Expected 1.1.1.2 to be pre-seeded as StatusSupported, got %v", status)
	}
	if status := pm.GetStatus(net.ParseIP("1.0.0.2")); status != StatusSupported {
		t.Errorf("Expected 1.0.0.2 to be pre-seeded as StatusSupported, got %v", status)
	}
}

func TestEngine_LoopbackDstIPFallback(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	_ = os.WriteFile(configPath, []byte(`{"doh_enabled": true, "dns_cache_enabled": true}`), 0644)
	mgr, err := config.NewManager(configPath)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Stop()

	filter := &mockFilter{
		blockedHosts: map[string]bool{
			"blocked.com": true,
		},
	}

	eng := NewEngine(mgr, filter, nil)

	clientAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:54321")
	// Pass loopback dstIP (which happens on Linux iptables REDIRECT)
	dstIP := net.ParseIP("127.0.0.1")
	query := createTestQuery(0x7777, "blocked.com", TypeA)

	// Blocked query should be handled properly even when dstIP is 127.0.0.1
	resp, passthrough := eng.ProcessDNSQuery(context.Background(), clientAddr, dstIP, query)
	if passthrough {
		t.Errorf("Expected passthrough=false for blocked domain with loopback dstIP")
	}
	if len(resp) < 12 || resp[3]&0x0F != RCodeNXDomain {
		t.Errorf("Expected NXDOMAIN response")
	}

	// Cache test with loopback dstIP: Pre-populate cache at 1.1.1.2 (sanitized target)
	cacheResp := createTestQuery(0x8888, "cached.com", TypeA)
	cacheResp[2] = 0x81
	eng.cache.Set(net.ParseIP("1.1.1.2"), "cached.com", TypeA, cacheResp)

	queryCached := createTestQuery(0x9999, "cached.com", TypeA)
	hitResp, passthrough := eng.ProcessDNSQuery(context.Background(), clientAddr, dstIP, queryCached)
	if passthrough {
		t.Errorf("Expected cache hit (passthrough=false)")
	}
	if len(hitResp) < 12 || hitResp[0] != 0x99 || hitResp[1] != 0x99 {
		t.Errorf("Expected rewritten ID 0x9999 on cache hit with loopback dstIP")
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

func TestDNSCache_EvictionAndCap(t *testing.T) {
	cache := NewCache(5 * time.Second)

	// Test Stop idempotency
	cache.Stop()
	cache.Stop() // Should not panic

	// Create fresh cache
	cache = NewCache(5 * time.Second)
	defer cache.Stop()

	dstIP := net.ParseIP("1.1.1.2")
	dummyResp := createTestQuery(0x1111, "expired.com", TypeA)
	dummyResp[2] = 0x81

	// Store dummy entry
	cache.Set(dstIP, "expired.com", TypeA, dummyResp)
	if cache.count.Load() != 1 {
		t.Fatalf("Expected count 1, got %d", cache.count.Load())
	}

	// Manually expire entry
	key := makeCacheKey(dstIP, "expired.com", TypeA)
	if val, ok := cache.entries.Load(key); ok {
		entry := val.(*cacheEntry)
		entry.expireAt = time.Now().Add(-1 * time.Second)
	}

	// 1. Test lazy eviction on Get
	_, hit := cache.Get(dstIP, "expired.com", TypeA, 0x1111)
	if hit {
		t.Errorf("Expected cache miss for expired entry")
	}
	if cache.count.Load() != 0 {
		t.Errorf("Expected count 0 after lazy eviction, got %d", cache.count.Load())
	}

	// 2. Test active eviction via evictExpired
	cache.Set(dstIP, "active-expire.com", TypeA, dummyResp)
	if cache.count.Load() != 1 {
		t.Fatalf("Expected count 1, got %d", cache.count.Load())
	}
	key2 := makeCacheKey(dstIP, "active-expire.com", TypeA)
	if val, ok := cache.entries.Load(key2); ok {
		entry := val.(*cacheEntry)
		entry.expireAt = time.Now().Add(-1 * time.Second)
	}
	cache.evictExpired()
	if cache.count.Load() != 0 {
		t.Errorf("Expected count 0 after evictExpired, got %d", cache.count.Load())
	}

	// 3. Test Purge
	cache.Set(dstIP, "purge1.com", TypeA, dummyResp)
	cache.Set(dstIP, "purge2.com", TypeA, dummyResp)
	if cache.count.Load() != 2 {
		t.Fatalf("Expected count 2, got %d", cache.count.Load())
	}
	cache.Purge()
	if cache.count.Load() != 0 {
		t.Errorf("Expected count 0 after Purge, got %d", cache.count.Load())
	}
}

