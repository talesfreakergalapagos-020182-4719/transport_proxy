package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigLoadAndDefaults(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	jsonData := `{
		"pac_url": "http://wpad/proxy.pac",
		"filter_mode": "whitelist",
		"dry_run": true,
		"allowed_domains": ["*.github.com", "golang.org"],
		"allowed_ips": ["192.168.1.0/24"]
	}`

	if err := os.WriteFile(configPath, []byte(jsonData), 0644); err != nil {
		t.Fatalf("Failed to write temp config: %v", err)
	}

	mgr, err := NewManager(configPath)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Stop()

	cfg := mgr.Get()
	if cfg.PacURL != "http://wpad/proxy.pac" {
		t.Errorf("Expected pac_url 'http://wpad/proxy.pac', got %q", cfg.PacURL)
	}
	if !cfg.DryRun {
		t.Errorf("Expected dry_run to be true, got false")
	}
	if cfg.FilterMode != "whitelist" {
		t.Errorf("Expected filter_mode 'whitelist', got %q", cfg.FilterMode)
	}
	if cfg.ListenAddr != "0.0.0.0:18080" { // Default
		t.Errorf("Expected default listen_addr '0.0.0.0:18080', got %q", cfg.ListenAddr)
	}
	if len(cfg.AllowedDomains) != 2 {
		t.Errorf("Expected 2 allowed domains, got %d", len(cfg.AllowedDomains))
	}
}

func TestManagerConcurrentStop(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	_ = os.WriteFile(configPath, []byte(`{"filter_mode":"whitelist"}`), 0644)

	mgr, err := NewManager(configPath)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	mgr.StartAutoReload()

	// Concurrently call Stop() from multiple goroutines - must not panic
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			mgr.Stop()
			done <- struct{}{}
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestBuildDivertFilter(t *testing.T) {
	// 1. Default all-port capture with outbound loop prevention
	cfg := DefaultConfig()
	fwd, full := cfg.BuildDivertFilter(18080)
	if fwd == "" || full == "" {
		t.Fatalf("Expected non-empty filter strings")
	}

	expectedForwardCond := fmt.Sprintf("outbound and tcp and !loopback and tcp.DstPort != 18080 and (tcp.SrcPort < %d or tcp.SrcPort > %d)", OutboundPortMin, OutboundPortMax)
	if fwd != expectedForwardCond {
		t.Errorf("Expected %q, got %q", expectedForwardCond, fwd)
	}

	// 2. Custom DivertFilter override
	cfg.DivertFilter = "outbound and tcp and (tcp.DstPort == 80 or tcp.DstPort == 443)"
	fwdCustom, fullCustom := cfg.BuildDivertFilter(18080)
	if fwdCustom != cfg.DivertFilter {
		t.Fatalf("Expected custom forward filter %q, got %q", cfg.DivertFilter, fwdCustom)
	}
	if fullCustom == "" {
		t.Fatalf("Expected non-empty full custom filter")
	}

	// Verify parentheses balance in generated filter string
	openCount := 0
	closeCount := 0
	for _, ch := range fullCustom {
		if ch == '(' {
			openCount++
		} else if ch == ')' {
			closeCount++
		}
	}
	if openCount != closeCount {
		t.Fatalf("Unbalanced parentheses in fullCustom filter: open=%d, close=%d (filter=%q)", openCount, closeCount, fullCustom)
	}
}
