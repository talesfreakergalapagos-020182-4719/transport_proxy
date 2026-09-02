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

func TestConfigManager_InvalidValuesHandled(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "invalid.json")
	// JSON with negative timeouts and empty required strings
	invalidJSON := `{
		"connect_timeout_sec": -5,
		"idle_timeout_sec": -10,
		"reload_interval_sec": 0
	}`
	if err := os.WriteFile(cfgPath, []byte(invalidJSON), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	mgr, err := NewManager(cfgPath)
	if err != nil {
		t.Fatalf("failed to create config manager: %v", err)
	}
	defer mgr.Stop()
	cfg := mgr.Get()

	if cfg.ConnectTimeoutSec != 10 {
		t.Errorf("expected negative connect timeout to fallback to 10, got %d", cfg.ConnectTimeoutSec)
	}
	if cfg.IdleTimeoutSec != 60 {
		t.Errorf("expected negative idle timeout to fallback to 60, got %d", cfg.IdleTimeoutSec)
	}
	if cfg.ReloadIntervalSec != 5 {
		t.Errorf("expected zero reload interval to fallback to 5, got %d", cfg.ReloadIntervalSec)
	}
}

func TestConfigManager_NonExistentFile(t *testing.T) {
	_, err := NewManager("does_not_exist.json")
	if err == nil {
		t.Error("expected error when loading non-existent config file, got nil")
	}
}

func TestConfig_CorporateProxySettings(t *testing.T) {
	tests := []struct {
		name          string
		jsonConfig    string
		expectedProxy string
		expectedPAC   string
		expectedSSPI  bool
	}{
		{
			name: "Standard HTTP Corporate Proxy",
			jsonConfig: `{
				"upstream_proxy": "http://proxy.corp.example.com:8080",
				"pac_url": ""
			}`,
			expectedProxy: "http://proxy.corp.example.com:8080",
			expectedPAC:   "",
			expectedSSPI:  false,
		},
		{
			name: "Corporate Proxy with IP and Custom Port",
			jsonConfig: `{
				"upstream_proxy": "http://10.20.30.40:3128",
				"pac_url": ""
			}`,
			expectedProxy: "http://10.20.30.40:3128",
			expectedPAC:   "",
			expectedSSPI:  false,
		},
		{
			name: "Corporate PAC Script Configuration",
			jsonConfig: `{
				"upstream_proxy": "",
				"pac_url": "http://pac.corp.internal/wpad.dat"
			}`,
			expectedProxy: "",
			expectedPAC:   "http://pac.corp.internal/wpad.dat",
			expectedSSPI:  false,
		},
		{
			name: "Corporate Proxy with SSPI Disabled (Bypass SSPI)",
			jsonConfig: `{
				"upstream_proxy": "http://proxy.corp.example.com:8080",
				"bypass_sspi": true
			}`,
			expectedProxy: "http://proxy.corp.example.com:8080",
			expectedPAC:   "",
			expectedSSPI:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			cfgPath := filepath.Join(tmpDir, "config.json")
			if err := os.WriteFile(cfgPath, []byte(tt.jsonConfig), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			mgr, err := NewManager(cfgPath)
			if err != nil {
				t.Fatalf("failed to create config manager: %v", err)
			}
			defer mgr.Stop()

			cfg := mgr.Get()
			if cfg.UpstreamProxy != tt.expectedProxy {
				t.Errorf("UpstreamProxy: expected %q, got %q", tt.expectedProxy, cfg.UpstreamProxy)
			}
			if cfg.PacURL != tt.expectedPAC {
				t.Errorf("PacURL: expected %q, got %q", tt.expectedPAC, cfg.PacURL)
			}
			if cfg.BypassSSPI != tt.expectedSSPI {
				t.Errorf("BypassSSPI: expected %v, got %v", tt.expectedSSPI, cfg.BypassSSPI)
			}
		})
	}
}

