package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestConfig_HotReload_DynamicFields(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	initialJSON := `{
		"filter_mode": "whitelist",
		"allowed_domains": ["example.com"],
		"dns_servers": ["8.8.8.8"],
		"doh_timeout_sec": 3,
		"reload_interval_sec": 5,
		"log_file": "old.log"
	}`
	if err := os.WriteFile(cfgPath, []byte(initialJSON), 0644); err != nil {
		t.Fatalf("failed to write initial config: %v", err)
	}

	mgr, err := NewManager(cfgPath)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Stop()

	reloaded := make(chan *Config, 1)
	mgr.OnReload(func(newCfg *Config) {
		reloaded <- newCfg
	})

	// Update file with new parameters
	updatedJSON := `{
		"filter_mode": "blacklist",
		"allowed_domains": [],
		"blocked_domains": ["bad.com"],
		"dns_servers": ["1.1.1.1", "1.0.0.1"],
		"doh_timeout_sec": 8,
		"reload_interval_sec": 2,
		"log_file": "new.log"
	}`
	// Ensure file modification time is in the future for drvfs/9p/NTFS cross-platform compatibility
	if err := os.WriteFile(cfgPath, []byte(updatedJSON), 0644); err != nil {
		t.Fatalf("failed to write updated config: %v", err)
	}
	futureTime := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(cfgPath, futureTime, futureTime)

	mgr.checkAndReload()

	select {
	case newCfg := <-reloaded:
		if newCfg.FilterMode != "blacklist" {
			t.Errorf("Expected filter_mode 'blacklist', got %q", newCfg.FilterMode)
		}
		if len(newCfg.DNSServers) != 2 || newCfg.DNSServers[0] != "1.1.1.1" {
			t.Errorf("Expected dns_servers [1.1.1.1, 1.0.0.1], got %v", newCfg.DNSServers)
		}
		if newCfg.DohTimeoutSec != 8 {
			t.Errorf("Expected doh_timeout_sec 8, got %d", newCfg.DohTimeoutSec)
		}
		if newCfg.ReloadIntervalSec != 2 {
			t.Errorf("Expected reload_interval_sec 2, got %d", newCfg.ReloadIntervalSec)
		}
		if newCfg.LogFile != "new.log" {
			t.Errorf("Expected log_file 'new.log', got %q", newCfg.LogFile)
		}
	default:
		t.Fatalf("OnReload callback was not triggered on checkAndReload")
	}
}

func TestConfig_SampleFileValidation(t *testing.T) {
	// Locate config.json.sample in project root
	samplePath := filepath.Join("..", "..", "config.json.sample")
	mgr, err := NewManager(samplePath)
	if err != nil {
		t.Fatalf("Failed to parse config.json.sample: %v", err)
	}
	defer mgr.Stop()

	cfg := mgr.Get()
	if cfg.ListenAddr != "0.0.0.0:18080" {
		t.Errorf("Expected listen_addr 0.0.0.0:18080, got %q", cfg.ListenAddr)
	}
	if cfg.FilterMode != "whitelist" {
		t.Errorf("Expected filter_mode whitelist, got %q", cfg.FilterMode)
	}
	if !cfg.DohEnabled {
		t.Errorf("Expected doh_enabled true, got %v", cfg.DohEnabled)
	}
	if cfg.DohTimeoutSec != 3 {
		t.Errorf("Expected doh_timeout_sec 3, got %d", cfg.DohTimeoutSec)
	}
	if !cfg.FallbackToUDP {
		t.Errorf("Expected fallback_to_udp true, got %v", cfg.FallbackToUDP)
	}
	if !cfg.DNSCacheEnabled {
		t.Errorf("Expected dns_cache_enabled true, got %v", cfg.DNSCacheEnabled)
	}
	if cfg.DNSCacheTTLSec != 300 {
		t.Errorf("Expected dns_cache_ttl_sec 300, got %d", cfg.DNSCacheTTLSec)
	}
	if cfg.ConnectTimeoutSec != 10 {
		t.Errorf("Expected connect_timeout_sec 10, got %d", cfg.ConnectTimeoutSec)
	}
	if cfg.IdleTimeoutSec != 60 {
		t.Errorf("Expected idle_timeout_sec 60, got %d", cfg.IdleTimeoutSec)
	}
	if cfg.ReloadIntervalSec != 5 {
		t.Errorf("Expected reload_interval_sec 5, got %d", cfg.ReloadIntervalSec)
	}
}

func TestConfig_GetEffectiveDNSServers(t *testing.T) {
	// 1. Default fallback to Cloudflare Security DNS
	cfgDefault := DefaultConfig()
	effective := cfgDefault.GetEffectiveDNSServers()
	if len(effective) != 4 {
		t.Fatalf("Expected 4 default DNS servers (2 IPv4 + 2 IPv6), got %d", len(effective))
	}
	if effective[0] != "1.1.1.2" || effective[1] != "1.0.0.2" {
		t.Errorf("Unexpected IPv4 default servers: %v", effective[:2])
	}
	if cfgDefault.IsCustomDNS() {
		t.Errorf("Expected IsCustomDNS() to be false for default config")
	}

	// 2. Custom DNS overrides defaults
	cfgCustom := DefaultConfig()
	cfgCustom.DNSServers = []string{"169.254.169.254", "10.0.0.2"}
	effectiveCustom := cfgCustom.GetEffectiveDNSServers()
	if len(effectiveCustom) != 2 || effectiveCustom[0] != "169.254.169.254" {
		t.Errorf("Unexpected custom DNS servers: %v", effectiveCustom)
	}
	if !cfgCustom.IsCustomDNS() {
		t.Errorf("Expected IsCustomDNS() to be true for custom config")
	}
}

func TestConfig_BuildDivertFilter_EdgeCases(t *testing.T) {
	// 1. Custom DivertFilter specified in config must take precedence
	cfgCustomFilter := DefaultConfig()
	cfgCustomFilter.DivertFilter = "outbound and tcp.DstPort == 80"
	fwdStr, _ := cfgCustomFilter.BuildDivertFilter(18080)
	if fwdStr != "outbound and tcp.DstPort == 80" {
		t.Errorf("Expected custom DivertFilter to be used directly, got: %q", fwdStr)
	}

	// 2. Default filter with empty dns_servers includes DNS (udp.DstPort == 53)
	cfgDefault := DefaultConfig()
	_, filterDefault := cfgDefault.BuildDivertFilter(18080)
	if !strings.Contains(filterDefault, "udp.DstPort == 53") {
		t.Errorf("Expected default filter to include DNS capture, got: %s", filterDefault)
	}
	if !strings.Contains(filterDefault, "40000") || !strings.Contains(filterDefault, "48999") {
		t.Errorf("Expected PortGuard exclusion range (40000-48999) in filter, got: %s", filterDefault)
	}

	// 3. Custom DNS servers specified: DNS capture (udp.DstPort == 53) must be excluded
	cfgWithDNS := DefaultConfig()
	cfgWithDNS.DNSServers = []string{"10.0.0.1"}
	_, filterWithDNS := cfgWithDNS.BuildDivertFilter(18080)
	if strings.Contains(filterWithDNS, "udp.DstPort == 53") {
		t.Errorf("Expected custom DNS config to NOT capture DNS in WinDivert filter, got: %s", filterWithDNS)
	}

	// 4. FilterUDP false (default): General UDP capture must NOT be present
	if strings.Contains(filterDefault, "udp.DstPort != 53 and udp.DstPort != 443") {
		t.Errorf("Expected default filter to NOT capture general UDP, got: %s", filterDefault)
	}

	// 5. FilterUDP true: General UDP capture must be included
	cfgWithUDP := DefaultConfig()
	cfgWithUDP.FilterUDP = true
	_, filterWithUDP := cfgWithUDP.BuildDivertFilter(18080)
	if !strings.Contains(filterWithUDP, "udp.DstPort != 53 and udp.DstPort != 443") {
		t.Errorf("Expected FilterUDP true to include general UDP capture, got: %s", filterWithUDP)
	}
}




