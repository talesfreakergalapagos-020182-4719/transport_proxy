package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Outbound port range reserved for tproxy dialer to prevent self-interception loop.
const (
	OutboundPortMin uint16 = 40000
	OutboundPortMax uint16 = 48999
)

// Config represents the application configuration.
type Config struct {
	ListenAddr        string   `json:"listen_addr"`         // Local transparent proxy listen address, e.g., "127.0.0.1:18080"
	UpstreamProxy     string   `json:"upstream_proxy"`      // Upstream HTTP proxy URL, e.g., "http://proxy.corp.local:8080" (empty for direct or if PAC is used)
	PacURL            string   `json:"pac_url"`             // URL to Proxy Auto-Configuration (.pac/.dat) file, e.g., "http://wpad.corp.local/proxy.pac"
	BypassSSPI        bool     `json:"bypass_sspi"`         // If true, disable SSPI authentication negotiation
	FilterMode        string   `json:"filter_mode"`         // "whitelist" (default, allow only specified) or "blacklist" (block specified)
	AllowedDomains    []string `json:"allowed_domains"`     // List of allowed domains/wildcards in whitelist mode
	AllowedIPs        []string `json:"allowed_ips"`         // List of allowed IPs or CIDRs in whitelist mode
	BlockedDomains    []string `json:"blocked_domains"`     // List of blocked domains/wildcards in blacklist mode
	BlockedIPs        []string `json:"blocked_ips"`         // List of blocked IPs or CIDRs in blacklist mode
	DivertFilter      string   `json:"divert_filter"`       // WinDivert filter string (empty for default all-port capture)
	DryRun            bool     `json:"dry_run"`             // If true, run in passive monitoring/audit mode without intercepting traffic
	LogFile           string   `json:"log_file"`            // Optional path to write log output (e.g. "tproxy.log")
	ConnectTimeoutSec int      `json:"connect_timeout_sec"` // TCP connection timeout in seconds (default: 10)
	IdleTimeoutSec    int      `json:"idle_timeout_sec"`    // TCP idle timeout in seconds (default: 120)
	ReloadIntervalSec int      `json:"reload_interval_sec"` // Interval in seconds to check for config file changes (default: 5)
	DohEnabled        bool     `json:"doh_enabled"`         // If true, automatically upgrade DNS queries to DoH when target DNS supports IP-cert DoH (default: true)
	DohTimeoutSec     int      `json:"doh_timeout_sec"`     // Timeout in seconds for DoH queries (default: 3)
	FallbackToUDP     bool     `json:"fallback_to_udp"`     // If true, fallback to standard UDP 53 DNS on DoH failure/unsupported (default: true)
	DNSCacheEnabled   bool     `json:"dns_cache_enabled"`   // If true, enable in-memory caching of DNS answers (default: true)
	DNSCacheTTLSec    int      `json:"dns_cache_ttl_sec"`   // Max TTL in seconds for DNS answer cache (default: 300)
	ForwardLayerEnabled bool     `json:"forward_layer_enabled"` // If true, concurrently capture forwarded/routed traffic via WINDIVERT_LAYER_NETWORK_FORWARD (default: true)
}

// BuildDivertFilter generates a complete WinDivert filter string capturing ALL TCP outbound traffic,
// excluding loopback, local proxy port, and proxy outbound port range (40000-48999) to prevent self-interception loops.
// When DohEnabled is true, it also captures outbound UDP port 53 traffic.
func (c *Config) BuildDivertFilter(localProxyPort uint16) (forwardCond string, fullFilter string) {
	dohFilter := ""
	if c.DohEnabled {
		dohFilter = " or (outbound and udp and udp.DstPort == 53 and !loopback)"
	}

	if c.DivertFilter != "" {
		return c.DivertFilter, fmt.Sprintf("((%s) or (outbound and tcp and tcp.SrcPort == %d) or (outbound and udp and udp.DstPort == 443 and !loopback)%s)",
			c.DivertFilter, localProxyPort, dohFilter)
	}

	// Capture all outbound TCP traffic on all ports (1-65535) except:
	// 1. Loopback traffic (!loopback)
	// 2. Traffic destined to local proxy listener (tcp.DstPort != localProxyPort)
	// 3. Traffic initiated by local proxy itself (tcp.SrcPort not in OutboundPortMin-OutboundPortMax)
	forwardCond = fmt.Sprintf("outbound and tcp and !loopback and tcp.DstPort != %d and (tcp.SrcPort < %d or tcp.SrcPort > %d)",
		localProxyPort, OutboundPortMin, OutboundPortMax)

	fullFilter = fmt.Sprintf("((%s) or (outbound and tcp and tcp.SrcPort == %d) or (outbound and udp and udp.DstPort == 443 and !loopback)%s)",
		forwardCond, localProxyPort, dohFilter)
	return forwardCond, fullFilter
}

// BuildForwardDivertFilter generates a WinDivert filter string for WINDIVERT_LAYER_NETWORK_FORWARD (Layer 1).
// Layer 1 intercepts packets routed/forwarded between interfaces (e.g. from WSL/Hyper-V VM to physical adapter).
// It does not use 'outbound' or '!loopback' since those apply to Layer 0.
func (c *Config) BuildForwardDivertFilter(localProxyPort uint16) string {
	dohFilter := ""
	if c.DohEnabled {
		dohFilter = " or (udp and udp.DstPort == 53)"
	}
	return fmt.Sprintf("((tcp and tcp.DstPort != %d and (tcp.SrcPort < %d or tcp.SrcPort > %d)) or (udp and udp.DstPort == 443)%s)",
		localProxyPort, OutboundPortMin, OutboundPortMax, dohFilter)
}

// DefaultConfig returns a Config with safe default settings.
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:        "0.0.0.0:18080",
		UpstreamProxy:     "",
		PacURL:            "",
		BypassSSPI:        false,
		FilterMode:        "whitelist",
		AllowedDomains:    []string{},
		AllowedIPs:        []string{},
		BlockedDomains:    []string{},
		BlockedIPs:        []string{},
		DivertFilter:      "",
		DryRun:            false,
		ConnectTimeoutSec: 10,
		IdleTimeoutSec:    120,
		ReloadIntervalSec: 5,
		DohEnabled:        true,
		DohTimeoutSec:     3,
		FallbackToUDP:     true,
		DNSCacheEnabled:     true,
		DNSCacheTTLSec:      300,
		ForwardLayerEnabled: true,
	}
}

// Manager manages configuration loading and dynamic hot-reloading.
type Manager struct {
	filePath   string
	currentCfg atomic.Pointer[Config]
	lastMod    time.Time
	mu         sync.Mutex
	callbacks  []func(newCfg *Config)
	stopChan   chan struct{}
	stopOnce   sync.Once
}

// NewManager loads the initial configuration from the given path and creates a Manager.
func NewManager(path string) (*Manager, error) {
	m := &Manager{
		filePath: path,
		stopChan: make(chan struct{}),
	}

	cfg, modTime, err := m.loadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load initial config from %s: %w", path, err)
	}

	m.currentCfg.Store(cfg)
	m.lastMod = modTime
	return m, nil
}

// Get returns the latest loaded Config.
func (m *Manager) Get() *Config {
	cfg := m.currentCfg.Load()
	if cfg == nil {
		return DefaultConfig()
	}
	return cfg
}

// OnReload registers a callback function to be called when the configuration is reloaded.
func (m *Manager) OnReload(cb func(newCfg *Config)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks = append(m.callbacks, cb)
}

// StartAutoReload starts a background goroutine to watch for configuration file modifications.
func (m *Manager) StartAutoReload() {
	go func() {
		for {
			var stopped bool
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("[Config] Recovered from panic in auto-reload goroutine: %v", r)
						time.Sleep(1 * time.Second)
					}
				}()

				ticker := time.NewTicker(time.Duration(m.Get().ReloadIntervalSec) * time.Second)
				defer ticker.Stop()

				for {
					select {
					case <-m.stopChan:
						stopped = true
						return
					case <-ticker.C:
						m.checkAndReload()
					}
				}
			}()

			if stopped {
				return
			}
		}
	}()
}

// Stop stops the auto-reload goroutine safely.
func (m *Manager) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopChan)
	})
}

func (m *Manager) checkAndReload() {
	fi, err := os.Stat(m.filePath)
	if err != nil {
		return
	}

	m.mu.Lock()
	if !fi.ModTime().After(m.lastMod) {
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()

	cfg, modTime, err := m.loadFile(m.filePath)
	if err != nil {
		log.Printf("[Config] Failed to reload config from %s: %v", m.filePath, err)
		return
	}

	m.currentCfg.Store(cfg)
	m.mu.Lock()
	m.lastMod = modTime
	callbacks := make([]func(*Config), len(m.callbacks))
	copy(callbacks, m.callbacks)
	m.mu.Unlock()

	log.Printf("[Config] Configuration successfully reloaded from %s", m.filePath)
	for _, cb := range callbacks {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[Config] Panic in reload callback: %v", r)
				}
			}()
			cb(cfg)
		}()
	}
}

func (m *Manager) loadFile(path string) (*Config, time.Time, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, err
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, time.Time{}, fmt.Errorf("JSON parse error: %w", err)
	}

	if cfg.FilterMode == "" {
		cfg.FilterMode = "whitelist"
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "0.0.0.0:18080"
	}
	if cfg.ConnectTimeoutSec <= 0 {
		cfg.ConnectTimeoutSec = 10
	}
	if cfg.IdleTimeoutSec < 0 {
		cfg.IdleTimeoutSec = 120
	}
	if cfg.ReloadIntervalSec <= 0 {
		cfg.ReloadIntervalSec = 5
	}

	return cfg, fi.ModTime(), nil
}
