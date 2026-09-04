//go:build windows

package pac

import (
	"testing"
)

func TestWinHTTP_GetIEProxyConfig(t *testing.T) {
	cfg, err := GetIEProxyConfigForCurrentUser()
	if err != nil {
		t.Logf("GetIEProxyConfigForCurrentUser returned error (may happen on headless/service account): %v", err)
		return
	}
	if cfg == nil {
		t.Fatalf("Expected non-nil IEProxyConfig")
	}

	t.Logf("Detected IE Proxy Config: AutoDetect=%v, AutoConfigURL=%q, Proxy=%q, ProxyBypass=%q",
		cfg.AutoDetect, cfg.AutoConfigURL, cfg.Proxy, cfg.ProxyBypass)
}

func TestWinHTTP_DetectAutoProxyConfigURL(t *testing.T) {
	url, err := DetectAutoProxyConfigURL()
	// In most test environments WPAD is not deployed via DHCP/DNS, so error or empty string is normal
	t.Logf("DetectAutoProxyConfigURL result: url=%q, err=%v", url, err)
}

func TestWinHTTP_DetectOSProxy(t *testing.T) {
	cfg, err := detectOSProxy()
	if err != nil {
		t.Logf("detectOSProxy returned error: %v", err)
		return
	}
	if cfg == nil {
		t.Fatalf("Expected non-nil osProxyConfig")
	}
	t.Logf("detectOSProxy config: AutoConfigURL=%q, Proxy=%q, AutoDetect=%v",
		cfg.AutoConfigURL, cfg.Proxy, cfg.AutoDetect)
}

func TestWinHTTP_SessionLifecycle(t *testing.T) {
	session, err := NewWinHTTPSession("test-agent/1.0")
	if err != nil {
		t.Fatalf("NewWinHTTPSession failed: %v", err)
	}
	defer session.Close()

	if session.handle == 0 {
		t.Errorf("Expected non-zero handle")
	}

	// Calling Close multiple times should be safe
	session.Close()
	if session.handle != 0 {
		t.Errorf("Expected handle to be 0 after Close")
	}
	session.Close() // idempotent
}
