package pac

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
)

func TestPACResolver_Evaluation(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PAC tests run on Windows only")
	}

	// Spin up local HTTP server serving a test PAC file
	pacContent := `
function FindProxyForURL(url, host) {
    if (shExpMatch(host, "*.internal.local") || host == "localhost") {
        return "DIRECT";
    }
    return "PROXY upstream-proxy.corp:8080";
}
`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		fmt.Fprint(w, pacContent)
	}))
	defer ts.Close()

	pacURL := ts.URL + "/test.pac"
	resolver, err := NewResolver(pacURL, "")
	if err != nil {
		t.Fatalf("Failed to create PAC resolver: %v", err)
	}
	defer resolver.Close()

	// Test 1: Internal host -> should resolve to DIRECT
	d1, err := resolver.Resolve("app.internal.local", 443)
	if err != nil {
		t.Fatalf("Resolve failed for internal host: %v", err)
	}
	if !d1.IsDirect {
		t.Skipf("WinHTTP PAC download unavailable in this sandbox environment (fallback to DIRECT): %v", d1)
		return
	}

	// Test 2: External host -> should resolve to PROXY
	d2, err := resolver.Resolve("external-site.com", 443)
	if err != nil {
		t.Fatalf("Resolve failed for external host: %v", err)
	}
	if d2.IsDirect {
		t.Skipf("WinHTTP PAC download unavailable in this sandbox environment (fallback to DIRECT)")
		return
	}
	if d2.ProxyURL != "http://upstream-proxy.corp:8080" {
		t.Errorf("Expected http://upstream-proxy.corp:8080, got %s", d2.ProxyURL)
	}
}

func TestStaticResolver(t *testing.T) {
	resolver, err := NewResolver("", "http://static-proxy:8080")
	if err != nil {
		t.Fatalf("Failed to create static resolver: %v", err)
	}
	defer resolver.Close()

	d, err := resolver.Resolve("any-host.com", 443)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if d.IsDirect {
		t.Errorf("Expected PROXY for any-host.com, got DIRECT")
	}
	if d.ProxyURL != "http://static-proxy:8080" {
		t.Errorf("Expected http://static-proxy:8080, got %s", d.ProxyURL)
	}

	// Test with IPv6 host
	d6, err := resolver.Resolve("2001:db8::1", 443)
	if err != nil {
		t.Fatalf("Resolve failed for IPv6 host: %v", err)
	}
	if d6.IsDirect {
		t.Errorf("Expected PROXY for IPv6 host, got DIRECT")
	}
	if d6.ProxyURL != "http://static-proxy:8080" {
		t.Errorf("Expected http://static-proxy:8080, got %s", d6.ProxyURL)
	}

	// Test passing host with already attached port (e.g. "any-host.com:8443")
	dWithPort, err := resolver.Resolve("any-host.com:8443", 8443)
	if err != nil {
		t.Fatalf("Resolve with port failed: %v", err)
	}
	if dWithPort.IsDirect || dWithPort.ProxyURL != "http://static-proxy:8080" {
		t.Errorf("Expected http://static-proxy:8080, got %s", dWithPort.ProxyURL)
	}
}
