package pac

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
)

func TestPACResolver_Evaluation(t *testing.T) {
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
		t.Errorf("Expected DIRECT for internal host, got: %v", d1)
	}

	// Test 2: External host -> should resolve to PROXY
	d2, err := resolver.Resolve("external-site.com", 443)
	if err != nil {
		t.Fatalf("Resolve failed for external host: %v", err)
	}
	if d2.IsDirect {
		t.Errorf("Expected PROXY for external host, got DIRECT")
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

func TestResolver_Cleanup_Lifecycle(t *testing.T) {
	// BUG-13 および BUG-6 に関連する、リソースリークとシャットダウンクリーンアップの検証
	resolver, err := NewResolver("", "http://cleanup-test:8080")
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}

	// 複数回 Close() を呼んでもパニックにならず、安全に処理されるかを検証（冪等性）
	resolver.Close()
	resolver.Close()

	// 既に Close された状態での Resolve 呼び出しが安全にフェールするか（あるいはそのままスタティック応答を返すか）
	// 現行の仕様では、スタティックプロキシの場合は Close 状態でも応答自体は可能なので、パニックにならないことだけを確認
	_, _ = resolver.Resolve("example.com", 80)
}

func TestPAC_AutoDetection(t *testing.T) {
	testCases := []struct {
		name           string
		pacURL         string
		staticProxy    string
		expectedPAC    bool
		expectedPACURL string
	}{
		{
			name:           "Explicit PAC URL",
			pacURL:         "http://pac.corp.local/proxy.pac",
			staticProxy:    "",
			expectedPAC:    true,
			expectedPACURL: "http://pac.corp.local/proxy.pac",
		},
		{
			name:           "PAC URL in static_proxy ending with .pac",
			pacURL:         "",
			staticProxy:    "http://corp.local/autoproxy.pac",
			expectedPAC:    true,
			expectedPACURL: "http://corp.local/autoproxy.pac",
		},
		{
			name:           "WPAD DAT file in static_proxy",
			pacURL:         "",
			staticProxy:    "http://wpad.corp.local/wpad.dat",
			expectedPAC:    true,
			expectedPACURL: "http://wpad.corp.local/wpad.dat",
		},
		{
			name:           "pac+ scheme prefix in static_proxy",
			pacURL:         "",
			staticProxy:    "pac+http://proxy.corp.local:8080/script",
			expectedPAC:    true,
			expectedPACURL: "http://proxy.corp.local:8080/script",
		},
		{
			name:           "Standard static HTTP proxy (not PAC)",
			pacURL:         "",
			staticProxy:    "http://proxy.corp.local:8080",
			expectedPAC:    false,
			expectedPACURL: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewResolver(tc.pacURL, tc.staticProxy)
			if err != nil {
				// WinHTTP session init may fail in headless/restricted environment
				t.Skipf("PAC session init skipped: %v", err)
				return
			}
			defer r.Close()

			if r.isPACMode != tc.expectedPAC {
				t.Errorf("Expected isPACMode=%v, got %v", tc.expectedPAC, r.isPACMode)
			}
			if r.pacURL != tc.expectedPACURL {
				t.Errorf("Expected pacURL=%q, got %q", tc.expectedPACURL, r.pacURL)
			}
		})
	}
}

func TestPAC_DynamicUpdateConfig(t *testing.T) {
	// Initialize with static proxy
	r, err := NewResolver("", "http://initial-proxy:8080")
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}
	defer r.Close()

	// Initial evaluation
	d1, err := r.Resolve("site1.com", 80)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if d1.ProxyURL != "http://initial-proxy:8080" {
		t.Errorf("Expected http://initial-proxy:8080, got %s", d1.ProxyURL)
	}

	// Update configuration dynamically to a different static proxy
	r.UpdateConfig("", "http://updated-proxy:3128")
	d2, err := r.Resolve("site1.com", 80)
	if err != nil {
		t.Fatalf("Resolve after update failed: %v", err)
	}
	if d2.ProxyURL != "http://updated-proxy:3128" {
		t.Errorf("Expected http://updated-proxy:3128 after update, got %s", d2.ProxyURL)
	}

	// Test ResolveRouting interface
	isDirect, proxyURL, err := r.ResolveRouting("site2.com", 443)
	if err != nil {
		t.Fatalf("ResolveRouting failed: %v", err)
	}
	if isDirect {
		t.Errorf("Expected isDirect=false for updated proxy")
	}
	if proxyURL != "http://updated-proxy:3128" {
		t.Errorf("Expected proxyURL=http://updated-proxy:3128, got %s", proxyURL)
	}
}

func TestPAC_Linux_PACSupport(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("This test verifies Linux-specific PAC execution and fallback")
	}

	// 1. Unreachable PAC path -> safe fallback to DIRECT immediately
	rUnreachable, err := NewResolver("/tmp/nonexistent_pac_file_12345.pac", "")
	if err != nil {
		t.Fatalf("NewResolver on Linux should not return error: %v", err)
	}
	defer rUnreachable.Close()

	d, err := rUnreachable.Resolve("example.com", 443)
	if err != nil {
		t.Fatalf("Resolve on Linux fallback should not return error: %v", err)
	}
	if !d.IsDirect {
		t.Errorf("Expected IsDirect=true on unreachable PAC fallback, got false")
	}

	// 2. Valid PAC server on Linux -> evaluated with JSEngine
	pacScript := `
function FindProxyForURL(url, host) {
    if (host == "internal-service.local") return "DIRECT";
    return "PROXY linux-pac-proxy.corp:8080";
}
`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, pacScript)
	}))
	defer ts.Close()

	rValid, err := NewResolver(ts.URL+"/proxy.pac", "")
	if err != nil {
		t.Fatalf("Failed to init PAC resolver on Linux: %v", err)
	}
	defer rValid.Close()

	dInternal, err := rValid.Resolve("internal-service.local", 80)
	if err != nil || !dInternal.IsDirect {
		t.Errorf("Expected DIRECT for internal-service.local, got %v (err: %v)", dInternal, err)
	}

	dExternal, err := rValid.Resolve("external-site.org", 443)
	if err != nil || dExternal.IsDirect || dExternal.ProxyURL != "http://linux-pac-proxy.corp:8080" {
		t.Errorf("Expected PROXY for external-site.org, got %v (err: %v)", dExternal, err)
	}
}

func TestPAC_AutoDetectExtension(t *testing.T) {
	// If static proxy URL ends with .pac or .dat or starts with pac+, should be auto-treated as PAC URL
	cases := []string{
		"http://wpad.corp.local/wpad.dat",
		"http://corp.local/proxy.pac",
		"pac+http://proxy.corp.local/custom",
	}

	for _, c := range cases {
		r, err := NewResolver("", c)
		if err != nil {
			t.Logf("NewResolver with %q failed (expected if PAC session fails on some envs): %v", c, err)
			continue
		}
		if !r.isPACMode {
			t.Errorf("Expected isPACMode=true for %q", c)
		}
		if r.staticProxy != "" {
			t.Errorf("Expected staticProxy to be cleared for %q, got %q", c, r.staticProxy)
		}
		r.Close()
	}
}

func TestPAC_UpdateConfig_DynamicModes(t *testing.T) {
	// Start with static proxy
	r, err := NewResolver("", "http://first-proxy:8080")
	if err != nil {
		t.Fatalf("NewResolver failed: %v", err)
	}
	defer r.Close()

	d1, err := r.Resolve("site1.com", 443)
	if err != nil || d1.IsDirect || d1.ProxyURL != "http://first-proxy:8080" {
		t.Errorf("Expected http://first-proxy:8080, got %v (err: %v)", d1, err)
	}

	// Update to another static proxy
	r.UpdateConfig("", "http://second-proxy:9090")
	d2, err := r.Resolve("site1.com", 443)
	if err != nil || d2.IsDirect || d2.ProxyURL != "http://second-proxy:9090" {
		t.Errorf("Expected http://second-proxy:9090, got %v (err: %v)", d2, err)
	}

	// Update to empty -> Direct mode (or auto-detect if OS has it)
	r.UpdateConfig("", "")
	d3, err := r.Resolve("site1.com", 443)
	if err != nil {
		t.Errorf("Resolve failed after reset: %v", err)
	}
	t.Logf("Result after clearing config: IsDirect=%v, ProxyURL=%q", d3.IsDirect, d3.ProxyURL)
}

func TestParseFirstProxy_Schemes(t *testing.T) {
	tests := []struct {
		input       string
		expected    string
		expectURL   string
	}{
		{"PROXY proxy.corp:8080", "http://proxy.corp:8080", "http://proxy.corp:8080"},
		{"HTTPS secure-proxy.corp:8443", "https://secure-proxy.corp:8443", "https://secure-proxy.corp:8443"},
		{"SOCKS5 socks.corp:1080", "socks5://socks.corp:1080", "socks5://socks.corp:1080"},
		{"SOCKS socks.corp:1080", "socks5://socks.corp:1080", "socks5://socks.corp:1080"},
		{"DIRECT", "DIRECT", "http://DIRECT"},
		{"HTTPS p1:8443; PROXY p2:8080; DIRECT", "https://p1:8443", "https://p1:8443"},
		{"PROXY p2:8080; DIRECT", "http://p2:8080", "http://p2:8080"},
		{"p3:8080", "p3:8080", "http://p3:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseFirstProxy(tt.input)
			if got != tt.expected {
				t.Errorf("parseFirstProxy(%q) = %q, want %q", tt.input, got, tt.expected)
			}
			norm := normalizeProxyURL(got)
			if norm != tt.expectURL {
				t.Errorf("normalizeProxyURL(%q) = %q, want %q", got, norm, tt.expectURL)
			}
		})
	}
}
