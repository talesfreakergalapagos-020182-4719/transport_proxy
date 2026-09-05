package pac

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestJSEngine_StandardPACFunctions(t *testing.T) {
	pacScript := `
function FindProxyForURL(url, host) {
    if (isPlainHostName(host)) {
        return "DIRECT";
    }
    if (dnsDomainIs(host, ".internal.corp")) {
        return "DIRECT";
    }
    if (shExpMatch(host, "*.dmz.example.com")) {
        return "PROXY dmz-proxy:8080";
    }
    if (isInNet(host, "10.0.0.0", "255.0.0.0")) {
        return "DIRECT";
    }
    if (dnsDomainLevels(host) == 1) {
        return "PROXY single-dot-proxy:3128";
    }
    return "PROXY default-proxy.corp:8080; DIRECT";
}
`

	engine, err := NewJSEngine(pacScript)
	if err != nil {
		t.Fatalf("Failed to initialize JSEngine: %v", err)
	}
	defer engine.Close()

	tests := []struct {
		url            string
		host           string
		expectedDirect bool
		expectedProxy  string
	}{
		{
			url:            "http://intranet/index.html",
			host:           "intranet",
			expectedDirect: true,
		},
		{
			url:            "https://portal.internal.corp/api",
			host:           "portal.internal.corp",
			expectedDirect: true,
		},
		{
			url:            "https://app.dmz.example.com/login",
			host:           "app.dmz.example.com",
			expectedDirect: false,
			expectedProxy:  "http://dmz-proxy:8080",
		},
		{
			url:            "http://10.20.30.40/data",
			host:           "10.20.30.40",
			expectedDirect: true,
		},
		{
			url:            "http://example.com/home",
			host:           "example.com",
			expectedDirect: false,
			expectedProxy:  "http://single-dot-proxy:3128",
		},
		{
			url:            "https://sub.sub2.example.org/path",
			host:           "sub.sub2.example.org",
			expectedDirect: false,
			expectedProxy:  "http://default-proxy.corp:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			rawRes, err := engine.FindProxyForURL(tt.url, tt.host)
			if err != nil {
				t.Fatalf("FindProxyForURL failed for %s: %v", tt.host, err)
			}
			decision := ParsePACResult(rawRes)

			if decision.IsDirect != tt.expectedDirect {
				t.Errorf("For %s: expected IsDirect=%v, got %v (raw: %q)", tt.host, tt.expectedDirect, decision.IsDirect, rawRes)
			}
			if !tt.expectedDirect && decision.ProxyURL != tt.expectedProxy {
				t.Errorf("For %s: expected ProxyURL=%q, got %q", tt.host, tt.expectedProxy, decision.ProxyURL)
			}
		})
	}
}

func TestJSEngine_TimeoutProtection(t *testing.T) {
	// Script containing an infinite loop to test timeout interrupt
	infiniteLoopPAC := `
function FindProxyForURL(url, host) {
    while (true) {
        // infinite loop
    }
    return "DIRECT";
}
`
	engine, err := NewJSEngine(infiniteLoopPAC)
	if err != nil {
		t.Fatalf("Failed to initialize JSEngine with infinite loop: %v", err)
	}
	defer engine.Close()

	// Set short timeout for unit test
	engine.timeout = 50 * time.Millisecond

	start := time.Now()
	_, err = engine.FindProxyForURL("http://example.com", "example.com")
	duration := time.Since(start)

	if err == nil {
		t.Fatalf("Expected timeout error for infinite loop, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") && !strings.Contains(err.Error(), "timeout") {
		t.Errorf("Expected error to mention timeout, got: %v", err)
	}
	if duration > 1*time.Second {
		t.Errorf("Evaluation took too long to interrupt: %v", duration)
	}
}

func TestJSEngine_Concurrency(t *testing.T) {
	pacScript := `
function FindProxyForURL(url, host) {
    if (host == "direct.local") return "DIRECT";
    return "PROXY proxy.corp:8080";
}
`
	engine, err := NewJSEngine(pacScript)
	if err != nil {
		t.Fatalf("Failed to initialize JSEngine: %v", err)
	}
	defer engine.Close()

	const concurrency = 20
	const iterations = 50
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				var host string
				if j%2 == 0 {
					host = "direct.local"
				} else {
					host = "external.com"
				}
				res, err := engine.FindProxyForURL("http://"+host, host)
				if err != nil {
					t.Errorf("Worker %d failed: %v", workerID, err)
					return
				}
				d := ParsePACResult(res)
				if host == "direct.local" && !d.IsDirect {
					t.Errorf("Expected direct for direct.local")
				}
				if host == "external.com" && (d.IsDirect || d.ProxyURL != "http://proxy.corp:8080") {
					t.Errorf("Expected proxy for external.com, got %v", d)
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestParsePACResult(t *testing.T) {
	tests := []struct {
		input          string
		expectedDirect bool
		expectedProxy  string
	}{
		{"DIRECT", true, ""},
		{"direct", true, ""},
		{"", true, ""},
		{"PROXY proxy.corp:8080", false, "http://proxy.corp:8080"},
		{"HTTPS secure-proxy.corp:8443", false, "https://secure-proxy.corp:8443"},
		{"SOCKS5 127.0.0.1:1080", false, "socks5://127.0.0.1:1080"},
		{"PROXY p1:8080; PROXY p2:8080; DIRECT", false, "http://p1:8080"},
		{"INVALID_SCHEME; DIRECT", true, ""},
	}

	for _, tt := range tests {
		d := ParsePACResult(tt.input)
		if d.IsDirect != tt.expectedDirect {
			t.Errorf("ParsePACResult(%q): expected IsDirect=%v, got %v", tt.input, tt.expectedDirect, d.IsDirect)
		}
		if !tt.expectedDirect && d.ProxyURL != tt.expectedProxy {
			t.Errorf("ParsePACResult(%q): expected ProxyURL=%q, got %q", tt.input, tt.expectedProxy, d.ProxyURL)
		}
	}
}

func TestJSEngine_ShExpMatch_URLPaths(t *testing.T) {
	pacScript := `
function FindProxyForURL(url, host) {
    if (shExpMatch(url, "http://*.example.com/api/*")) {
        return "PROXY api-proxy:8080";
    }
    if (shExpMatch(url, "*://secure.example.com/*")) {
        return "HTTPS secure-proxy:8443";
    }
    return "DIRECT";
}
`
	engine, err := NewJSEngine(pacScript)
	if err != nil {
		t.Fatalf("Failed to initialize JSEngine: %v", err)
	}
	defer engine.Close()

	tests := []struct {
		url      string
		host     string
		expected string
	}{
		{"http://v1.example.com/api/v2/users", "v1.example.com", "http://api-proxy:8080"},
		{"http://v1.example.com/other", "v1.example.com", ""}, // DIRECT
		{"https://secure.example.com/login", "secure.example.com", "https://secure-proxy:8443"},
	}

	for _, tt := range tests {
		res, err := engine.FindProxyForURL(tt.url, tt.host)
		if err != nil {
			t.Fatalf("FindProxyForURL failed for %s: %v", tt.url, err)
		}
		d := ParsePACResult(res)
		if tt.expected == "" && !d.IsDirect {
			t.Errorf("Expected DIRECT for %s, got %s", tt.url, d.ProxyURL)
		} else if tt.expected != "" && d.ProxyURL != tt.expected {
			t.Errorf("Expected %s for %s, got %s", tt.expected, tt.url, d.ProxyURL)
		}
	}
}

func TestJSEngine_TimeoutProtection_PoolSafety(t *testing.T) {
	pacScript := `
function FindProxyForURL(url, host) {
    if (url.indexOf("hang=true") !== -1) {
        while (true) {}
    }
    return "PROXY healthy-proxy:8080";
}
`
	engine, err := NewJSEngine(pacScript)
	if err != nil {
		t.Fatalf("Failed to initialize JSEngine: %v", err)
	}
	defer engine.Close()

	engine.timeout = 50 * time.Millisecond

	// 1. Trigger timeout
	_, err = engine.FindProxyForURL("http://example.com/test?hang=true", "example.com")
	if err == nil {
		t.Fatalf("Expected timeout error")
	}

	// 2. Subsequent call must succeed (pool was not poisoned with interrupted VM)
	res, err := engine.FindProxyForURL("http://example.com/test?hang=false", "example.com")
	if err != nil {
		t.Fatalf("Subsequent call failed due to poisoned pool: %v", err)
	}
	d := ParsePACResult(res)
	if d.ProxyURL != "http://healthy-proxy:8080" {
		t.Errorf("Expected http://healthy-proxy:8080, got %s", d.ProxyURL)
	}
}

func TestMatchShExp_Exhaustive(t *testing.T) {
	testCases := []struct {
		str      string
		pattern  string
		expected bool
	}{
		{"http://sub.domain.com/path/file.html", "http://*.domain.com/*/file.html", true},
		{"http://sub.domain.com/path/file.html", "http://*.domain.com/other/*", false},
		{"ftp://files.corp.internal/a/b/c", "*://*.corp.internal/*", true},
		{"https://test.corp:8443/api?id=123", "https://*.corp:8443/api?id=*", true},
		{"https://test.corp:8443/api?id=123", "https://*.corp:8443/api?key=*", false},
		{"foo.bar", "foo.?ar", true},
		{"foobar", "foo?ar", true},
		{"foobar", "foo?az", false},
		{"foor", "foo?ar", false},
		{"anything", "*", true},
		{"exact-match", "exact-match", true},
		{"prefix-match-extra", "prefix-match", false},
		{"", "*", true},
		{"", "", true},
		{"test", "", false},
		{"", "test", false},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s_VS_%s", tc.str, tc.pattern), func(t *testing.T) {
			got := MatchShExp(tc.str, tc.pattern)
			if got != tc.expected {
				t.Errorf("MatchShExp(%q, %q) = %v; want %v", tc.str, tc.pattern, got, tc.expected)
			}
		})
	}
}

func TestJSEngine_MultipleTimeouts_NoLeakOrHang(t *testing.T) {
	// Engine with a script that times out if url contains "loop"
	pacScript := `
function FindProxyForURL(url, host) {
    if (url.indexOf("loop") !== -1) {
        var x = 0;
        while (true) { x++; }
    }
    return "PROXY normal-proxy:8080";
}
`
	engine, err := NewJSEngine(pacScript)
	if err != nil {
		t.Fatalf("Failed to initialize JSEngine: %v", err)
	}
	defer engine.Close()

	engine.timeout = 30 * time.Millisecond

	// 1. Run 5 consecutive timeouts to ensure interrupted VMs are safely discarded
	for i := 0; i < 5; i++ {
		_, err := engine.FindProxyForURL(fmt.Sprintf("http://loop-%d.test", i), "loop.test")
		if err == nil {
			t.Fatalf("Expected timeout error at iteration %d", i)
		}
	}

	// 2. Run 10 consecutive normal queries to ensure freshly created VMs work seamlessly
	for i := 0; i < 10; i++ {
		res, err := engine.FindProxyForURL("http://normal.test", "normal.test")
		if err != nil {
			t.Fatalf("Normal query failed at iteration %d: %v", i, err)
		}
		d := ParsePACResult(res)
		if d.ProxyURL != "http://normal-proxy:8080" {
			t.Errorf("Expected normal-proxy:8080, got %s", d.ProxyURL)
		}
	}
}
