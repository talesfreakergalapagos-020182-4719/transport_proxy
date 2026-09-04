package filter

import (
	"testing"
)

func TestEngine_AllPassMode(t *testing.T) {
	engine := NewEngine("all", []string{"test.com"}, []string{})
	if engine.ShouldBlock("test.com") {
		t.Error("expected test.com to be allowed in all-pass mode")
	}
	if engine.ShouldBlock("bad.com") {
		t.Error("expected bad.com to be allowed in all-pass mode")
	}
}

func TestEngine_UpdateRules(t *testing.T) {
	engine := NewEngine("whitelist", []string{"allowed.com"}, []string{})
	
	if !engine.ShouldBlock("blocked.com") {
		t.Error("expected blocked.com to be blocked initially")
	}

	// Update to blacklist
	engine.UpdateRules("blacklist", []string{"blocked.com"}, []string{})

	if engine.ShouldBlock("allowed.com") {
		t.Error("expected allowed.com to be allowed after updating to blacklist")
	}
	if !engine.ShouldBlock("blocked.com") {
		t.Error("expected blocked.com to be blocked after updating to blacklist")
	}
}

func TestEngine_EdgeCases(t *testing.T) {
	allowedDomains := []string{
		"*.github.com",
		"golang.org",
	}
	allowedIPs := []string{
		"192.168.0.0/16",
		"2001:db8::/32",
		"::1",
	}

	engine := NewEngine("whitelist", allowedDomains, allowedIPs)

	tests := []struct {
		input       string
		shouldBlock bool
		desc        string
	}{
		// Case insensitivity
		{"API.GITHUB.COM", false, "Uppercase allowed domain"},
		{"GoLang.Org:8080", false, "Mixed case with port"},
		{"MALICIOUS.COM", true, "Uppercase blocked domain"},

		// Trailing dot (FQDN representation)
		{"golang.org.", false, "Trailing dot allowed"},
		{"api.github.com.", false, "Trailing dot wildcard allowed"},
		{"badsite.org.", true, "Trailing dot blocked"},

		// Host:Port formats
		{"github.com:443", false, "Allowed domain with port 443"},
		{"192.168.1.50:8000", false, "Allowed IPv4 with port"},
		{"[2001:db8::1]:8443", false, "Allowed IPv6 bracketed with port"},
		{"2001:db8::55", false, "Allowed IPv6 bare"},
		{"[2001:db8::55]", false, "Allowed IPv6 bracketed bare (no port)"},
		{"[::1]", false, "Allowed IPv6 loopback bracketed bare"},

		// Blocked IPs
		{"192.169.1.1", true, "IP outside allowed subnet"},
		{"[2001:db9::1]:443", true, "IPv6 outside allowed prefix"},
		{"[2001:db9::1]", true, "Blocked IPv6 bracketed bare (no port)"},

		// Degenerate / invalid inputs (should be safely blocked, no panic)
		{"", true, "Empty input"},
		{"   ", true, "Whitespace input"},
		{":::", true, "Malformed IPv6"},
		{"...", true, "Malformed domain"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			blocked := engine.ShouldBlock(tt.input)
			if blocked != tt.shouldBlock {
				t.Errorf("ShouldBlock(%q) = %v; want %v (%s)", tt.input, blocked, tt.shouldBlock, tt.desc)
			}
		})
	}
}

func TestEngine_ConcurrentAccess(t *testing.T) {
	engine := NewEngine("whitelist", []string{"*.example.com"}, []string{"10.0.0.0/8"})

	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			if i%2 == 0 {
				engine.UpdateRules("blacklist", []string{"bad.com"}, []string{"192.168.1.1"})
			} else {
				engine.UpdateRules("whitelist", []string{"*.example.com"}, []string{"10.0.0.0/8"})
			}
		}
		close(done)
	}()

	// Concurrent readers
	for i := 0; i < 100; i++ {
		_ = engine.ShouldBlock("api.example.com")
		_ = engine.ShouldBlock("10.1.2.3")
		_ = engine.ShouldBlock("bad.com")
	}

	<-done
}

func TestEngine_ArbitraryWildcardPatterns(t *testing.T) {
	allowedDomains := []string{
		"update.*.microsoft.com",
		"*-internal.company.net",
		"api-v*.service.org",
		"exact-match.com",
	}

	engine := NewEngine("whitelist", allowedDomains, []string{})

	tests := []struct {
		input       string
		shouldBlock bool
		desc        string
	}{
		{"update.os.microsoft.com", false, "Middle wildcard match"},
		{"update.prod.v2.microsoft.com", false, "Middle multi-segment wildcard match"},
		{"update.microsoft.com", true, "Middle wildcard missing segment"},
		{"backend-internal.company.net", false, "Prefix wildcard match"},
		{"internal.company.net", true, "Prefix wildcard missing prefix"},
		{"api-v1.service.org", false, "Version wildcard v1"},
		{"api-v2.service.org", false, "Version wildcard v2"},
		{"api.service.org", true, "Missing wildcard prefix"},
		{"exact-match.com", false, "Exact domain match"},
		{"other.com", true, "Unrelated domain blocked"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			blocked := engine.ShouldBlock(tt.input)
			if blocked != tt.shouldBlock {
				t.Errorf("ShouldBlock(%q) = %v; want %v (%s)", tt.input, blocked, tt.shouldBlock, tt.desc)
			}
		})
	}
}

func TestEngine_CIDR_EdgeCases(t *testing.T) {
	allowedIPs := []string{
		"10.0.0.1/32",         // Single host CIDR
		"192.168.1.0/24",       // Standard subnet
		"0.0.0.0/0",           // Any IPv4 (in a test whitelist engine)
	}

	engine := NewEngine("whitelist", []string{}, allowedIPs)

	if engine.ShouldBlock("10.0.0.1") {
		t.Errorf("Expected 10.0.0.1 to be allowed by /32")
	}
	if engine.ShouldBlock("192.168.1.254") {
		t.Errorf("Expected 192.168.1.254 to be allowed by /24")
	}
	if engine.ShouldBlock("8.8.8.8") {
		t.Errorf("Expected 8.8.8.8 to be allowed by 0.0.0.0/0")
	}

	// Blacklist test with IPv6 prefix
	blackEngine := NewEngine("blacklist", []string{}, []string{"2001:db8:ffff::/48"})
	if !blackEngine.ShouldBlock("2001:db8:ffff::1") {
		t.Errorf("Expected 2001:db8:ffff::1 to be blocked by /48 blacklist")
	}
	if blackEngine.ShouldBlock("2001:db8:0001::1") {
		t.Errorf("Expected 2001:db8:0001::1 to be allowed outside /48 blacklist")
	}
}

