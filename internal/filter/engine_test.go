package filter

import (
	"testing"
)

func TestFilterEngine_Whitelist(t *testing.T) {
	allowedDomains := []string{
		"*.github.com",
		"golang.org",
		"*.windowsupdate.com",
	}
	allowedIPs := []string{
		"192.168.0.0/16",
		"10.0.0.1",
	}

	engine := NewEngine("whitelist", allowedDomains, allowedIPs)

	tests := []struct {
		input       string
		shouldBlock bool
	}{
		// Allowed domains
		{"github.com", false},
		{"api.github.com", false},
		{"raw.github.com:443", false},
		{"golang.org", false},
		{"pkg.golang.org", false},
		{"download.windowsupdate.com", false},

		// Blocked (not in whitelist)
		{"malicious.com", true},
		{"gitlab.com", true},
		{"evil.github.com.evil.com", true},

		// Allowed IPs
		{"192.168.1.100", false},
		{"10.0.0.1", false},

		// Blocked IPs
		{"8.8.8.8", true},
		{"10.0.0.2", true},
	}

	for _, tt := range tests {
		blocked := engine.ShouldBlock(tt.input)
		if blocked != tt.shouldBlock {
			t.Errorf("ShouldBlock(%q) = %v; want %v", tt.input, blocked, tt.shouldBlock)
		}
	}
}

func TestFilterEngine_Blacklist(t *testing.T) {
	blockedDomains := []string{
		"malicious.com",
		"*.ads.net",
	}
	blockedIPs := []string{
		"192.0.2.1",
	}

	engine := NewEngine("blacklist", blockedDomains, blockedIPs)

	tests := []struct {
		input       string
		shouldBlock bool
	}{
		{"malicious.com", true},
		{"sub.malicious.com", true},
		{"banner.ads.net", true},
		{"github.com", false},
		{"192.0.2.1", true},
		{"192.0.2.2", false},
	}

	for _, tt := range tests {
		blocked := engine.ShouldBlock(tt.input)
		if blocked != tt.shouldBlock {
			t.Errorf("Blacklist ShouldBlock(%q) = %v; want %v", tt.input, blocked, tt.shouldBlock)
		}
	}
}

func TestFilterEngine_AllPass(t *testing.T) {
	for _, mode := range []string{"none", "off", "all", "disabled", "passthrough"} {
		engine := NewEngine(mode, []string{"blocked.com"}, []string{"1.2.3.4"})

		if engine.ShouldBlock("blocked.com") {
			t.Errorf("Mode %q: Expected blocked.com to NOT be blocked (all-pass mode)", mode)
		}
		if engine.ShouldBlock("1.2.3.4") {
			t.Errorf("Mode %q: Expected 1.2.3.4 to NOT be blocked (all-pass mode)", mode)
		}
		if engine.ShouldBlock("random-domain.org") {
			t.Errorf("Mode %q: Expected random-domain.org to NOT be blocked (all-pass mode)", mode)
		}
	}
}

func TestFilterEngine_IPv6(t *testing.T) {
	allowedDomains := []string{"*.example.com"}
	allowedIPs := []string{
		"::1",
		"fe80::/10",
		"2001:db8::/32",
	}

	engine := NewEngine("whitelist", allowedDomains, allowedIPs)

	tests := []struct {
		input       string
		shouldBlock bool
	}{
		// Allowed IPv6
		{"::1", false},
		{"[::1]:8080", false},
		{"fe80::1", false},
		{"fe80::dead:beef", false},
		{"2001:db8::1", false},
		{"2001:db8:ffff::1", false},
		{"[2001:db8::1]:443", false},

		// Blocked IPv6 (not in allowed CIDR / IPs)
		{"2001:4860:4860::8888", true},
		{"[2001:4860:4860::8888]:53", true},
		{"::2", true},
		{"2001:db9::1", true},
	}

	for _, tt := range tests {
		blocked := engine.ShouldBlock(tt.input)
		if blocked != tt.shouldBlock {
			t.Errorf("IPv6 ShouldBlock(%q) = %v; want %v", tt.input, blocked, tt.shouldBlock)
		}
	}

	// Test Blacklist mode with IPv6
	blockedIPs := []string{
		"2001:db8:dead::/48",
		"2001:db8:bad::1",
	}
	blEngine := NewEngine("blacklist", nil, blockedIPs)

	blTests := []struct {
		input       string
		shouldBlock bool
	}{
		{"2001:db8:dead::1", true},
		{"[2001:db8:dead::beef]:80", true},
		{"2001:db8:bad::1", true},
		{"2001:db8:b00d::1", false},
		{"::1", false},
	}

	for _, tt := range blTests {
		blocked := blEngine.ShouldBlock(tt.input)
		if blocked != tt.shouldBlock {
			t.Errorf("IPv6 Blacklist ShouldBlock(%q) = %v; want %v", tt.input, blocked, tt.shouldBlock)
		}
	}
}
