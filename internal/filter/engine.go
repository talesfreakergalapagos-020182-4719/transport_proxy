package filter

import (
	"net"
	"strings"
	"sync/atomic"
)

// RuleSet holds precompiled lookup structures for fast, lock-free evaluation.
type RuleSet struct {
	mode             string // "whitelist" or "blacklist"
	exactDomains     map[string]struct{}
	suffixRoots      map[string]struct{} // roots for subdomain match, e.g. "github.com"
	wildcardPatterns []string            // patterns with '*'
	ips              map[string]struct{}
	cidrs            []*net.IPNet
}

// Engine evaluates hostnames and IP addresses against filtering rules.
type Engine struct {
	rules atomic.Pointer[RuleSet]
}

// NewEngine creates a new filter engine with initial rules.
// mode can be "whitelist" (default) or "blacklist".
func NewEngine(mode string, domains []string, ips []string) *Engine {
	e := &Engine{}
	e.UpdateRules(mode, domains, ips)
	return e
}

// UpdateRules compiles and atomically swaps the active rule set.
func (e *Engine) UpdateRules(mode string, domains []string, ips []string) {
	if mode == "" {
		mode = "whitelist"
	}

	rs := &RuleSet{
		mode:         strings.ToLower(mode),
		exactDomains: make(map[string]struct{}),
		suffixRoots:  make(map[string]struct{}),
		ips:          make(map[string]struct{}),
	}

	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}

		if strings.HasPrefix(d, "*.") {
			// Wildcard subdomain pattern, e.g. "*.github.com" -> match ".github.com" and "github.com"
			root := d[2:]
			rs.exactDomains[root] = struct{}{}
			rs.suffixRoots[root] = struct{}{}
		} else if strings.Contains(d, "*") {
			// Arbitrary wildcard pattern, e.g. "update.*.microsoft.com"
			rs.wildcardPatterns = append(rs.wildcardPatterns, d)
		} else {
			// Exact domain and its subdomains
			rs.exactDomains[d] = struct{}{}
			rs.suffixRoots[d] = struct{}{}
		}
	}

	for _, ipStr := range ips {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}

		if strings.HasPrefix(ipStr, "[") && strings.HasSuffix(ipStr, "]") {
			ipStr = ipStr[1 : len(ipStr)-1]
		}

		if strings.Contains(ipStr, "/") {
			// CIDR notation, e.g. "192.168.0.0/16"
			_, ipNet, err := net.ParseCIDR(ipStr)
			if err == nil && ipNet != nil {
				rs.cidrs = append(rs.cidrs, ipNet)
			}
		} else {
			// Single IP
			parsedIP := net.ParseIP(ipStr)
			if parsedIP != nil {
				rs.ips[parsedIP.String()] = struct{}{}
			}
		}
	}

	e.rules.Store(rs)
}

// ShouldBlock evaluates whether the given hostOrIP should be blocked based on the active mode.
// In "whitelist" mode (default): Returns true (BLOCK) unless it matches an allowed rule.
// In "blacklist" mode: Returns true (BLOCK) if it matches a blocked rule.
// In "none" / "off" / "disabled" / "all" / "passthrough" mode: Returns false (ALLOW ALL, no filtering).
func (e *Engine) ShouldBlock(hostOrIP string) bool {
	if hostOrIP == "" {
		return true // Block empty destinations
	}

	rs := e.rules.Load()
	if rs == nil {
		return false
	}

	switch rs.mode {
	case "none", "off", "disabled", "all", "passthrough":
		return false // All-pass mode: Never block
	case "blacklist":
		return e.match(rs, hostOrIP)
	case "whitelist":
		fallthrough
	default:
		return !e.match(rs, hostOrIP)
	}
}

// match checks if hostOrIP matches the rule set.
func (e *Engine) match(rs *RuleSet, hostOrIP string) bool {
	// Fast path: avoid net.SplitHostPort error allocation if no port/colon is present
	if strings.IndexByte(hostOrIP, ':') != -1 {
		if host, _, err := net.SplitHostPort(hostOrIP); err == nil {
			hostOrIP = host
		}
	}

	// Strip enclosing brackets for bare IPv6 literals without port (e.g. "[2001:db8::1]")
	if len(hostOrIP) >= 2 && hostOrIP[0] == '[' && hostOrIP[len(hostOrIP)-1] == ']' {
		hostOrIP = hostOrIP[1 : len(hostOrIP)-1]
	}

	parsedIP := net.ParseIP(hostOrIP)
	if parsedIP != nil {
		// Check exact IP
		if _, ok := rs.ips[parsedIP.String()]; ok {
			return true
		}
		// Check CIDRs
		for _, cidr := range rs.cidrs {
			if cidr.Contains(parsedIP) {
				return true
			}
		}
		return false
	}

	// Hostname matching
	domain := strings.ToLower(strings.TrimSuffix(hostOrIP, "."))

	// 1. Exact match
	if _, ok := rs.exactDomains[domain]; ok {
		return true
	}

	// 2. O(1) Hierarchical Suffix match (check each subdomain label in hash set)
	// For "api.v2.github.com", checks "v2.github.com" and "github.com" in suffixRoots map
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			sub := domain[i+1:]
			if _, ok := rs.suffixRoots[sub]; ok {
				return true
			}
		}
	}

	// 3. Wildcard pattern match (only if arbitrary wildcards exist)
	for _, pattern := range rs.wildcardPatterns {
		if matchWildcard(pattern, domain) {
			return true
		}
	}

	return false
}

// matchWildcard implements a fast recursive wildcard matcher without external regex overhead.
func matchWildcard(pattern, s string) bool {
	if pattern == "" {
		return s == ""
	}
	if pattern == "*" {
		return true
	}

	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			for len(pattern) > 1 && pattern[1] == '*' {
				pattern = pattern[1:] // Collapse multiple '*'
			}
			if len(pattern) == 1 {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if matchWildcard(pattern[1:], s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(s) == 0 {
				return false
			}
			s = s[1:]
			pattern = pattern[1:]
		default:
			if len(s) == 0 || pattern[0] != s[0] {
				return false
			}
			s = s[1:]
			pattern = pattern[1:]
		}
	}

	return len(s) == 0
}
