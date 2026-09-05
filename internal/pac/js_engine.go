package pac

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
)

// JSEngine executes PAC (Proxy Auto-Config) scripts using the pure Go Goja JavaScript engine.
type JSEngine struct {
	script  string
	program *goja.Program
	pool    sync.Pool
	timeout time.Duration
}

// NewJSEngine compiles a PAC script and initializes the execution engine.
func NewJSEngine(pacScript string) (*JSEngine, error) {
	program, err := goja.Compile("pac.js", pacScript, false)
	if err != nil {
		return nil, fmt.Errorf("failed to compile PAC script: %w", err)
	}

	engine := &JSEngine{
		script:  pacScript,
		program: program,
		timeout: 2 * time.Second,
	}

	engine.pool = sync.Pool{
		New: func() any {
			vm := goja.New()
			engine.bindStandardPACFunctions(vm)
			// Run the precompiled script in this VM instance to register FindProxyForURL
			if _, err := vm.RunProgram(engine.program); err != nil {
				return nil
			}
			return vm
		},
	}

	// Verify that FindProxyForURL is defined by testing one VM initialization
	testVM := engine.acquireVM()
	if testVM == nil {
		return nil, fmt.Errorf("failed to initialize PAC VM instance")
	}
	defer engine.releaseVM(testVM)

	fn := testVM.Get("FindProxyForURL")
	if fn == nil || goja.IsNull(fn) || goja.IsUndefined(fn) {
		return nil, fmt.Errorf("PAC script does not define FindProxyForURL function")
	}
	if _, ok := goja.AssertFunction(fn); !ok {
		return nil, fmt.Errorf("FindProxyForURL is not a callable function")
	}

	return engine, nil
}

func (e *JSEngine) acquireVM() *goja.Runtime {
	val := e.pool.Get()
	if val == nil {
		return nil
	}
	return val.(*goja.Runtime)
}

func (e *JSEngine) releaseVM(vm *goja.Runtime) {
	if vm != nil {
		e.pool.Put(vm)
	}
}

// FindProxyForURL evaluates the PAC function for a given target URL and host.
func (e *JSEngine) FindProxyForURL(targetURL string, host string) (string, error) {
	vm := e.acquireVM()
	if vm == nil {
		return "", fmt.Errorf("failed to obtain VM instance from pool")
	}

	fn, ok := goja.AssertFunction(vm.Get("FindProxyForURL"))
	if !ok {
		e.releaseVM(vm)
		return "", fmt.Errorf("FindProxyForURL not found in VM")
	}

	// Execute with timeout interrupt protection against infinite loops in PAC
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	done := make(chan struct{})
	var (
		res goja.Value
		err error
	)

	go func() {
		defer close(done)
		res, err = fn(goja.Undefined(), vm.ToValue(targetURL), vm.ToValue(host))
	}()

	select {
	case <-ctx.Done():
		vm.Interrupt("PAC execution timeout")
		<-done
		// Do NOT return interrupted VM to pool to avoid corrupting future executions
		return "", fmt.Errorf("PAC execution timed out after %v", e.timeout)
	case <-done:
		// Normal completion: return healthy VM back to pool
		e.releaseVM(vm)
		if err != nil {
			return "", fmt.Errorf("FindProxyForURL error: %w", err)
		}
		return res.String(), nil
	}
}

// Close releases any engine resources.
func (e *JSEngine) Close() {
	// sync.Pool instances are collected by runtime GC
}

// bindStandardPACFunctions injects standard Netscape PAC JavaScript functions into the VM.
func (e *JSEngine) bindStandardPACFunctions(vm *goja.Runtime) {
	// isPlainHostName(host) - True if host has no domain name (no dots)
	_ = vm.Set("isPlainHostName", func(host string) bool {
		return !strings.Contains(host, ".")
	})

	// dnsDomainIs(host, domain) - True if host ends with specified domain
	_ = vm.Set("dnsDomainIs", func(host, domain string) bool {
		if !strings.HasPrefix(domain, ".") && !strings.HasPrefix(host, domain) {
			domain = "." + domain
		}
		return strings.HasSuffix(strings.ToLower(host), strings.ToLower(domain)) || strings.EqualFold(host, strings.TrimPrefix(domain, "."))
	})

	// localHostOrDomainIs(host, hostdom) - True if exact match or unqualified hostname matches
	_ = vm.Set("localHostOrDomainIs", func(host, hostdom string) bool {
		if strings.EqualFold(host, hostdom) {
			return true
		}
		parts := strings.Split(host, ".")
		return strings.EqualFold(parts[0], hostdom)
	})

	lookupIP := func(host string) ([]net.IP, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		return net.DefaultResolver.LookupIP(ctx, "ip", host)
	}

	// isResolvable(host) - True if DNS can resolve the host
	_ = vm.Set("isResolvable", func(host string) bool {
		ips, err := lookupIP(host)
		return err == nil && len(ips) > 0
	})

	// isInNet(ip, pattern, mask) - True if IP matches subnet
	_ = vm.Set("isInNet", func(ipStr, patternStr, maskStr string) bool {
		parsedIP := net.ParseIP(ipStr)
		if parsedIP == nil {
			// Try resolving hostname if host was passed instead of IP
			ips, err := lookupIP(ipStr)
			if err != nil || len(ips) == 0 {
				return false
			}
			parsedIP = ips[0]
		}

		patternIP := net.ParseIP(patternStr)
		maskIP := net.ParseIP(maskStr)
		if parsedIP == nil || patternIP == nil || maskIP == nil {
			return false
		}

		// Convert IPv4 mask
		v4Mask := net.IPMask(maskIP.To4())
		if v4Mask == nil {
			v4Mask = net.IPMask(maskIP)
		}

		ipNet := net.IPNet{
			IP:   patternIP.Mask(v4Mask),
			Mask: v4Mask,
		}

		return ipNet.Contains(parsedIP)
	})

	// dnsResolve(host) - Returns IPv4 address string of host, or empty string if unresolvable
	_ = vm.Set("dnsResolve", func(host string) string {
		ips, err := lookupIP(host)
		if err != nil {
			return ""
		}
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				return v4.String()
			}
		}
		if len(ips) > 0 {
			return ips[0].String()
		}
		return ""
	})

	// myIpAddress() - Returns local machine IP address
	_ = vm.Set("myIpAddress", func() string {
		addrs, err := net.InterfaceAddrs()
		if err == nil {
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
					if v4 := ipNet.IP.To4(); v4 != nil {
						return v4.String()
					}
				}
			}
		}
		return "127.0.0.1"
	})

	// dnsDomainLevels(host) - Returns number of dots in hostname
	_ = vm.Set("dnsDomainLevels", func(host string) int {
		return strings.Count(host, ".")
	})

	// shExpMatch(str, pattern) - Shell wildcard matching (* and ?)
	_ = vm.Set("shExpMatch", func(str, pattern string) bool {
		return MatchShExp(str, pattern)
	})

	// alert(msg) - Debug print
	_ = vm.Set("alert", func(msg any) {
		// No-op for security/cleanliness in production
	})
}

// ParsePACResult converts the return string of FindProxyForURL into a primary ProxyDecision.
// Examples of PAC return strings:
//   "DIRECT"
//   "PROXY proxy.corp.local:8080"
//   "PROXY proxy1:8080; PROXY proxy2:8080; DIRECT"
//   "HTTPS secure-proxy.corp.local:8443; DIRECT"
//   "SOCKS5 socks.corp.local:1080"
func ParsePACResult(pacResult string) ProxyDecision {
	trimmed := strings.TrimSpace(pacResult)
	if trimmed == "" || strings.EqualFold(trimmed, "DIRECT") {
		return ProxyDecision{IsDirect: true}
	}

	// Split fallback options separated by semicolon
	options := strings.Split(trimmed, ";")
	for _, opt := range options {
		opt = strings.TrimSpace(opt)
		if opt == "" {
			continue
		}
		parts := strings.Fields(opt)
		if len(parts) == 0 {
			continue
		}

		schemeType := strings.ToUpper(parts[0])
		if schemeType == "DIRECT" {
			return ProxyDecision{IsDirect: true}
		}

		if len(parts) >= 2 && (schemeType == "PROXY" || schemeType == "HTTP" || schemeType == "HTTPS" || schemeType == "SOCKS" || schemeType == "SOCKS5") {
			hostPort := parts[1]
			// Ensure valid URL prefix
			var proxyURL string
			if strings.HasPrefix(hostPort, "http://") || strings.HasPrefix(hostPort, "https://") || strings.HasPrefix(hostPort, "socks5://") {
				proxyURL = hostPort
			} else if schemeType == "HTTPS" {
				proxyURL = "https://" + hostPort
			} else if schemeType == "SOCKS" || schemeType == "SOCKS5" {
				proxyURL = "socks5://" + hostPort
			} else {
				proxyURL = "http://" + hostPort
			}

			// Validate URL parsing
			if _, err := url.Parse(proxyURL); err == nil {
				return ProxyDecision{
					IsDirect: false,
					ProxyURL: proxyURL,
				}
			}
		}
	}

	return ProxyDecision{IsDirect: true}
}

// MatchShExp implements shell expression matching (* and ?) compatible with PAC shExpMatch.
// Unlike filepath.Match, it does not treat '/' as a separator, allowing full URL matching.
func MatchShExp(str, pattern string) bool {
	return wildcardMatch(str, pattern)
}

func wildcardMatch(s, p string) bool {
	sRunes := []rune(s)
	pRunes := []rune(p)
	sLen := len(sRunes)
	pLen := len(pRunes)

	sIdx := 0
	pIdx := 0
	matchIdx := 0
	starIdx := -1

	for sIdx < sLen {
		if pIdx < pLen && (pRunes[pIdx] == '?' || pRunes[pIdx] == sRunes[sIdx]) {
			sIdx++
			pIdx++
		} else if pIdx < pLen && pRunes[pIdx] == '*' {
			starIdx = pIdx
			matchIdx = sIdx
			pIdx++
		} else if starIdx != -1 {
			pIdx = starIdx + 1
			matchIdx++
			sIdx = matchIdx
		} else {
			return false
		}
	}

	for pIdx < pLen && pRunes[pIdx] == '*' {
		pIdx++
	}

	return pIdx == pLen
}
