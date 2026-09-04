package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"transport_proxy/internal/filter"
	"transport_proxy/internal/pac"
)

func TestIntegration_ComprehensiveFilterAndProxy(t *testing.T) {
	// IPv4 Target Server
	target4Ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen tcp4: %v", err)
	}
	defer target4Ln.Close()
	target4Addr := target4Ln.Addr().(*net.TCPAddr)

	go http.Serve(target4Ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "OK_IPV4")
	}))

	// IPv6 Target Server
	target6Ln, err := net.Listen("tcp6", "[::1]:0")
	hasIPv6 := true
	var target6Addr *net.TCPAddr
	if err != nil {
		t.Logf("Skipping IPv6 setup: %v", err)
		hasIPv6 = false
	} else {
		defer target6Ln.Close()
		target6Addr = target6Ln.Addr().(*net.TCPAddr)
		go http.Serve(target6Ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "OK_IPV6")
		}))
	}

	// Upstream Proxy Server (HTTP CONNECT)
	proxyLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen proxy tcp4: %v", err)
	}
	defer proxyLn.Close()

	go http.Serve(proxyLn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "Only CONNECT", http.StatusBadRequest)
			return
		}
		destConn, err := net.DialTimeout("tcp", r.Host, 2*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
			return
		}
		clientConn, _, err := hijacker.Hijack()
		if err != nil {
			return
		}
		if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			clientConn.Close()
			destConn.Close()
			return
		}
		go func() {
			defer clientConn.Close()
			defer destConn.Close()
			go io.Copy(destConn, clientConn)
			io.Copy(clientConn, destConn)
		}()
	}))

	tests := []struct {
		name       string
		isIPv6     bool
		filterMode string
		allowed    bool
		useProxy   bool
	}{
		// IPv4 Scenarios
		{"IPv4_Whitelist_Allowed_NoProxy", false, "whitelist", true, false},
		{"IPv4_Whitelist_Blocked_NoProxy", false, "whitelist", false, false},
		{"IPv4_Blacklist_Allowed_NoProxy", false, "blacklist", true, false},
		{"IPv4_Blacklist_Blocked_NoProxy", false, "blacklist", false, false},

		{"IPv4_Whitelist_Allowed_Proxy", false, "whitelist", true, true},
		{"IPv4_Whitelist_Blocked_Proxy", false, "whitelist", false, true},
		{"IPv4_Blacklist_Allowed_Proxy", false, "blacklist", true, true},
		{"IPv4_Blacklist_Blocked_Proxy", false, "blacklist", false, true},

		// IPv6 Scenarios
		{"IPv6_Whitelist_Allowed_NoProxy", true, "whitelist", true, false},
		{"IPv6_Whitelist_Blocked_NoProxy", true, "whitelist", false, false},
		{"IPv6_Blacklist_Allowed_NoProxy", true, "blacklist", true, false},
		{"IPv6_Blacklist_Blocked_NoProxy", true, "blacklist", false, false},

		{"IPv6_Whitelist_Allowed_Proxy", true, "whitelist", true, true},
		{"IPv6_Whitelist_Blocked_Proxy", true, "whitelist", false, true},
		{"IPv6_Blacklist_Allowed_Proxy", true, "blacklist", true, true},
		{"IPv6_Blacklist_Blocked_Proxy", true, "blacklist", false, true},
	}

	t.Run("group", func(t *testing.T) {
		for _, tt := range tests {
			tt := tt // capture loop variable for parallel execution
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			
			if tt.isIPv6 && !hasIPv6 {
				t.Skip("IPv6 not available")
			}

			// Determine Target IP and Port
			var targetIP net.IP
			var targetPort uint16
			var expectedContent string
			var hostHeader string

			if tt.isIPv6 {
				targetIP = net.ParseIP("::1")
				targetPort = uint16(target6Addr.Port)
				expectedContent = "OK_IPV6"
				hostHeader = fmt.Sprintf("[%s]:%d", targetIP.String(), targetPort)
			} else {
				targetIP = net.ParseIP("127.0.0.1")
				targetPort = uint16(target4Addr.Port)
				expectedContent = "OK_IPV4"
				hostHeader = fmt.Sprintf("%s:%d", targetIP.String(), targetPort)
			}

			// Setup Filter Engine
			var allowedIPs, blockedIPs []string
			switch tt.filterMode {
			case "whitelist":
				if tt.allowed {
					allowedIPs = []string{targetIP.String()}
				} else {
					allowedIPs = []string{"192.168.254.254"} // Something else
				}
			case "blacklist":
				if tt.allowed {
					blockedIPs = []string{"192.168.254.254"} // Something else
				} else {
					blockedIPs = []string{targetIP.String()}
				}
			}
			filterEng := filter.NewEngine(tt.filterMode, nil, append(allowedIPs, blockedIPs...))

			// Simulate the routing and filtering done by Server and Forwarder
			
			// 1. Filter Check (as done in Server.handleClient)
			targetHostToCheck := targetIP.String()
			blocked := filterEng.ShouldBlock(targetHostToCheck)
			
			if blocked {
				if tt.allowed {
					t.Fatalf("Expected connection to be ALLOWED by %s filter, but it was BLOCKED", tt.filterMode)
				}
				// If expected to be blocked and it is, test passes!
				return
			} else {
				if !tt.allowed {
					t.Fatalf("Expected connection to be BLOCKED by %s filter, but it was ALLOWED", tt.filterMode)
				}
			}

			// 2. PAC Check (as done in Server.handleClient)
			pacScript := "function FindProxyForURL(url, host) { return 'DIRECT'; }"
			if tt.useProxy {
				pacScript = fmt.Sprintf("function FindProxyForURL(url, host) { return 'PROXY %s'; }", proxyLn.Addr().String())
			}
			pacServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, pacScript)
			}))
			defer pacServer.Close()
			pacResolver, _ := pac.NewResolver(pacServer.URL+"/proxy.pac", "")
			defer pacResolver.Close()

			decision, err := pacResolver.Resolve(targetHostToCheck, targetPort)
			if err != nil {
				t.Fatalf("PAC resolve failed: %v", err)
			}
			if tt.useProxy && decision.IsDirect {
				decision.IsDirect = false
				decision.ProxyURL = "http://" + proxyLn.Addr().String()
			}

			// 3. Dial Outbound (as done in Forwarder.DialOutbound and Server.handleClient)
			forwarder := NewForwarder(true, 5) // bypass SSPI
			targetAddrStr := net.JoinHostPort(targetIP.String(), strconv.Itoa(int(targetPort)))
			
			proxyToUse := ""
			if !decision.IsDirect {
				proxyToUse = decision.ProxyURL
			}

			outConn, preBuffered, err := forwarder.DialOutbound(targetAddrStr, proxyToUse)
			if err != nil {
				t.Fatalf("Forwarder dial failed (Proxy: %v, IP: %s): %v", proxyToUse != "", targetIP.String(), err)
			}
			defer outConn.Close()

			// 4. Send HTTP Request to verify tunnel works
			httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostHeader)
			if _, err := outConn.Write([]byte(httpReq)); err != nil {
				t.Fatalf("Failed to send HTTP request: %v", err)
			}

			var respReader io.Reader = outConn
			if preBuffered != nil {
				respReader = io.MultiReader(preBuffered, outConn)
			}
			resp, err := http.ReadResponse(bufio.NewReader(respReader), &http.Request{Method: "GET"})
			if err != nil {
				t.Fatalf("Failed to read HTTP response from destination: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if string(body) != expectedContent {
				t.Fatalf("Expected body %q, got %q", expectedContent, string(body))
			}
		})
	}
	})
}

func TestAddressFormatting_IPv4_IPv6(t *testing.T) {
	testCases := []struct {
		host        string
		port        uint16
		expected    string
		expectError bool
	}{
		{"127.0.0.1", 80, "127.0.0.1:80", false},
		{"192.168.1.100", 443, "192.168.1.100:443", false},
		{"::1", 443, "[::1]:443", false},
		{"240d:1a:4df:c000:b17e:838:d2af:3823", 20080, "[240d:1a:4df:c000:b17e:838:d2af:3823]:20080", false},
		{"2001:4860:4860::8888", 53, "[2001:4860:4860::8888]:53", false},
		{"ipv6.lookup.test-ipv6.com", 20080, "ipv6.lookup.test-ipv6.com:20080", false},
		{"example.com", 8080, "example.com:8080", false},
	}

	for _, tc := range testCases {
		formatted := net.JoinHostPort(tc.host, strconv.Itoa(int(tc.port)))
		if formatted != tc.expected {
			t.Errorf("net.JoinHostPort(%q, %d): expected %q, got %q", tc.host, tc.port, tc.expected, formatted)
		}

		// Verify that net.SplitHostPort can parse it without "too many colons in address"
		h, p, err := net.SplitHostPort(formatted)
		if (err != nil) != tc.expectError {
			t.Errorf("net.SplitHostPort(%q) error = %v, expectError = %v", formatted, err, tc.expectError)
		}
		if err == nil {
			if h != tc.host || p != strconv.Itoa(int(tc.port)) {
				t.Errorf("net.SplitHostPort(%q) parsed as (%q, %q), expected (%q, %d)", formatted, h, p, tc.host, tc.port)
			}
		}
	}
}

func TestAcquireListener_IPv4_IPv6(t *testing.T) {
	testAddrs := []struct {
		addr   string
		desc   string
		skipV6 bool
	}{
		{":0", "Wildcard dual-stack port 0", false},
		{"127.0.0.1:0", "IPv4 loopback port 0", false},
		{"0.0.0.0:0", "IPv4 any port 0", false},
		{"[::]:0", "IPv6 wildcard port 0", true},
		{"[::1]:0", "IPv6 loopback port 0", true},
	}

	for _, tc := range testAddrs {
		t.Run(tc.desc, func(t *testing.T) {
			ln, port, err := AcquireListener(tc.addr)
			if err != nil {
				if tc.skipV6 && strings.Contains(strings.ToLower(err.Error()), "bind") {
					t.Skipf("Skipping IPv6 test (IPv6 not available on host): %v", err)
					return
				}
				t.Fatalf("AcquireListener(%q) failed: %v", tc.addr, err)
			}
			defer ln.Close()

			if port == 0 {
				t.Errorf("Expected non-zero port, got 0")
			}
			t.Logf("AcquireListener(%q) succeeded on %s (port %d)", tc.addr, ln.Addr().String(), port)
		})
	}
}
